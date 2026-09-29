const express = require('express');
const { nanoid } = require('nanoid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const db = require('./db');
const { authenticateToken, JWT_SECRET } = require('./auth');
const stripe = require('./stripe');

const app = express();

app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_mock';
  
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error(`Webhook Error: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.expired') {
    const session = event.data.object;
    const code = session.metadata && session.metadata.code;
    
    if (code) {
      const isCompleted = event.type === 'checkout.session.completed';
      const newStatus = isCompleted ? 'paid' : 'expired';
      
      const selectResult = await db.query('SELECT status FROM links WHERE code = $1', [code]);
      if (selectResult.rows.length > 0) {
        const currentStatus = selectResult.rows[0].status;
        if (currentStatus !== 'paid' && currentStatus !== 'expired') {
          if (isCompleted) {
            await db.query('UPDATE links SET status = $1, paid_at = CURRENT_TIMESTAMP WHERE code = $2', [newStatus, code]);
          } else {
            await db.query('UPDATE links SET status = $1 WHERE code = $2', [newStatus, code]);
          }
        }
      }
    }
  }

  res.json({ received: true });
});

app.use(express.json());

// Serve static frontend files (e.g. index.html at root)
app.use(express.static('public'));

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
const redirectLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 500, standardHeaders: true, legacyHeaders: false });

app.use('/links', apiLimiter);
app.use('/signup', apiLimiter);
app.use('/login', apiLimiter);

app.post('/signup', [
  body('email').isEmail(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email, hashedPassword]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already exists' });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', [
  body('email').isEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (user && await bcrypt.compare(password, user.password_hash)) {
      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Guardrail checks
async function checkAbuseGuardrails(userId, amount) {
  // 1. Max links per merchant per hour
  const countResult = await db.query(`
    SELECT count(*) FROM links 
    WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 hour'
  `, [userId]);
  
  const hourlyCount = parseInt(countResult.rows[0].count, 10);
  if (hourlyCount >= 50) {
    throw new Error('TOO_MANY_REQUESTS');
  }

  // 2. Suspicious amount flags (e.g., > 100000 cents == $1000)
  if (amount > 100000) {
    const identicalHighValueResult = await db.query(`
      SELECT count(*) FROM links 
      WHERE user_id = $1 AND amount = $2 AND created_at > NOW() - INTERVAL '1 hour'
    `, [userId, amount]);
    
    if (parseInt(identicalHighValueResult.rows[0].count, 10) >= 3) {
      console.warn(`[Abuse Guardrail] Suspicious activity: User ${userId} created >= 3 links for amount ${amount} within an hour.`);
    }
  }
}

app.post('/links', authenticateToken, [
  body('amount').isInt({ gt: 0 }),
  body('currency').isLength({ min: 3, max: 3 }),
  body('description').isString().isLength({ max: 255 }),
  body('expires_at').optional().isISO8601().toDate()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { amount, currency, description, expires_at } = req.body;
  const userId = req.user.id;
  const code = nanoid(7);

  try {
    try {
      await checkAbuseGuardrails(userId, amount);
    } catch (err) {
      if (err.message === 'TOO_MANY_REQUESTS') {
        return res.status(429).json({ error: 'Max links per hour exceeded.' });
      }
      throw err;
    }

    const result = await db.query(
      'INSERT INTO links(code, user_id, amount, currency, description, expires_at) VALUES($1, $2, $3, $4, $5, $6) RETURNING code',
      [code, userId, amount, currency.toLowerCase(), description, expires_at || null]
    );
    const generatedCode = result.rows[0].code;
    const url = `${req.protocol}://${req.get('host')}/${generatedCode}`;
    res.status(201).json({ code: generatedCode, url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Analytics & Dashboard Endpoints
app.get('/links', authenticateToken, async (req, res) => {
  try {
    const result = await db.query('SELECT code, amount, currency, status, clicks, created_at FROM links WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
    res.json({ links: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/links/:code/stats', authenticateToken, async (req, res) => {
  const { code } = req.params;
  try {
    const result = await db.query('SELECT * FROM links WHERE code = $1 AND user_id = $2', [code, req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Link not found' });
    
    const link = result.rows[0];
    let timeToPaySeconds = null;
    if (link.paid_at && link.created_at) {
      timeToPaySeconds = (new Date(link.paid_at).getTime() - new Date(link.created_at).getTime()) / 1000;
    }
    
    res.json({
      code: link.code,
      status: link.status,
      clicks: link.clicks,
      time_to_pay_seconds: timeToPaySeconds
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Redirect endpoint
app.get('/:code', redirectLimiter, async (req, res) => {
  const { code } = req.params;
  
  // Exclude our own non-code routes from hitting the DB unnecessarily if they clash (e.g. /success)
  if (['success', 'cancel', 'links'].includes(code)) return res.sendStatus(404);
  
  try {
    // Increment clicks immediately
    await db.query('UPDATE links SET clicks = clicks + 1 WHERE code = $1', [code]);

    const selectResult = await db.query('SELECT * FROM links WHERE code = $1', [code]);
    if (selectResult.rows.length === 0) return res.status(404).send('Link not found');
    
    const link = selectResult.rows[0];
    if (link.expires_at && new Date(link.expires_at) < new Date()) return res.status(410).send('Link expired');
    if (link.status === 'used' || link.status === 'paid' || link.status === 'expired') {
      return res.status(400).send('Link already used or no longer active');
    }

    await db.query("UPDATE links SET status = 'used' WHERE id = $1", [link.id]);
    
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: { currency: link.currency, product_data: { name: link.description || 'Payment' }, unit_amount: link.amount },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${req.protocol}://${req.get('host')}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.protocol}://${req.get('host')}/cancel`,
      metadata: { code: link.code }
    });

    res.redirect(303, session.url);
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal server error');
  }
});

app.get('/success', (req, res) => res.send('Payment successful!'));
app.get('/cancel', (req, res) => res.send('Payment cancelled.'));

module.exports = app;
