require('dotenv').config();

const requiredEnvs = ['DATABASE_URL', 'JWT_SECRET', 'STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET'];
for (const env of requiredEnvs) {
  if (!process.env[env]) {
    console.error(`FATAL ERROR: Missing required environment variable: ${env}`);
    process.exit(1);
  }
}

const app = require('./app');
const { startStaleLinkSweeper } = require('./jobs');

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Phase 4 Server listening on port ${PORT} at 0.0.0.0`);
  startStaleLinkSweeper();
});
