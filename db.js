const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

pool.on('error', (err) => {
  console.error('Unexpected database connection error:', err);
});

// Test connection on startup
pool.connect((err, client, release) => {
  if (err) {
    console.error('Failed to connect to the database on startup:', err.stack);
  } else {
    console.log('Successfully connected to the database.');
    release();
  }
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool
};
