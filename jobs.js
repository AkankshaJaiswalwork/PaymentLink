const db = require('./db');

function startStaleLinkSweeper() {
  const INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

  setInterval(async () => {
    try {
      const result = await db.query(`
        UPDATE links 
        SET status = 'expired' 
        WHERE expires_at < NOW() AND status = 'pending'
      `);
      if (result.rowCount > 0) {
        console.log(`[Sweeper] Expired ${result.rowCount} stale links.`);
      }
    } catch (err) {
      console.error('[Sweeper] Error expiring stale links:', err);
    }
  }, INTERVAL_MS);
  
  console.log('[Sweeper] Stale link sweeper started.');
}

module.exports = { startStaleLinkSweeper };
