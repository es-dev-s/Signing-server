/**
 * Deletes signaling.db next to this script's parent folder.
 * Run:  node scripts/reset-db.js
 * Then start the server — a fresh DB is created and seeded with acme / root / Admin@123
 */
const fs = require('fs')
const path = require('path')

const dbPath = path.join(__dirname, '..', 'signaling.db')
try {
  fs.unlinkSync(dbPath)
  console.log('Removed', dbPath)
} catch (e) {
  if (e.code === 'EBUSY' || e.code === 'EPERM') {
    console.error('Database file is locked. Stop the signaling server, then run this script again.')
    process.exit(1)
  }
  if (e.code !== 'ENOENT') throw e
  console.log('No DB file at', dbPath)
}
