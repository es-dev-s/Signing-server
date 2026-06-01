#!/usr/bin/env node
/**
 * Mint a short-lived ingest token for /api/call-events.
 * Usage:
 *   node scripts/mint-ingest-token.js --clientId=123 --orgId=5 [--ttlMs=900000]
 *
 * Requires INGEST_TOKEN_SECRET in env (same as server).
 */
const crypto = require('crypto')

function parseArgs() {
  const out = {}
  for (const arg of process.argv.slice(2)) {
    const [k, v] = arg.replace(/^--/, '').split('=')
    out[k] = v
  }
  return out
}

function sign(body, secret) {
  const data = Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url')
  return `${data}.${sig}`
}

function main() {
  const secret = process.env.INGEST_TOKEN_SECRET
  if (!secret) {
    console.error('INGEST_TOKEN_SECRET env is required')
    process.exit(1)
  }

  const args = parseArgs()
  const clientId = Number(args.clientId)
  const orgId = Number(args.orgId)
  const ttlMs = Number(args.ttlMs || 15 * 60 * 1000)

  if (!Number.isFinite(clientId) || clientId <= 0) {
    console.error('clientId is required and must be a positive number')
    process.exit(1)
  }
  if (!Number.isFinite(orgId) || orgId <= 0) {
    console.error('orgId is required and must be a positive number')
    process.exit(1)
  }
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    console.error('ttlMs must be a positive number')
    process.exit(1)
  }

  const exp = Date.now() + ttlMs
  const token = sign({ clientId, orgId, exp }, secret)
  console.log(token)
  console.log(`Expires at: ${new Date(exp).toISOString()}`)
}

main()
