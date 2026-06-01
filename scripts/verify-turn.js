const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');

function setEnvIfMissing(key, value) {
  if (!value) return;
  if (process.env[key]) return;
  process.env[key] = value;
}

function hasRequiredTurnEnv() {
  const keys = [
    'TURN_STUN_URL',
    'TURN_UDP_URL',
    'TURN_TCP_URL',
    'TURN_TLS_URL',
    'TURN_TLSTCP_URL',
    'TURN_USERNAME',
    'TURN_CREDENTIAL',
  ];
  return keys.every((k) => !!process.env[k]);
}

function tryLoadLegacyTurnSnippet(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw || !raw.includes('iceServers')) return false;

    const urls = [...raw.matchAll(/urls\s*:\s*["']([^"']+)["']/g)].map((m) => m[1]).filter(Boolean);
    const usernameMatch = raw.match(/username\s*:\s*["']([^"']+)["']/);
    const credentialMatch = raw.match(/credential\s*:\s*["']([^"']+)["']/);
    const username = usernameMatch?.[1];
    const credential = credentialMatch?.[1];

    setEnvIfMissing('TURN_STUN_URL', urls.find((u) => u.startsWith('stun:')));
    setEnvIfMissing('TURN_UDP_URL', urls.find((u) => u.startsWith('turn:') && !u.startsWith('turns:') && !u.includes('transport=tcp')));
    setEnvIfMissing('TURN_TCP_URL', urls.find((u) => u.startsWith('turn:') && u.includes('transport=tcp')));
    setEnvIfMissing('TURN_TLS_URL', urls.find((u) => u.startsWith('turn:') && u.includes(':443') && !u.includes('transport=tcp')));
    setEnvIfMissing('TURN_TLSTCP_URL', urls.find((u) => u.startsWith('turns:')));
    setEnvIfMissing('TURN_USERNAME', username);
    setEnvIfMissing('TURN_CREDENTIAL', credential);
    return urls.length > 0 || !!username || !!credential;
  } catch {
    return false;
  }
}

function loadTurnEnv() {
  const candidates = [
    path.join(__dirname, '../.env.turn'),
    path.join(__dirname, '../.env.trun'),
  ];
  for (const filePath of candidates) {
    if (!fs.existsSync(filePath)) continue;
    dotenv.config({ path: filePath });
    if (hasRequiredTurnEnv()) return;
    if (tryLoadLegacyTurnSnippet(filePath)) return;
  }
}

loadTurnEnv();

console.log('=== TURN Config Verification ===');
const keys = [
  'TURN_STUN_URL', 'TURN_UDP_URL', 'TURN_TCP_URL',
  'TURN_TLS_URL', 'TURN_TLSTCP_URL', 'TURN_USERNAME', 'TURN_CREDENTIAL',
];
let allPresent = true;
for (const key of keys) {
  const val = process.env[key];
  if (!val) {
    console.error(`MISSING: ${key}`);
    allPresent = false;
  } else if (key === 'TURN_USERNAME' || key === 'TURN_CREDENTIAL') {
    console.log(`${key}: [SET, length=${val.length}]`);
  } else {
    console.log(`${key}: ${val}`);
  }
}
console.log(allPresent ? '\nAll TURN config present!' : '\nFix missing keys above');
