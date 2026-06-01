const fs = require('fs');
const path = require('path');

const file = process.argv[2] || 'database.js';
const n = Number(process.argv[3] || 140);
const p = path.resolve(__dirname, '..', file);
const lines = fs.readFileSync(p, 'utf8').split(/\r?\n/);
console.log(lines.slice(0, n).map((l, i) => `${i + 1}: ${l}`).join('\n'));
