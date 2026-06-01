import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 20,
  duration: '3m',
  thresholds: {
    http_req_duration: ['p(95)<200'],
    http_req_failed: ['rate<0.01'],
  },
};

const BASE = __ENV.BASE_URL || 'https://YOUR_SIGNALING_HOST';
const TOKEN = __ENV.INGEST_TOKEN || '';

export default function () {
  if (!TOKEN) {
    throw new Error('Set INGEST_TOKEN env to a valid ingest token (Bearer)');
  }
  const events = [
    {
      type: 'call_start',
      platform: 'zoom',
      timestamp: new Date().toISOString(),
    },
    {
      type: 'call_end',
      platform: 'zoom',
      timestamp: new Date(Date.now() + 5000).toISOString(),
      duration_ms: 5000,
    },
  ];
  const res = http.post(`${BASE}/api/call-events`, JSON.stringify({ events }), {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${TOKEN}`,
    },
  });
  check(res, {
    'status 200': (r) => r.status === 200,
    'accepted>0': (r) => r.json('accepted') > 0,
  });
  sleep(1);
}
