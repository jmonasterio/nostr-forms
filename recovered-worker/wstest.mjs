// Authenticated read test: connect → NIP-42 AUTH (signed by the Rust tool)
// → REQ → observe. A fresh key should auth OK and get EOSE with zero events
// (nothing is #p-addressed to it), proving auth works + scoping holds.
import { execSync } from 'node:child_process';

const sk = process.argv[2];
const RELAY = 'wss://relay.argw.com';
const out = [];
let events = 0, done = false;
const ws = new WebSocket(RELAY);
const finish = () => {
  if (done) return; done = true;
  console.log(JSON.stringify({ flow: out, events }));
  try { ws.close(); } catch {}
  process.exit(0);
};
setTimeout(finish, 20000);
ws.onerror = () => { out.push('ERR'); finish(); };
ws.onmessage = (e) => {
  const m = JSON.parse(e.data);
  if (m[0] === 'AUTH') {
    out.push('AUTH-challenge');
    const signed = execSync(
      `cargo run -q --example admin_tool -- nip42 ${sk} ${RELAY} ${m[1]}`,
      { encoding: 'utf8' }
    ).trim();
    ws.send(JSON.stringify(['AUTH', JSON.parse(signed)]));
  } else if (m[0] === 'OK') {
    out.push('OK:' + (m[1] === undefined ? '' : m[1]) + ':' + (m[2] || ''));
    ws.send(JSON.stringify(['REQ', 't1', { kinds: [1, 4, 1059], limit: 10 }]));
  } else if (m[0] === 'EVENT') {
    events++;
  } else if (m[0] === 'EOSE') {
    out.push('EOSE'); finish();
  } else if (m[0] === 'CLOSED') {
    out.push('CLOSED:' + (m[2] || '')); finish();
  }
};
