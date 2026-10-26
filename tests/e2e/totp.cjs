const {createHmac} = require('node:crypto');
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32(bytes) {
  let bits = '';
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');
  return bits.match(/.{1,5}/g).map(chunk => alphabet[parseInt(chunk.padEnd(5, '0'), 2)]).join('');
}

function totp(secret, now = Date.now()) {
  const bits = [...secret.toUpperCase().replace(/=+$/, '')].map(char => {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error('Invalid test authenticator secret');
    return value.toString(2).padStart(5, '0');
  }).join('');
  const bytes = Buffer.from((bits.match(/.{8}/g) || []).map(byte => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 30000)));
  const digest = createHmac('sha1', bytes).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
}

// The server rejects a code whose 30-second step was already accepted for the
// account, so sign-ins and sudo refreshes must each use a new step. Steps are
// recorded in the run's auth directory so global setup and workers agree.
function stepFile() {
  return process.env.E2E_AUTH_DIR ? require('node:path').join(process.env.E2E_AUTH_DIR, 'totp-steps.json') : '';
}

function usedSteps() {
  try {
    return JSON.parse(require('node:fs').readFileSync(stepFile(), 'utf8'));
  } catch {
    return {};
  }
}

async function freshTotp(secret) {
  const used = usedSteps();
  const key = createHmac('sha256', 'e2e-step').update(secret).digest('hex');
  let step = Math.floor(Date.now() / 30000);
  while (used[key] !== undefined && step <= used[key]) {
    await new Promise(resolve => setTimeout(resolve, (step + 1) * 30000 - Date.now() + 100));
    step = Math.floor(Date.now() / 30000);
  }
  used[key] = step;
  if (stepFile()) require('node:fs').writeFileSync(stepFile(), JSON.stringify(used));
  return totp(secret, step * 30000);
}

module.exports = {base32, totp, freshTotp};
