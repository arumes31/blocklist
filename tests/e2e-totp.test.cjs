const {test} = require('node:test');
const assert = require('node:assert/strict');
const {base32, totp} = require('./e2e/totp.cjs');

test('browser-test authenticator agrees with RFC 4226 SHA-1 counter vectors', () => {
  // Public RFC test bytes, not a credential used by any environment.
  const key = Buffer.from(Array.from({length: 20}, (_, index) => 48 + (index + 1) % 10));
  const expected = ['755224', '287082', '359152', '969429', '338314'];
  expected.forEach((code, counter) => assert.equal(totp(base32(key), counter * 30000), code));
});

test('base32 encodes non-aligned buffers without losing trailing bits', () => {
  assert.equal(base32(Buffer.from('foobar')), 'MZXW6YTBOI');
  assert.throws(() => totp('INVALID!'), /Invalid test authenticator/);
});
