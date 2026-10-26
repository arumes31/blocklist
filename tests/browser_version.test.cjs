const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('browser container matches the locked Playwright executable revision', () => {
  const root = path.resolve(__dirname, '..');
  const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
  const version = lock.packages['node_modules/playwright'].version;
  const compose = fs.readFileSync(path.join(root, 'tests/e2e/compose.yml'), 'utf8');
  const image = compose.match(/image:\s*mcr\.microsoft\.com\/playwright:v([^\s]+)-noble/);
  assert.ok(image, 'browser image must identify its Playwright version');
  assert.equal(image[1], version);
  assert.equal(lock.packages['node_modules/@playwright/test'].version, version);
  assert.equal(lock.packages['node_modules/playwright-core'].version, version);
});
