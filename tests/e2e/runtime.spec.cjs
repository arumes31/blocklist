const {test, expect, unique} = require('./fixtures.cjs');
const fs = require('node:fs');
const path = require('node:path');
const {minifyJavaScript} = require('../../scripts/build-assets.cjs');

test('image serves minified JavaScript at the original asset URLs', async ({request}) => {
  for (const name of ['identity.js', 'sidebar-navigation.js', 'login-scene.js', 'threat-map-data.js', 'leaflet-heat.js']) {
    const source = fs.readFileSync(path.join(__dirname, '../../cmd/server/static/js', name), 'utf8');
    const response = await request.get('/js/' + name);
    expect(response.status()).toBe(200);
    expect(response.headers()['content-type']).toMatch(/javascript/);
    const output = await response.text();
    expect(output).toBe(await minifyJavaScript(source, name));
    if (name === 'leaflet-heat.js') {
      // Already minified: the builder may retain the source verbatim. Its LF
      // and CRLF variants are both covered by the asset-build unit tests.
      expect(Buffer.byteLength(output), `${name} must not grow`)
        .toBeLessThanOrEqual(Buffer.byteLength(source));
    } else {
      // Line-ending changes alone must not satisfy first-party minification.
      const sourceBytes = Buffer.byteLength(source.replace(/\r\n/g, '\n'));
      const outputBytes = Buffer.byteLength(output.replace(/\r\n/g, '\n'));
      expect(outputBytes, `${name} must be minified`).toBeLessThan(sourceBytes);
    }
  }
});

// Keep main's candidate API/asset checks in the shared isolated UI harness.
// Login, logout, accessibility and reviewed screenshots live in the dedicated
// auth, accessibility and visual suites instead of a second Playwright setup.
test('API health, embedded assets and authentication boundary', async ({playwright, api, baseURL}) => {
  const request = await playwright.request.newContext({
    baseURL, storageState: {cookies: [], origins: []},
  });
  try {
    expect((await request.get('/health')).status()).toBe(200);
    expect((await request.get('/api/v1/raw')).status()).toBe(200);
    expect((await request.get('/api/v1/ips')).status()).toBe(401);
    expect((await request.get('/api/v1/ips', {
      headers: {Authorization: 'Bearer invalid'},
    })).status()).toBe(401);

    const created = await api.post('/api/v1/settings/tokens', {
      form: {name: unique('runtime-token'), permissions: 'view_ips'},
    });
    expect(created.status()).toBe(200);
    const token = JSON.parse(created.headers()['hx-trigger']).newToken;
    expect(token).toMatch(/^bl_[a-f0-9]{64}$/);
    const headers = {Authorization: 'Bearer ' + token};
    expect((await request.get('/api/v1/ips', {headers})).status()).toBe(200);
    expect((await request.get('/api/v1/stats', {headers})).status()).toBe(403);

    const logo = await request.get('/cd/logo.png');
    expect(logo.status()).toBe(200);
    expect(logo.headers()['content-type']).toContain('image/png');
    const schema = await request.get('/openapi.json');
    expect(schema.status()).toBe(200);
    expect((await schema.json()).paths).toHaveProperty('/api/v1/ips');
  } finally {
    await request.dispose();
  }
});
