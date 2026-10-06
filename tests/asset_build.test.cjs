const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const {minifyJavaScript} = require('../scripts/build-assets.cjs');

test('minification preserves cross-script globals, callback names and properties', async () => {
  const source = `
    /*! Fixture license */
    // An ordinary comment that should disappear.
    var selection = { count: 3 };
    function onSelect(increment) {
      selection.count += increment;
      return selection.count;
    }
    class Account { label() { return 'Viewer'; } }
    globalThis.identity = { onSelect, Account };
  `;
  const output = await minifyJavaScript(source, 'fixture.js');
  assert.ok(output.length < source.length);
  assert.match(output, /Fixture license/);
  assert.doesNotMatch(output, /ordinary comment/);
  const context = vm.createContext({});
  vm.runInContext(output, context);
  assert.equal(vm.runInContext('onSelect(2)', context), 5);
  assert.equal(context.selection.count, 5);
  assert.equal(context.identity.onSelect.name, 'onSelect');
  assert.equal(context.identity.Account.name, 'Account');
  assert.equal(vm.runInContext('new Account().label()', context), 'Viewer');
});

test('minification is deterministic, never enlarges assets, and rejects invalid syntax', async () => {
  const source = 'window.example=1;';
  assert.equal(await minifyJavaScript(source, 'vendor.min.js'), source);
  const readable = '// comment\nfunction value() { return 42; }\n';
  assert.equal(await minifyJavaScript(readable, 'app.js'), await minifyJavaScript(readable, 'app.js'));
  await assert.rejects(minifyJavaScript('function broken( {', 'broken.js'));
});

test('minification preserves plain third-party copyright and license notices', async () => {
  const source = `/* (c) 2014, Example Author */
    /* Copyright 2026 Example Authors */
    /* Released under the MIT License */
    // Ordinary implementation note.
    function example() { return 1; }
  `;
  const output = await minifyJavaScript(source, 'vendor.js');
  for (const notice of ['(c) 2014, Example Author', 'Copyright 2026 Example Authors', 'Released under the MIT License']) {
    assert.ok(output.includes(notice));
  }
  assert.doesNotMatch(output, /Ordinary implementation note/);
});

test('minified map data module keeps its CommonJS exports and behavior', async () => {
  const filename = path.join(__dirname, '../cmd/server/static/js/threat-map-data.js');
  const source = fs.readFileSync(filename, 'utf8');
  const expected = require(filename);
  const context = vm.createContext({module: {exports: {}}});
  vm.runInContext(await minifyJavaScript(source, 'threat-map-data.js'), context);
  const actual = context.module.exports;
  assert.deepEqual(Object.keys(actual).sort(), Object.keys(expected).sort());
  for (const value of [{active_blocks: 42, total: 9000}, {blocks_minute: 2.5}, {}]) {
    assert.equal(JSON.stringify(actual.stats(value)), JSON.stringify(expected.stats(value)));
  }
});

test('Docker embeds generated assets after copying sources and keeps build tools out of runtime', () => {
  const dockerfile = fs.readFileSync(path.join(__dirname, '../Dockerfile'), 'utf8');
  const copySource = dockerfile.indexOf('COPY . .');
  const copyAssets = dockerfile.indexOf('COPY --from=assets /app/.build/js/ ./cmd/server/static/js/');
  const compile = dockerfile.indexOf('RUN CGO_ENABLED=0');
  assert.ok(copySource > -1 && copySource < copyAssets && copyAssets < compile);
  assert.match(dockerfile, /RUN npm ci --ignore-scripts/);
  assert.match(dockerfile, /RUN npm run build:assets/);
  const runtime = dockerfile.slice(dockerfile.lastIndexOf('\nFROM '));
  assert.doesNotMatch(runtime, /COPY --from=assets|npm|node_modules/);
});
