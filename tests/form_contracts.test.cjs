const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const template = name => fs.readFileSync(path.join(__dirname, '../cmd/server/templates', name), 'utf8');

test('role key HTML pattern works with modern browser Unicode-set validation', () => {
  const pattern = template('roles.html').match(/id="roleKey"[^>]*pattern="([^"]+)"/)[1];
  const valid = new RegExp(`^(?:${pattern})$`, 'v');
  for (const key of ['viewer', 'incident-reviewer', 'test_2']) assert.equal(valid.test(key), true);
  for (const key of ['INVALID KEY', '1role', 'has space', 'x'.repeat(65)]) assert.equal(valid.test(key), false);
});

test('token request listener sends current checkboxes, replacing previously serialized scopes', () => {
  const source = template('settings.html');
  const start = source.indexOf('function prepareTokenPerms()');
  const end = source.indexOf('function setTokenTemplate(', start);
  const hidden = {value: ''};
  let chosen = [], listener;
  const form = {addEventListener: (name, fn) => {
    assert.equal(name, 'htmx:configRequest');
    listener = fn;
  }};
  vm.runInNewContext(source.slice(start, end), {document: {
    querySelectorAll: selector => {
      assert.equal(selector, '.token-perm:checked');
      return chosen.map(value => ({value}));
    },
    getElementById: id => id === 'tokenForm' ? form : hidden,
  }});
  for (const permissions of [['block_ips'], ['view_ips', 'export_data'], []]) {
    chosen = permissions;
    const event = {detail: {parameters: {permissions: 'stale', name: 'test-token'}}};
    listener(event);
    assert.equal(event.detail.parameters.permissions, permissions.join(','));
    assert.equal(event.detail.parameters.name, 'test-token');
    assert.equal(hidden.value, permissions.join(','));
  }
});
