const { test } = require('node:test');
const assert = require('node:assert/strict');
const { canDelete } = require('../scripts/ci/cleanup-packages.cjs');
const now = Date.parse('2026-10-06T00:00:00Z');
const version = tags => ({ updated_at: '2026-01-01T00:00:00Z', metadata: { container: { tags } } });
test('cleanup preserves protected aliases, candidates, releases and their untagged manifests', () => {
  for (const tag of ['main', 'latest', 'test', 'v2b_test', 'rollback', 'candidate-abc-123-1', 'v1.0']) {
    assert.equal(canDelete(version(['old-tag', tag]), now), false);
  }
  assert.equal(canDelete(version([]), now), false);
  assert.equal(canDelete({}, now), false);
});
test('only unprotected versions older than 30 days are eligible', () => {
  assert.equal(canDelete(version(['old-branch']), now), true);
  const recent = version(['old-branch']);
  recent.updated_at = '2026-10-01T00:00:00Z';
  assert.equal(canDelete(recent, now), false);
  recent.updated_at = 'invalid';
  assert.equal(canDelete(recent, now), false);
});
