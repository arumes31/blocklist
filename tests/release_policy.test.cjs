const { test } = require('node:test');
const assert = require('node:assert/strict');
const { validateProduction, publicationTags } = require('../scripts/ci/release-policy.cjs');

const environment = {
  can_admins_bypass: false,
  protection_rules: [{ type: 'required_reviewers', reviewers: [{ type: 'User', reviewer: { id: 1 } }] }],
  deployment_branch_policy: { protected_branches: false, custom_branch_policies: true },
};
const branches = [{ name: 'main', type: 'branch' }];

test('production policy accepts configured human approval', () => {
  assert.doesNotThrow(() => validateProduction(environment, branches));
});
for (const [name, mutate] of Object.entries({
  'missing reviewers': value => { value.protection_rules = []; },
  'empty reviewers': value => { value.protection_rules[0].reviewers = []; },
  'administrator bypass': value => { value.can_admins_bypass = true; },
  'unreadable bypass policy': value => { delete value.can_admins_bypass; },
  'unrestricted branches': value => { value.deployment_branch_policy = null; },
})) {
  test(`production rejects ${name}`, () => {
    const value = structuredClone(environment);
    mutate(value);
    assert.throws(() => validateProduction(value, branches));
  });
}
for (const rules of [[], [{ name: '*', type: 'branch' }], [{ name: 'main', type: 'tag' }],
  [...branches, { name: 'test', type: 'branch' }]]) {
  test(`production rejects branch rules ${JSON.stringify(rules)}`, () => {
    assert.throws(() => validateProduction(environment, rules));
  });
}
test('only main can move latest; branch and tag names cannot masquerade as main', () => {
  const sha = 'a'.repeat(40);
  assert.deepEqual(publicationTags('refs/heads/main', sha), ['main', 'latest', sha]);
  for (const branch of ['test', 'v2b_test']) {
    assert.throws(() => publicationTags(`refs/heads/${branch}`, sha));
  }
  for (const ref of ['refs/tags/main', 'refs/heads/feature', 'refs/heads/test/other']) {
    assert.throws(() => publicationTags(ref, sha));
  }
});
