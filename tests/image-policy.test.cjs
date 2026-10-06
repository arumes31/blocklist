const {test} = require('node:test');
const assert = require('node:assert/strict');
const {validateProductionPolicy} = require('../.github/scripts/image-policy.cjs');

function fixture() {
  return {
    environment: {can_admins_bypass: false, deployment_branch_policy: {custom_branch_policies: true},
      protection_rules: [{type: 'required_reviewers', reviewers: [{type: 'User'}]}]},
    policies: {total_count: 1, branch_policies: [{name: 'main', type: 'branch'}]},
    currentSHA: 'a'.repeat(40), candidateSHA: 'a'.repeat(40),
  };
}
test('protected current main candidate is accepted', () => {
  assert.doesNotThrow(() => validateProductionPolicy(...Object.values(fixture())));
});
for (const [name, mutate] of [
  ['no required reviewers', f => { f.environment.protection_rules = []; }],
  ['empty reviewer list', f => { f.environment.protection_rules[0].reviewers = []; }],
  ['administrator bypass', f => { f.environment.can_admins_bypass = true; }],
  ['unrestricted branches', f => { f.environment.deployment_branch_policy = null; }],
  ['main tag instead of branch', f => { f.policies.branch_policies[0].type = 'tag'; }],
  ['wildcard branch rule', f => { f.policies.branch_policies[0].name = '*'; }],
  ['extra deployment rules', f => { f.policies.total_count = 2; }],
  ['stale candidate', f => { f.currentSHA = 'b'.repeat(40); }],
  ['invalid commit', f => { f.currentSHA = f.candidateSHA = 'main'; }],
]) {
  test(`publication fails closed: ${name}`, () => {
    const f = fixture();
    mutate(f);
    assert.throws(() => validateProductionPolicy(...Object.values(f)));
  });
}
