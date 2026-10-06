const { test } = require('node:test');
const assert = require('node:assert/strict');
const { promote } = require('../scripts/ci/promote.cjs');

function fixture(ref = 'refs/heads/main') {
  const image = 'ghcr.io/example/blocklist';
  const digest = `sha256:${'a'.repeat(64)}`;
  const previous = `sha256:${'b'.repeat(64)}`;
  const sha = 'c'.repeat(40);
  const registry = new Map([[`${image}@${digest}`, digest], [`${image}:latest`, previous]]);
  const writes = [], records = [];
  return {
    env: { IMAGE: image, DIGEST: digest, GITHUB_SHA: sha, GITHUB_REF: ref },
    previous, registry, writes, records,
    io: {
      checkProduction: async () => {}, mainHead: async () => sha,
      inspect: (name, optional) => {
        if (!registry.has(name) && !optional) throw new Error('missing candidate');
        return registry.get(name) || null;
      },
      copy: (source, target) => { writes.push(target); registry.set(target, source.split('@')[1]); },
      save: record => records.push(structuredClone(record)),
    },
  };
}
test('rollback is verified before latest moves; all tags use the tested digest', async () => {
  const f = fixture();
  const record = await promote(f.env, f.io);
  assert.equal(f.writes[0], `${f.env.IMAGE}:rollback`);
  assert.equal(record.rollback, f.previous);
  assert.equal(record.status, 'published');
  assert.deepEqual(record.verified, ['main', 'latest', f.env.GITHUB_SHA]);
  assert.equal(f.registry.get(`${f.env.IMAGE}:rollback`), f.previous);
});
for (const reason of ['stale main', 'unreadable policy', 'missing candidate']) {
  test(`${reason} blocks every registry write`, async () => {
    const f = fixture();
    if (reason === 'stale main') f.io.mainHead = async () => 'd'.repeat(40);
    if (reason === 'unreadable policy') f.io.checkProduction = async () => { throw new Error('403'); };
    if (reason === 'missing candidate') f.registry.delete(`${f.env.IMAGE}@${f.env.DIGEST}`);
    await assert.rejects(promote(f.env, f.io));
    assert.deepEqual(f.writes, []);
    assert.equal(f.records.at(-1).status, 'failed');
  });
}
test('failed writes preserve the partial publication record', async () => {
  const f = fixture();
  const copy = f.io.copy;
  f.io.copy = (source, target) => {
    copy(source, target);
    if (target.endsWith(':latest')) throw new Error('connection lost after write');
  };
  await assert.rejects(promote(f.env, f.io));
  assert.deepEqual(f.records.at(-1).attempted, ['main', 'latest']);
  assert.deepEqual(f.records.at(-1).verified, ['main']);
  assert.equal(f.records.at(-1).rollback, f.previous);
});
test('retry after latest moved preserves the original rollback', async () => {
  const f = fixture();
  await promote(f.env, f.io);
  f.writes.length = 0;
  const record = await promote(f.env, f.io);
  assert.equal(record.rollback, f.previous);
  assert.ok(!f.writes.includes(`${f.env.IMAGE}:rollback`));
});
for (const branch of ['test', 'v2b_test']) {
  test(`${branch} cannot publish any image tags`, async () => {
    const f = fixture(`refs/heads/${branch}`);
    await assert.rejects(promote(f.env, f.io), /cannot publish images/);
    assert.deepEqual(f.writes, []);
  });
}
