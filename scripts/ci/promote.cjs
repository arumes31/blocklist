'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const { execFileSync } = require('node:child_process');
const { publicationTags, github, checkProduction } = require('./release-policy.cjs');

function inspect(image, allowMissing = false) {
  try {
    return execFileSync('docker', ['buildx', 'imagetools', 'inspect', image,
      '--format', '{{.Manifest.Digest}}'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  } catch (error) {
    // Authentication, network and other registry failures must never look like a first release.
    if (allowMissing && /manifest unknown|MANIFEST_UNKNOWN/.test(error.stderr?.toString())) return null;
    throw error;
  }
}

function copy(source, target) {
  execFileSync('docker', ['buildx', 'imagetools', 'create', '--prefer-index=false',
    '--tag', target, source], { stdio: 'inherit' });
}

async function promote(env, io) {
  const { IMAGE: image, DIGEST: digest, GITHUB_SHA: sha, GITHUB_REF: ref } = env;
  const record = { image, digest, commit: sha, ref, run: env.GITHUB_RUN_ID,
    attempt: env.GITHUB_RUN_ATTEMPT, previousLatest: null, rollback: null, attempted: [], verified: [], status: 'started' };
  io.save(record);
  try {
    assert.match(image, /^ghcr\.io\/[a-z0-9_.-]+\/[a-z0-9_.-]+$/);
    assert.match(digest, /^sha256:[a-f0-9]{64}$/);
    const tags = publicationTags(ref, sha);
    const source = `${image}@${digest}`;
    if (ref === 'refs/heads/main') await io.checkProduction();
    assert.equal(io.inspect(source), digest, 'Tested candidate is missing or changed');
    if (ref === 'refs/heads/main') {
      assert.equal(await io.mainHead(), sha, 'main advanced; approve the newer successful candidate');
      record.previousLatest = io.inspect(`${image}:latest`, true);
      io.save(record);
      if (record.previousLatest && record.previousLatest !== digest) {
        record.rollback = record.previousLatest;
        io.save(record); // Persist intent BEFORE the first registry write.
        io.copy(`${image}@${record.previousLatest}`, `${image}:rollback`);
        assert.equal(io.inspect(`${image}:rollback`), record.previousLatest);
      } else if (record.previousLatest === digest) {
        // Retrying an already successful latest write must not destroy its rollback.
        record.rollback = io.inspect(`${image}:rollback`, true);
      }
    }
    for (const tag of tags) {
      if (ref === 'refs/heads/main') {
        assert.equal(await io.mainHead(), sha, 'main advanced during promotion');
      }
      record.attempted.push(tag);
      io.save(record);
      io.copy(source, `${image}:${tag}`);
      assert.equal(io.inspect(`${image}:${tag}`), digest, `Digest mismatch for ${tag}`);
      record.verified.push(tag);
      io.save(record);
    }
    // Re-read every tag after all writes, not only immediately after each write.
    for (const tag of tags) assert.equal(io.inspect(`${image}:${tag}`), digest);
    record.status = 'published';
  } catch (error) {
    record.status = 'failed';
    record.error = error.message;
    throw error;
  } finally {
    io.save(record);
  }
  return record;
}

module.exports = { promote };
if (require.main === module) {
  promote(process.env, {
    inspect, copy, checkProduction,
    mainHead: async () => (await github(`/repos/${process.env.GITHUB_REPOSITORY}/git/ref/heads/main`)).object.sha,
    save: record => fs.writeFileSync('publication.json', JSON.stringify(record, null, 2) + '\n'),
  }).then(record => {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,
      `Published commit \`${record.commit}\`: \`${record.image}@${record.digest}\`\n\n` +
      `Verified tags: ${record.verified.join(', ')}\n\nRollback digest: \`${record.rollback || 'none (first publication)'}\`\n`);
  }).catch(error => { console.error(error.message); process.exitCode = 1; });
}
