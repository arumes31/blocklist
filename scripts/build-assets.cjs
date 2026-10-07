const fs = require('node:fs/promises');
const path = require('node:path');
const {minify} = require('terser');

const root = path.resolve(__dirname, '..');
const sourceDir = path.join(root, 'cmd/server/static/js');
const outputDir = path.join(root, '.build/js');

async function minifyJavaScript(source, filename) {
  const result = await minify({[filename]: source}, {
    // These are independent classic scripts, including vendored libraries.
    // Preserve names, scopes and expressions used by inline handlers/other files.
    compress: false,
    mangle: false,
    module: false,
    // Some vendored files use plain "(c)" notices rather than /*! or @license.
    format: {comments: /^!|@preserve|@license|@cc_on|copyright|\(c\)|\blicen[cs]e\b/i},
  });
  const output = result.code + '\n';
  // Already-minified vendor assets should never grow after reformatting.
  return Buffer.byteLength(output) < Buffer.byteLength(source) ? output : source;
}

async function buildAssets() {
  // Only replace generated output at this fixed path, never tracked sources.
  await fs.rm(outputDir, {recursive: true, force: true});
  const stats = {files: 0, before: 0, after: 0};
  async function visit(relative = '') {
    const directory = path.join(sourceDir, relative);
    await fs.mkdir(path.join(outputDir, relative), {recursive: true});
    const entries = await fs.readdir(directory, {withFileTypes: true});
    entries.sort((a, b) => a.name.localeCompare(b.name, 'en'));
    for (const entry of entries) {
      const name = path.join(relative, entry.name);
      if (entry.isDirectory()) {
        await visit(name);
      } else if (entry.isFile()) {
        const input = await fs.readFile(path.join(sourceDir, name));
        const output = name.endsWith('.js')
          ? await minifyJavaScript(input.toString('utf8'), name)
          : input;
        await fs.writeFile(path.join(outputDir, name), output);
        if (name.endsWith('.js')) {
          stats.files++;
          stats.before += input.length;
          stats.after += Buffer.byteLength(output);
        }
      } else {
        throw new Error(`Unsupported asset entry: ${name}`);
      }
    }
  }
  await visit();
  if (!stats.files) throw new Error('No JavaScript assets found.');
  return stats;
}

if (require.main === module) {
  buildAssets().then(stats => {
    const saved = ((1 - stats.after / stats.before) * 100).toFixed(1);
    console.log(`JavaScript: ${stats.files} files, ${stats.before} -> ${stats.after} bytes (${saved}% smaller).`);
  }).catch(error => {
    console.error(`Asset build failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = {minifyJavaScript};
