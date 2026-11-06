'use strict';
// The built file must parse as ES5 (it has to run on the old browsers it reports), and our
// own code must pass ESLint. The vendored blocks are blanked (line count kept) before linting.
const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const { ESLint } = require('eslint');

const file = path.join(__dirname, '..', 'dist', 'browser-beacon.js');
const src = fs.readFileSync(file, 'utf8');
acorn.parse(src, { ecmaVersion: 5 });
console.log('ES5 parse: ok');

const own = src.replace(/(\/\* @@BEGIN[^\n]*\*\/\n)([\s\S]*?)(\n\/\* @@END)/g,
  (m, begin, body, end) => begin + '\n'.repeat(body.split('\n').length - 1) + end);

(async () => {
  const eslint = new ESLint({ useEslintrc: false, overrideConfigFile: path.join(__dirname, '..', '.eslintrc.json') });
  const results = await eslint.lintText(own, { filePath: file });
  const out = (await eslint.loadFormatter('stylish')).format(results);
  if (out) { console.log(out); }
  if (results.some((r) => r.errorCount)) { process.exit(1); }
  console.log('ESLint: clean');
})().catch((e) => { console.error(e); process.exit(1); });
