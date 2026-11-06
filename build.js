// Assembles dist/browser-beacon.js from src/core.js plus the two vendored files, byte-for-byte.
'use strict';
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const uap = fs.readFileSync(path.join(__dirname, 'node_modules/ua-parser-js/dist/ua-parser.min.js'), 'utf8');
const ipa = fs.readFileSync(path.join(__dirname, 'node_modules/ipaddr1/ipaddr.min.js'), 'utf8');
let src = fs.readFileSync(path.join(__dirname, 'src/core.js'), 'utf8');

// Vendored text is inserted verbatim (neither file ends in a newline), so the bytes
// between the BEGIN line and the newline before END are exactly the npm file.
if (uap.endsWith('\n') || ipa.endsWith('\n')) { throw new Error('unexpected trailing newline'); }
const uapBody = uap;
const ipaBody = ipa;
src = src
  .replace('@@UAP_SHA@@', sha(uapBody)).replace('@@UAP_CODE@@', () => uapBody)
  .replace('@@IPA_SHA@@', sha(ipaBody)).replace('@@IPA_CODE@@', () => ipaBody);
if (/@@[A-Z_]+@@/.test(src)) { throw new Error('unreplaced placeholder'); }
fs.mkdirSync(path.join(__dirname, 'dist'), { recursive: true });
fs.writeFileSync(path.join(__dirname, 'dist/browser-beacon.js'), src);
console.log('built dist/browser-beacon.js', src.length, 'bytes; sha256', sha(src));
console.log('ua-parser block sha256', sha(uapBody), 'file sha256', sha(uap));
console.log('ipaddr block sha256   ', sha(ipaBody), 'file sha256', sha(ipa));
