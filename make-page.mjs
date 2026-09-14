#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
const strip = (p) => readFileSync(new URL(p, import.meta.url), 'utf8')
  .replace(/^export /gm, '').replace(/\r\n/g, '\n').trimEnd();

const kernel = strip('./kernel.mjs');
// the QR module rides in its own closure — only qrMatrix escapes, so it can never
// collide with a kernel identifier
const qr = 'const qrMatrix = (() => {\n' + strip('./qr.mjs') + '\nreturn qrMatrix;\n})();';

let page = readFileSync(new URL('./index.html', import.meta.url), 'utf8').replace(/\r\n/g, '\n');

// inline the hero icon as a data: URI so a saved meshos.html opened from file:// is not headed
// by a broken image (idempotent: the pattern matches whatever src it currently carries)
const iconB64 = readFileSync(new URL('./icon.svg', import.meta.url)).toString('base64');
page = page.replace(/(<img class="hero-icon" src=")[^"]*(")/, '$1data:image/svg+xml;base64,' + iconB64 + '$2');
function inject(src, tag, body) {
  const BEGIN = '// ⟦' + tag + '-BEGIN⟧ generated from ' + body.file + ' by make-page.mjs — do not edit here';
  const END = '// ⟦' + tag + '-END⟧';
  const a = src.indexOf(BEGIN), b = src.indexOf(END);
  if (a === -1 || b === -1 || b < a) { console.error(tag + ' markers missing'); process.exit(1); }
  return src.slice(0, a + BEGIN.length) + '\n' + body.code + '\n' + src.slice(b);
}
page = inject(page, 'QR', { file: 'qr.mjs', code: qr });
page = inject(page, 'KERNEL', { file: 'kernel.mjs', code: kernel });
writeFileSync(new URL('./index.html', import.meta.url), page);
console.log('injected: kernel ' + kernel.length + ' chars, qr ' + qr.length + ' chars');
