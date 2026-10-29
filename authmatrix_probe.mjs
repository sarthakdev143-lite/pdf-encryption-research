// pdf.js authentication probe (Node).
// stdin: JSON array of {idx, file, password}
// stdout: one JSON object per line {idx,status,text_len,text,error}
// PasswordException => BLOCKED; successful open => extract page text.
import fs from 'node:fs';
import * as pdfjs from 'pdfjs-dist/legacy/build/pdf.mjs';

const items = JSON.parse(fs.readFileSync(0, 'utf8'));

for (const item of items) {
  const out = { idx: item.idx, status: 'OK', text_len: 0, text: '' };
  try {
    const data = new Uint8Array(fs.readFileSync(item.file));
    const task = pdfjs.getDocument({
      data,
      password: item.password,
      useSystemFonts: true,
      disableFontFace: true,
      isEvalSupported: false,
    });
    const doc = await task.promise;
    const parts = [];
    for (let i = 1; i <= doc.numPages; i++) {
      const page = await doc.getPage(i);
      const content = await page.getTextContent();
      parts.push(content.items.map((it) => ('str' in it ? it.str : '')).join(' '));
    }
    const text = parts.join('\n');
    out.text = text.slice(0, 4000);
    out.text_len = text.trim().length;
    try {
      await task.destroy();
    } catch {
      /* teardown best-effort */
    }
  } catch (e) {
    const name = e?.name ?? 'Error';
    const msg = `${name}: ${e?.message ?? String(e)}`;
    out.status = name === 'PasswordException' || /password/i.test(msg) ? 'BLOCKED' : 'ERROR';
    out.error = msg.slice(0, 300);
  }
  process.stdout.write(JSON.stringify(out) + '\n');
}
