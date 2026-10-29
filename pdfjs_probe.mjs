// pdf.js extractor probe (Node).
// Reads a JSON array of absolute PDF paths from stdin.
// Writes one JSON object per line to stdout: {file,status,text_len,text,error}
//
// Runs WITHOUT a password, exactly like a browser viewing an encrypted PDF
// with no password supplied. PasswordException => BLOCKED; anything else is a
// clean ERROR; successful text/metadata/attachment extraction => OK.
import fs from 'node:fs';
import * as pdfjs from 'pdfjs-dist/legacy/build/pdf.mjs';

const paths = JSON.parse(fs.readFileSync(0, 'utf8'));

for (const file of paths) {
  const out = { file, status: 'OK', text_len: 0, text: '' };
  try {
    const data = new Uint8Array(fs.readFileSync(file));
    const task = pdfjs.getDocument({
      data,
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

    // metadata (Info dict + XMP) is part of the document surface
    try {
      const meta = await doc.getMetadata();
      parts.push(JSON.stringify(meta.info ?? {}));
      if (meta.metadata) parts.push(String(meta.metadata.getRaw?.() ?? ''));
    } catch {
      /* metadata unavailable is not fatal for the probe */
    }

    // embedded files, if any
    try {
      const atts = await doc.getAttachments();
      for (const [name, att] of Object.entries(atts ?? {})) {
        if (!att?.content) continue;
        parts.push(name);
        parts.push(Buffer.from(att.content).toString('latin1'));
      }
    } catch {
      /* attachments unavailable is not fatal */
    }

    const text = parts.join('\n');
    out.text = text.slice(0, 6000);
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
    out.error = msg.slice(0, 500);
    out.text_len = 0;
    out.text = '';
  }
  process.stdout.write(JSON.stringify(out) + '\n');
}
