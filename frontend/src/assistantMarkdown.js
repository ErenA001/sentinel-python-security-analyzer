/**
 * Small, deliberately limited Markdown parser for assistant chat messages.
 * It returns data blocks only; React renders every value as text, never HTML.
 * Supported: paragraphs, # headings, ordered/unordered lists, fenced code,
 * bold text, and inline code (the inline formatting is rendered in App.jsx).
 */
export function parseAssistantMarkdown(input) {
  const lines = String(input ?? '').replace(/\r\n?/g, '\n').split('\n');
  const blocks = [];
  let paragraph = [];
  let list = null;
  let code = null;

  const flushParagraph = () => {
    if (paragraph.length) {
      const text = paragraph.join(' ').trim();
      if (text) blocks.push({ type: 'paragraph', text });
      paragraph = [];
    }
  };

  const flushList = () => {
    if (list?.items.length) blocks.push(list);
    list = null;
  };

  const flushCode = () => {
    if (code) {
      blocks.push({ type: 'code', language: code.language, text: code.lines.join('\n') });
      code = null;
    }
  };

  for (const line of lines) {
    if (code) {
      if (/^\s*```\s*$/.test(line)) flushCode();
      else code.lines.push(line);
      continue;
    }

    const fence = line.match(/^\s*```\s*([a-zA-Z0-9_+-]{0,24})\s*$/);
    if (fence) {
      flushParagraph();
      flushList();
      code = { language: fence[1] || '', lines: [] };
      continue;
    }

    if (!line.trim()) {
      flushParagraph();
      flushList();
      continue;
    }

    const heading = line.match(/^\s{0,3}(#{1,3})\s+(.+?)\s*#*\s*$/);
    if (heading) {
      flushParagraph();
      flushList();
      blocks.push({ type: 'heading', level: heading[1].length, text: heading[2] });
      continue;
    }

    if (/^\s{0,3}(?:[-*_]\s*){3,}$/.test(line)) {
      flushParagraph();
      flushList();
      blocks.push({ type: 'divider' });
      continue;
    }

    const item = line.match(/^\s{0,3}((?:\d{1,3}[.)])|[-*+])\s+(.+)$/);
    if (item) {
      flushParagraph();
      const ordered = /^\d/.test(item[1]);
      const type = ordered ? 'ordered-list' : 'unordered-list';
      if (list && list.type !== type) flushList();
      if (!list) list = { type, items: [] };
      list.items.push(item[2]);
      continue;
    }

    flushList();
    paragraph.push(line.trim());
  }

  flushParagraph();
  flushList();
  flushCode();
  return blocks;
}
