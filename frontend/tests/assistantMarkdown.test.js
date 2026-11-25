import test from 'node:test';
import assert from 'node:assert/strict';
import { parseAssistantMarkdown } from '../src/assistantMarkdown.js';

test('parses paragraphs and blank-line separation', () => {
  const blocks = parseAssistantMarkdown('First paragraph.\ncontinued line.\n\nSecond paragraph.');
  assert.deepEqual(blocks, [
    { type: 'paragraph', text: 'First paragraph. continued line.' },
    { type: 'paragraph', text: 'Second paragraph.' },
  ]);
});

test('parses ordered and unordered lists', () => {
  const blocks = parseAssistantMarkdown('1. **Remove eval()**\n2. Parse input as data\n\n- Validate input\n- Add tests');
  assert.deepEqual(blocks, [
    { type: 'ordered-list', items: ['**Remove eval()**', 'Parse input as data'] },
    { type: 'unordered-list', items: ['Validate input', 'Add tests'] },
  ]);
});

test('preserves fenced code and language label', () => {
  const blocks = parseAssistantMarkdown('Example:\n```python\nimport json\nvalue = json.loads(raw)\n```');
  assert.deepEqual(blocks, [
    { type: 'paragraph', text: 'Example:' },
    { type: 'code', language: 'python', text: 'import json\nvalue = json.loads(raw)' },
  ]);
});

test('parses headings and inline Markdown without interpreting HTML', () => {
  const blocks = parseAssistantMarkdown('## Safer approach\nUse `json.loads()` instead of **eval()**.\n<script>alert(1)</script>');
  assert.deepEqual(blocks, [
    { type: 'heading', level: 2, text: 'Safer approach' },
    { type: 'paragraph', text: 'Use `json.loads()` instead of **eval()**. <script>alert(1)</script>' },
  ]);
});

test('keeps an unclosed fenced block as inert code text', () => {
  const blocks = parseAssistantMarkdown('```python\nprint("hello")');
  assert.deepEqual(blocks, [{ type: 'code', language: 'python', text: 'print("hello")' }]);
});
