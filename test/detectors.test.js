import test from 'node:test';
import assert from 'node:assert/strict';
import { scanText, redactText } from '../lib/detectors.js';

test('detects secrets without returning the secret', () => {
  const text = 'token sk-abcdefghijklmnopqrstuvwxyz and Bearer eyJhbGciOiJIUzI1NiJ9.abc.def';
  const result = scanText(text);
  assert.ok(result.counts.secret >= 2);
  assert.equal(result.findings.every((finding) => !JSON.stringify(finding).includes('sk-abc')), true);
  assert.ok(result.findings.every((finding) => finding.category === 'secret'));
});

test('detects phone, email, id card and local paths', () => {
  const text = '电话 13800138000，邮箱 me@example.com，路径 /Users/alice/Documents/secret.txt，身份证 11010519491231002X';
  const result = scanText(text);
  assert.equal(result.counts.pii >= 3, true);
  assert.equal(result.counts.path >= 1, true);
});

test('private terms are deduped and matched case-insensitively', () => {
  const result = scanText('我住在朝阳区，朝阳区很大', { terms: ['朝阳区', '朝阳区'] });
  assert.equal(result.counts['private-term'], 2);
  assert.equal(new Set(result.findings.map((finding) => finding.start)).size, 2);
});

test('redaction replaces the original text', () => {
  const text = 'token sk-abcdefghijklmnopqrstuvwxyz at /Users/alice/x';
  const result = scanText(text);
  const redacted = redactText(text, result.findings);
  assert.equal(redacted.includes('sk-abcdefghijklmnopqrstuvwxyz'), false);
  assert.equal(redacted.includes('/Users/alice'), false);
  assert.match(redacted, /\[REDACTED:SECRET\]/);
  assert.match(redacted, /\[REDACTED:PATH\]/);
});
