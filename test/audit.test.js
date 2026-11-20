import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAudit } from '../lib/audit.js';

test('audit appends a verifiable chain', () => {
  const dir = mkdtempSync(join(tmpdir(), 'whale-audit-'));
  const audit = createAudit({ dataDir: dir, maxEntries: 50 });
  audit.append('outbound-blocked', { tool: 'qq_send_group_message', audience: 'group', decision: 'deny', reasons: ['private-term:1'] });
  audit.append('outbound-allowed', { tool: 'qq_send_private_message', audience: 'private', decision: 'allow' });
  const check = audit.verify();
  assert.equal(check.ok, true);
  assert.equal(check.checked, 2);
  assert.equal(audit.read(1).length, 1);
});

test('tampering breaks verification', () => {
  const dir = mkdtempSync(join(tmpdir(), 'whale-audit-tamper-'));
  const audit = createAudit({ dataDir: dir, maxEntries: 50 });
  audit.append('outbound-blocked', { tool: 'qq_send_group_message', audience: 'group', decision: 'deny' });
  const file = join(dir, 'audit.jsonl');
  const raw = readFileSync(file, 'utf8');
  writeFileSync(file, raw.replace('outbound-blocked', 'outbound-allowed'));
  const reopened = createAudit({ dataDir: dir });
  assert.equal(reopened.verify().ok, false);
});
