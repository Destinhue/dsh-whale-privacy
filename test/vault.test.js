import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createVault } from '../lib/vault.js';

test('vault encrypts at rest and recalls by audience', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'whale-vault-'));
  const vault = createVault({ dataDir: dir });
  const secret = '他住在朝阳区，电话 13800138000';
  const record = await vault.add({ text: secret, terms: ['朝阳区'], audience: 'private' });
  assert.match(record.id, /^p_[0-9a-f]{16}$/);

  const raw = readFileSync(join(dir, 'vault.enc'), 'utf8');
  assert.equal(raw.includes(secret), false);
  assert.equal(raw.includes('朝阳区'), false);

  const reopened = createVault({ dataDir: dir });
  assert.equal(reopened.stats().count, 1);
  assert.equal(reopened.recall({ audience: 'private' }).allowed.length, 1);
  assert.equal(reopened.recall({ audience: 'group', scope: 'qq:group:1' }).allowed.length, 0);
});

test('group facts stay in their group scope', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'whale-vault-scope-'));
  const vault = createVault({ dataDir: dir });
  await vault.add({ text: '本群暗号是蓝鲸', audience: 'group', scope: 'qq:group:1' });
  assert.equal(vault.recall({ audience: 'group', scope: 'qq:group:1' }).allowed.length, 1);
  assert.equal(vault.recall({ audience: 'group', scope: 'qq:group:2' }).allowed.length, 0);
  assert.equal(vault.recall({ audience: 'private' }).allowed.length, 0);
});

test('forget removes a fact', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'whale-vault-forget-'));
  const vault = createVault({ dataDir: dir });
  const record = await vault.add({ text: '短期事实', audience: 'private' });
  assert.equal(await vault.remove(record.id), true);
  assert.equal(vault.stats().count, 0);
  assert.equal(await vault.remove(record.id), false);
});
