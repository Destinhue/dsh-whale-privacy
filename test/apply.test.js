import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { apply } from '../index.js';

function fakeCtx() {
  const handlers = new Map();
  const specs = [];
  const sections = [];
  let provided = null;
  const ctx = {
    logger: { info() {}, warn() {}, error() {} },
    on(name, handler) {
      handlers.set(name, handler);
      return () => handlers.delete(name);
    },
    get(name) {
      if (name === 'tools') return { register(spec) { specs.push(spec); return () => {}; } };
      if (name === 'systemPrompt') return ctx.systemPrompt;
      return undefined;
    },
    provide(name, value) {
      if (name === 'whalePrivacy') provided = value;
    },
    systemPrompt: {
      section(section) {
        sections.push(section);
        return () => {};
      },
    },
  };
  return { ctx, handlers, specs, sections, get provided() { return provided; } };
}

test('apply registers tools, hooks, prompt section and service', () => {
  const dir = mkdtempSync(join(tmpdir(), 'whale-apply-'));
  const fake = fakeCtx();
  const { ctx, handlers, specs, sections } = fake;
  const dispose = apply(ctx, { dataDir: dir });
  assert.equal(specs.length, 6);
  assert.deepEqual(specs.map((spec) => spec.name).sort(), [
    'privacy_audit', 'privacy_forget', 'privacy_recall', 'privacy_remember', 'privacy_scan', 'privacy_status',
  ]);
  assert.equal(handlers.has('tools/pre-execute'), true);
  assert.equal(handlers.has('tools/post-execute'), true);
  assert.equal(sections.length, 1);
  assert.equal(sections[0].name, 'whale-privacy');
  assert.ok(fake.provided);
  assert.equal(typeof dispose, 'function');
});

test('pre-execute denies a group send containing a private term', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'whale-apply-deny-'));
  const { ctx, handlers, specs } = fakeCtx();
  apply(ctx, { dataDir: dir });
  const remember = specs.find((spec) => spec.name === 'privacy_remember');
  await remember.execute({ text: '他住在朝阳区', terms: ['朝阳区'], audience: 'private' });

  let nextCalled = false;
  const next = async () => { nextCalled = true; return { kind: 'allow' }; };
  const deny = await handlers.get('tools/pre-execute')({
    name: 'qq_send_group_message',
    arguments: { group_id: '123', message: '他住在朝阳区' },
  }, next);
  assert.equal(deny.kind, 'deny');
  assert.match(deny.reason, /私聊/);
  assert.equal(nextCalled, false);

  const blockedPrivate = await handlers.get('tools/pre-execute')({
    name: 'qq_send_private_message',
    arguments: { peer_id: 'u1', message: '他住在朝阳区' },
  }, next);
  assert.equal(blockedPrivate.kind, 'deny');
  assert.match(blockedPrivate.reason, /主人/);
  assert.equal(nextCalled, false);

  const allow = await handlers.get('tools/pre-execute')({
    name: 'qq_send_private_message',
    arguments: { peer_id: 'owner', message: '他住在朝阳区' },
  }, next);
  assert.equal(allow.kind, 'allow');
  assert.equal(nextCalled, true);
});

test('post-execute redacts a secret in tool output', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'whale-apply-post-'));
  const { ctx, handlers } = fakeCtx();
  apply(ctx, { dataDir: dir });
  const result = { content: [{ type: 'text', text: 'token sk-abcdefghijklmnopqrstuvwxyz' }] };
  let nextCalled = false;
  await handlers.get('tools/post-execute')({ name: 'shell' }, result, async () => { nextCalled = true; return result; });
  assert.equal(nextCalled, true);
  assert.match(result.content[0].text, /\[REDACTED:SECRET\]/);
  assert.equal(result.content[0].text.includes('sk-abcdefghijklmnopqrstuvwxyz'), false);
});

test('privacy_scan never echoes the secret', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'whale-apply-scan-'));
  const { ctx, specs } = fakeCtx();
  apply(ctx, { dataDir: dir });
  const scan = specs.find((spec) => spec.name === 'privacy_scan');
  const out = await scan.execute({ text: 'key sk-abcdefghijklmnopqrstuvwxyz', audience: 'public' });
  assert.match(out.text, /BLOCK/);
  assert.equal(out.text.includes('sk-abcdefghijklmnopqrstuvwxyz'), false);
});
