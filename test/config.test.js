import test from 'node:test';
import assert from 'node:assert/strict';
import { inferAudience, normalizeConfig, evaluate, isOutboundTool, matchGlob } from '../lib/config.js';

test('glob and outbound matching', () => {
  assert.equal(matchGlob('qq_send_group_message', '*send*message*'), true);
  assert.equal(matchGlob('privacy_remember', 'privacy_*'), true);
  assert.equal(isOutboundTool('privacy_remember', normalizeConfig({})), false);
  assert.equal(isOutboundTool('qq_send_group_message', normalizeConfig({})), true);
  assert.equal(isOutboundTool('audio_read', normalizeConfig({})), false);
});

test('audience inference prefers explicit group/private args over names', () => {
  const group = inferAudience('qq_send_group_message', { group_id: '123', message: 'hello' });
  assert.equal(group.audience, 'group');
  assert.equal(group.scope, 'qq:group:123');

  const privateDm = inferAudience('qq_send_private_message', { peer_id: 'u1', message: 'hi' });
  assert.equal(privateDm.audience, 'private');
  assert.equal(privateDm.scope, 'qq:private:u1');

  const publicComment = inferAudience('bili_comment', { comment: 'hi' });
  assert.equal(publicComment.audience, 'public');

  assert.equal(inferAudience('mystery_tool', { payload: 'x' }).audience, 'unknown');
});

test('private terms are blocked for groups and allowed for private', () => {
  const config = normalizeConfig({ pii: 'block' });
  const terms = ['朝阳区'];
  const group = evaluate({
    tool: 'qq_send_group_message',
    args: { group_id: '1', message: '他住在朝阳区，电话 13800138000' },
    config,
    terms,
  });
  assert.equal(group.audience, 'group');
  assert.equal(group.wouldBlock, true);
  assert.deepEqual(group.blocked.map((item) => item.category).sort(), ['pii', 'private-term']);
  assert.match(group.reason, /阻止/);

  const privateDm = evaluate({
    tool: 'qq_send_private_message',
    args: { peer_id: 'u1', message: '他住在朝阳区，电话 13800138000' },
    config,
    terms,
  });
  assert.equal(privateDm.audience, 'private');
  assert.equal(privateDm.wouldBlock, false);
  assert.equal(privateDm.counts['private-term'], 1);
});

test('secret always blocks even in private', () => {
  const config = normalizeConfig({});
  const decision = evaluate({
    tool: 'qq_send_private_message',
    args: { peer_id: 'u1', message: 'key sk-abcdefghijklmnopqrstuvwxyz' },
    config,
  });
  assert.equal(decision.wouldBlock, true);
  assert.equal(decision.blocked[0].category, 'secret');
});

test('explicit audience override wins over inference', () => {
  const config = normalizeConfig({});
  const decision = evaluate({
    tool: 'mystery_tool',
    args: { text: '朝阳区' },
    config,
    terms: ['朝阳区'],
    audience: 'private',
  });
  assert.equal(decision.audience, 'private');
  assert.equal(decision.wouldBlock, false);
});


test('unknown audience defaults to warn, can be raised to block or lowered to allow', () => {
  const args = { message: '他住在朝阳区' };
  const warn = evaluate({ tool: 'send_message', args, config: normalizeConfig({}), terms: ['朝阳区'] });
  assert.equal(warn.audience, 'unknown');
  assert.equal(warn.wouldBlock, false);
  assert.deepEqual(warn.warned.map((item) => item.category), ['private-term']);

  const block = evaluate({ tool: 'send_message', args, config: normalizeConfig({ unknownAudience: 'block' }), terms: ['朝阳区'] });
  assert.equal(block.wouldBlock, true);

  const allow = evaluate({ tool: 'send_message', args, config: normalizeConfig({ unknownAudience: 'allow' }), terms: ['朝阳区'] });
  assert.equal(allow.wouldBlock, false);
  assert.equal(allow.warned.length, 0);
});


test('private chats still block credentials and local paths', () => {
  const config = normalizeConfig({});
  const d = evaluate({
    tool: 'qq_send_private_message',
    args: { peer_id: 'u1', message: '看这个 /Users/alice/secret.txt' },
    config,
  });
  assert.equal(d.audience, 'private');
  assert.equal(d.wouldBlock, true);
  assert.deepEqual(d.blocked.map((item) => item.category), ['path']);
});
