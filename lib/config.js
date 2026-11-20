/**
 * Configuration, audience inference and the decision shared by the tool gate,
 * the `privacy_scan` tool and the tests.
 *
 * The important design choice: audience is inferred from the *tool call*, not
 * from the model's claim. A model that says "this is private" cannot widen a
 * group send; the `group_id` in the arguments decides it.
 */

import * as detectors from './detectors.js';

export const DEFAULTS = {
  enabled: true,
  action: 'deny',
  outboundTools: [
    '*send*message*',
    '*send*text*',
    '*send*reply*',
    '*reply*',
    '*comment*',
    '*publish*',
    '*post*',
    '*dm*',
    '*webhook*',
    '*broadcast*',
    '*announce*',
    '*group*message*',
    '*private*message*',
  ],
  excludedTools: ['privacy_*', 'audio_*', 'video_*'],
  unknownAudience: 'warn',
  secrets: 'block',
  paths: 'block',
  pii: 'warn',
  privateTerms: 'block',
  scanToolResults: true,
  resultRedaction: 'secrets',
  maxScanChars: 20000,
  dataDir: '',
  audit: { maxEntries: 2000, logAllow: true },
  vault: { enabled: true, ttlDays: 365 },
  promptPolicy: true,
};

const ENUMS = {
  action: ['deny', 'ask'],
  unknownAudience: ['block', 'warn', 'allow'],
  secrets: ['block', 'warn', 'off'],
  paths: ['block', 'warn', 'off'],
  pii: ['block', 'warn', 'off'],
  privateTerms: ['block', 'warn', 'off'],
  resultRedaction: ['off', 'secrets', 'secrets-pii'],
};

export function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

export function mergeDeep(base, patch) {
  const out = Array.isArray(base) ? base.slice() : { ...(isPlainObject(base) ? base : {}) };
  if (!isPlainObject(patch)) return out;
  for (const [key, value] of Object.entries(patch)) {
    if (isPlainObject(value) && isPlainObject(out[key])) out[key] = mergeDeep(out[key], value);
    else if (value !== undefined) out[key] = value;
  }
  return out;
}

function strings(value, fallback) {
  if (!Array.isArray(value)) return fallback.slice();
  const out = value.map((item) => String(item ?? '').trim()).filter(Boolean);
  return out.length ? out : fallback.slice();
}

function enumValue(value, allowed, fallback) {
  const text = String(value ?? '').trim();
  return allowed.includes(text) ? text : fallback;
}

function boundedNumber(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.round(number)));
}

export function normalizeConfig(raw) {
  const config = mergeDeep(DEFAULTS, isPlainObject(raw) ? raw : {});
  config.enabled = config.enabled !== false;
  config.action = enumValue(config.action, ENUMS.action, DEFAULTS.action);
  config.unknownAudience = enumValue(config.unknownAudience, ENUMS.unknownAudience, DEFAULTS.unknownAudience);
  config.secrets = enumValue(config.secrets, ENUMS.secrets, DEFAULTS.secrets);
  config.paths = enumValue(config.paths, ENUMS.paths, DEFAULTS.paths);
  config.pii = enumValue(config.pii, ENUMS.pii, DEFAULTS.pii);
  config.privateTerms = enumValue(config.privateTerms, ENUMS.privateTerms, DEFAULTS.privateTerms);
  config.resultRedaction = enumValue(config.resultRedaction, ENUMS.resultRedaction, DEFAULTS.resultRedaction);
  config.outboundTools = strings(config.outboundTools, DEFAULTS.outboundTools);
  config.excludedTools = strings(config.excludedTools, DEFAULTS.excludedTools);
  config.scanToolResults = config.scanToolResults !== false;
  config.maxScanChars = boundedNumber(config.maxScanChars, DEFAULTS.maxScanChars, 200, 200000);
  config.dataDir = String(config.dataDir ?? '').trim();
  config.audit = mergeDeep(DEFAULTS.audit, config.audit);
  config.audit.maxEntries = boundedNumber(config.audit.maxEntries, DEFAULTS.audit.maxEntries, 50, 100000);
  config.audit.logAllow = config.audit.logAllow !== false;
  config.vault = mergeDeep(DEFAULTS.vault, config.vault);
  config.vault.enabled = config.vault.enabled !== false;
  config.vault.ttlDays = boundedNumber(config.vault.ttlDays, DEFAULTS.vault.ttlDays, 1, 36500);
  config.promptPolicy = config.promptPolicy !== false;
  return config;
}

/** Tiny glob matcher: `*` spans anything, `?` one character. */
export function matchGlob(name, pattern) {
  const escaped = String(pattern || '')
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, 'i').test(String(name || ''));
}

export function matchesAny(name, patterns) {
  return (Array.isArray(patterns) ? patterns : []).some((pattern) => matchGlob(name, pattern));
}

export function isOutboundTool(name, config) {
  if (!name) return false;
  if (matchesAny(name, config.excludedTools)) return false;
  return matchesAny(name, config.outboundTools);
}

const PREFERRED_KEYS = new Set([
  'text', 'content', 'message', 'comment', 'caption', 'body', 'markdown',
  'title', 'description', 'reply', 'post', 'dm', 'prompt', 'summary',
]);

const SKIP_KEYS = new Set([
  'file', 'filepath', 'path', 'image', 'images', 'audio', 'video', 'base64',
  'data', 'buffer', 'bytes', 'attachments', 'mime', 'mimetype', 'id', 'chat_id',
]);

function pushStrings(value, key, out, depth) {
  if (out.length >= 400 || depth > 8 || value == null) return;
  if (typeof value === 'string') {
    const text = value.trim();
    if (text) out.push(text);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) pushStrings(item, key, out, depth + 1);
    return;
  }
  if (typeof value === 'object') {
    for (const [childKey, childValue] of Object.entries(value)) {
      pushStrings(childValue, childKey, out, depth + 1);
    }
  }
}

/** Return the human-visible text of an outbound call, never the raw JSON. */
export function extractText(args, maxChars = 20000) {
  const preferred = [];
  const other = [];
  if (typeof args === 'string') {
    preferred.push(args);
  } else if (args && typeof args === 'object') {
    for (const [key, value] of Object.entries(args)) {
      const lower = key.toLowerCase();
      if (SKIP_KEYS.has(lower)) continue;
      if (PREFERRED_KEYS.has(lower)) pushStrings(value, key, preferred, 0);
      else pushStrings(value, key, other, 0);
    }
  }
  const joined = (preferred.length ? preferred : other).join('\n').trim();
  return joined.length > maxChars ? `${joined.slice(0, maxChars)}\n…[truncated]` : joined;
}

const PLATFORM_PREFIX = /^(qq|bili|wechat|wecom|feishu|dingtalk|telegram|discord|slack|matrix|mastodon|twitter|x)[_:.-]/i;

function platformOf(name) {
  const match = String(name || '').match(PLATFORM_PREFIX);
  return match ? match[1].toLowerCase() : 'unknown';
}

function firstValue(args, keys) {
  if (!args || typeof args !== 'object') return null;
  for (const key of keys) {
    const value = args[key];
    if (value !== undefined && value !== null && typeof value !== 'object') return value;
  }
  return null;
}

function hasKey(args, keys) {
  if (!args || typeof args !== 'object') return false;
  return keys.some((key) => Object.prototype.hasOwnProperty.call(args, key));
}

const GROUP_KEYS = ['group_id', 'groupid', 'group', 'room_id', 'roomid', 'guild_id', 'guildid', 'channel_id', 'channelid', 'chat_id', 'chatid', 'conversation_id', 'conversationid', 'group_code'];
const PRIVATE_KEYS = ['peer_id', 'peerid', 'user_id', 'userid', 'openid', 'friend_id', 'friendid', 'target_user', 'recipient', 'to'];

export function inferAudience(toolName, args) {
  const name = String(toolName || '');
  const platform = platformOf(name);
  const publicByName = /(comment|post|publish|dynamic|feed|tweet|公开|评论|动态|弹幕)/i.test(name);
  const groupByName = /(group|room|guild|channel|群|频道)/i.test(name);
  const privateByName = /(private|dm|direct|friend|peer|私聊|好友)/i.test(name);
  const publicByArg = hasKey(args, ['comment', 'post', 'dynamic', 'feed', 'tweet', 'public']);
  const groupByArg = hasKey(args, GROUP_KEYS);
  const privateByArg = hasKey(args, PRIVATE_KEYS);

  let audience = 'unknown';
  let reason = 'no-audience-signal';
  if (publicByName || publicByArg) {
    audience = 'public';
    reason = publicByName ? 'tool-name-public' : 'argument-public';
  } else if (groupByName || groupByArg) {
    audience = 'group';
    reason = groupByName ? 'tool-name-group' : 'argument-group';
  } else if (privateByName || privateByArg) {
    audience = 'private';
    reason = privateByName ? 'tool-name-private' : 'argument-private';
  }

  const targetId = firstValue(args, audience === 'group' ? GROUP_KEYS : audience === 'private' ? PRIVATE_KEYS : [...GROUP_KEYS, ...PRIVATE_KEYS]);
  const scope = audience === 'unknown'
    ? null
    : `${platform}:${audience}:${targetId == null ? '*' : String(targetId)}`;
  return { audience, platform, targetId: targetId == null ? null : String(targetId), scope, reason };
}

const BLOCK_TEXT = {
  secret: '密钥/凭据',
  'private-term': '仅限私聊的私人信息',
  pii: '个人信息（手机号/邮箱/证件号等）',
  path: '本机路径',
};

function modeFor(category, config) {
  if (category === 'secret') return config.secrets;
  if (category === 'path') return config.paths;
  if (category === 'pii') return config.pii;
  if (category === 'private-term') return config.privateTerms;
  return 'off';
}

/**
 * The single policy decision. For `private` targets only secrets and paths are
 * restricted; private terms are exactly what a private chat is for.
 */
export function evaluate({ tool, args, config, terms = [], audience: forcedAudience = null }) {
  const text = extractText(args, config.maxScanChars);
  const audienceInfo = forcedAudience
    ? { audience: String(forcedAudience), platform: 'local', targetId: null, scope: null, reason: 'explicit' }
    : inferAudience(tool, args);
  const { audience } = audienceInfo;
  const scanResult = scan(text, terms);
  const blocked = [];
  const warned = [];

  for (const [category, count] of Object.entries(scanResult.counts)) {
    if (!count) continue;
    let mode = modeFor(category, config);
    if (mode === 'off') continue;

    // An unknown recipient is not a license to leak: by default the gate warns
    // (so a human sees it) but still blocks secrets outright. `unknownAudience:
    // 'block'` upgrades the rest to the normal block policy; `'allow'` leaves
    // only the always-on secret rule.
    const unknown = audience === 'unknown';
    const restrictedAudience = category === 'secret'
      || audience === 'group'
      || audience === 'public'
      || (unknown && config.unknownAudience !== 'allow');
    if (!restrictedAudience) continue;
    if (unknown && category !== 'secret' && config.unknownAudience === 'warn' && mode === 'block') {
      mode = 'warn';
    }
    if (mode === 'block') blocked.push({ category, count });
    else warned.push({ category, count });
  }

  const first = blocked[0] || warned[0] || null;
  const reason = first
    ? `出站内容包含${BLOCK_TEXT[first.category] || first.category}（${first.category}${first.count > 1 ? ` ×${first.count}` : ''}），已由隐私闸门${blocked.length ? '阻止' : '标记'}。`
    : null;

  return {
    text,
    ...audienceInfo,
    findings: scanResult.findings,
    counts: scanResult.counts,
    blocked,
    warned,
    wouldBlock: blocked.length > 0,
    action: blocked.length ? config.action : 'allow',
    reason,
  };
}

function scan(text, terms) {
  // Kept as a tiny indirection so tests can import the pure detector separately.
  return detectors.scanText(text, { terms });
}


export function categorySummary(counts) {
  return Object.entries(counts)
    .filter(([, count]) => count > 0)
    .map(([category, count]) => `${category}:${count}`)
    .join(', ');
}
