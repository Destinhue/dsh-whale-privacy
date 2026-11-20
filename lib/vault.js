/**
 * Encrypted, audience-scoped private memory.
 *
 * This is deliberately a small vault, not a general memory database: the point is
 * that a fact can carry the audience it is allowed to reach. Encryption at rest
 * matters because the vault file sits next to session logs that may be copied into
 * a release zip (the dafeiyu-hub incident in the risk report).
 */

import {
  createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync,
} from 'node:crypto';
import {
  chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

const AAD = Buffer.from('dsh-whale-privacy-v1');
const AUDIENCES = new Set(['private', 'group', 'public']);
const MAX_TERMS = 20;

export class VaultError extends Error {
  constructor(message, hint = '') {
    super(message);
    this.name = 'VaultError';
    this.hint = hint;
  }
}

export function defaultDataDir() {
  const home = process.env.DSH_HOME || join(homedir(), '.dsh');
  return join(home, 'whale-privacy');
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  try {
    const stat = statSync(path);
    if ((stat.mode & 0o077) !== 0) chmodSync(path, 0o700);
  } catch { /* best effort */ }
}

function keyFromEnv(env) {
  const text = String(env || '').trim();
  if (!text) return null;
  if (/^[0-9a-f]{64}$/i.test(text)) return Buffer.from(text, 'hex');
  if (/^[A-Za-z0-9+/=]{43,44}$/.test(text)) {
    const buffer = Buffer.from(text, 'base64');
    if (buffer.length === 32) return buffer;
  }
  return scryptSync(text, AAD, 32);
}

function loadOrCreateKey(root) {
  const envKey = keyFromEnv(process.env.DSH_WHALE_PRIVACY_KEY);
  if (envKey) return envKey;
  const keyFile = join(root, 'vault.key');
  if (existsSync(keyFile)) {
    const key = readFileSync(keyFile);
    if (key.length === 32) return key;
    throw new VaultError('vault.key 不是 32 字节', '删除它会让已有私密记忆无法解密，请先备份。');
  }
  const key = randomBytes(32);
  writeFileSync(keyFile, key, { mode: 0o600 });
  return key;
}

function normalizeTerms(text, terms) {
  const out = [];
  const add = (value) => {
    const term = String(value ?? '').trim();
    if (term.length < 2 || term.length > 200) return;
    if (out.some((item) => item.toLowerCase() === term.toLowerCase())) return;
    out.push(term);
  };
  if (Array.isArray(terms)) for (const term of terms) add(term);
  const body = String(text ?? '').trim();
  if (body.length >= 2 && body.length <= 80) add(body);
  return out.slice(0, MAX_TERMS);
}

function safeId() {
  return `p_${randomBytes(8).toString('hex')}`;
}

export function createVault({ dataDir, ttlDays = 365, logger } = {}) {
  const root = resolve(dataDir || defaultDataDir());
  ensureDir(root);
  const file = join(root, 'vault.enc');
  const key = loadOrCreateKey(root);
  let records = [];
  let lastError = null;
  let writeChain = Promise.resolve();

  const decrypt = (raw) => {
    const envelope = JSON.parse(raw);
    if (envelope?.v !== 1) throw new VaultError('不支持的 vault 版本');
    const iv = Buffer.from(envelope.iv, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    const data = Buffer.from(envelope.data, 'base64');
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(AAD);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
    const parsed = JSON.parse(plain);
    return Array.isArray(parsed?.records) ? parsed.records : [];
  };

  const load = () => {
    if (!existsSync(file)) {
      records = [];
      return;
    }
    try {
      records = decrypt(readFileSync(file, 'utf8'));
      lastError = null;
    } catch (error) {
      const backup = `${file}.corrupt-${Date.now()}`;
      try { renameSync(file, backup); } catch { /* ignore */ }
      records = [];
      lastError = new VaultError(`私密记忆库无法解密：${String(error?.message || error)}`, `已备份到 ${backup}；检查 DSH_WHALE_PRIVACY_KEY 是否被改过。`);
      try { logger?.warn?.(`[dsh-whale-privacy] ${lastError.message}`); } catch { /* ignore */ }
    }
  };

  const saveNow = () => {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(AAD);
    const plain = Buffer.from(JSON.stringify({ version: 1, records }), 'utf8');
    const data = Buffer.concat([cipher.update(plain), cipher.final()]);
    const envelope = {
      v: 1,
      alg: 'aes-256-gcm',
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      data: data.toString('base64'),
    };
    const temp = `${file}.${process.pid}.${Date.now()}.tmp`;
    writeFileSync(temp, JSON.stringify(envelope), { mode: 0o600 });
    renameSync(temp, file);
    try { chmodSync(file, 0o600); } catch { /* ignore */ }
  };

  load();

  const save = () => {
    writeChain = writeChain.then(() => { saveNow(); });
    return writeChain;
  };

  const active = () => records.filter((record) => !record.expiresAt || Date.parse(record.expiresAt) > Date.now());

  const add = async ({ text, terms, audience = 'private', scope, ttlDays: ttl } = {}) => {
    if (lastError) throw lastError;
    const body = String(text ?? '').trim();
    if (!body) throw new VaultError('需要一段要记住的私密内容');
    const level = AUDIENCES.has(audience) ? audience : 'private';
    const days = Math.min(36500, Math.max(1, Number(ttl) || ttlDays));
    const record = {
      id: safeId(),
      text: body.slice(0, 4000),
      terms: normalizeTerms(body, terms),
      audience: level,
      scope: String(scope || (level === 'private' ? 'private:owner' : `${level}:*`)).slice(0, 200),
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + days * 86_400_000).toISOString(),
    };
    records.push(record);
    await save();
    return record;
  };

  const remove = async (id) => {
    const before = records.length;
    records = records.filter((record) => record.id !== id);
    if (records.length === before) return false;
    await save();
    return true;
  };

  const recall = ({ audience = 'private', scope = '', query = '', limit = 10 } = {}) => {
    const level = AUDIENCES.has(audience) ? audience : 'private';
    const q = String(query || '').trim().toLowerCase();
    const scoped = active().filter((record) => {
      if (record.audience === 'public') return true;
      if (record.audience === 'private') return level === 'private';
      // A group fact stays in its own group; it does not follow the model to a
      // different group or to a public comment.
      return level === 'group' && (!scope || record.scope === scope || record.scope.endsWith(`:${scope}`));
    }).filter((record) => {
      if (!q) return true;
      const hay = `${record.text} ${(record.terms || []).join(' ')}`.toLowerCase();
      return hay.includes(q);
    });
    const allowed = scoped.slice(0, Math.min(50, Math.max(1, Number(limit) || 10)));
    return {
      allowed,
      hidden: active().length - scoped.length,
      total: active().length,
    };
  };

  const allTerms = () => {
    const out = [];
    const seen = new Set();
    for (const record of active()) {
      for (const term of record.terms || []) {
        const key = term.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ id: record.id, term });
        if (out.length >= 500) return out;
      }
    }
    return out;
  };

  const stats = () => ({
    path: file,
    encrypted: true,
    count: active().length,
    keySource: process.env.DSH_WHALE_PRIVACY_KEY ? 'env' : 'file',
    error: lastError ? lastError.message : null,
  });

  return { add, remove, recall, allTerms, stats, flush: () => writeChain, root };
}

export function fingerprint(text) {
  return createHash('sha256').update(String(text ?? '')).digest('hex').slice(0, 16);
}
