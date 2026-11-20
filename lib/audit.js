/**
 * Tamper-evident audit trail.
 *
 * One JSON object per line, chained by SHA-256. The audit deliberately stores no
 * message text: an audit log that repeats the secret is a second leak. `verify()`
 * catches edits, deletions and reordering after the fact.
 */

import {
  appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';

const GENESIS = '0'.repeat(64);

export class AuditError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuditError';
  }
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
}

export function hashEntry(entry) {
  const canonical = JSON.stringify([
    entry.seq,
    entry.ts,
    entry.event,
    entry.tool || '',
    entry.audience || '',
    entry.decision || '',
    Array.isArray(entry.reasons) ? entry.reasons : [],
    entry.prev || GENESIS,
  ]);
  return createHash('sha256').update(canonical).digest('hex');
}

function parseLines(raw) {
  return String(raw || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

export function createAudit({ dataDir, maxEntries = 2000, logger } = {}) {
  const root = resolve(dataDir);
  ensureDir(root);
  const file = join(root, 'audit.jsonl');
  let entries = [];
  let lastError = null;

  const load = () => {
    if (!existsSync(file)) return;
    try {
      const lines = parseLines(readFileSync(file, 'utf8'));
      entries = lines.map((line) => JSON.parse(line));
    } catch (error) {
      lastError = new AuditError(`审计日志无法解析：${String(error?.message || error)}`);
      entries = [];
      try { logger?.warn?.(`[dsh-whale-privacy] ${lastError.message}`); } catch { /* ignore */ }
    }
  };

  const state = () => {
    const last = entries[entries.length - 1];
    return { seq: last ? Number(last.seq) + 1 : 1, prev: last ? last.hash : GENESIS };
  };

  const rewrite = () => {
    const temp = `${file}.${process.pid}.tmp`;
    writeFileSync(temp, entries.map((entry) => JSON.stringify(entry)).join('\n') + (entries.length ? '\n' : ''), { mode: 0o600 });
    renameSync(temp, file);
  };

  const rotate = () => {
    const limit = Math.max(50, Number(maxEntries) || 2000);
    if (entries.length <= limit) return;
    const keep = entries.slice(-limit);
    // Re-chain the retained window so verification still works after pruning.
    let prev = GENESIS;
    entries = keep.map((entry, index) => {
      const next = {
        seq: index + 1,
        ts: entry.ts,
        event: entry.event,
        tool: entry.tool || '',
        audience: entry.audience || '',
        decision: entry.decision || '',
        reasons: Array.isArray(entry.reasons) ? entry.reasons : [],
        prev,
      };
      next.hash = hashEntry(next);
      prev = next.hash;
      return next;
    });
    rewrite();
  };

  const append = (event, details = {}) => {
    const { seq, prev } = state();
    const entry = {
      seq,
      ts: new Date().toISOString(),
      event: String(event || 'event').slice(0, 80),
      tool: String(details.tool || '').slice(0, 120),
      audience: String(details.audience || '').slice(0, 20),
      decision: String(details.decision || '').slice(0, 40),
      reasons: Array.isArray(details.reasons)
        ? details.reasons.slice(0, 8).map((item) => String(item).slice(0, 40))
        : [],
      prev,
    };
    entry.hash = hashEntry(entry);
    entries.push(entry);
    try {
      appendFileSync(file, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
      if (entries.length > Math.max(50, Number(maxEntries) || 2000) + 32) rotate();
    } catch (error) {
      lastError = new AuditError(`审计日志写入失败：${String(error?.message || error)}`);
      throw lastError;
    }
    return entry;
  };

  const verify = () => {
    let prev = GENESIS;
    for (let index = 0; index < entries.length; index += 1) {
      const entry = entries[index];
      if (entry.prev !== prev) return { ok: false, checked: index, brokenAt: index, reason: 'prev-mismatch' };
      if (entry.hash !== hashEntry(entry)) return { ok: false, checked: index, brokenAt: index, reason: 'hash-mismatch' };
      prev = entry.hash;
    }
    return { ok: true, checked: entries.length, brokenAt: null, reason: null };
  };

  const read = (limit = 50) => entries.slice(-Math.max(1, Math.min(500, Number(limit) || 50)));

  const stats = () => {
    const check = verify();
    return {
      path: file,
      count: entries.length,
      lastSeq: entries.length ? entries[entries.length - 1].seq : 0,
      ok: check.ok,
      error: lastError ? lastError.message : null,
      size: existsSync(file) ? statSync(file).size : 0,
    };
  };

  load();

  return { append, read, verify, stats, file };
}
