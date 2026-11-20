import { evaluate, isOutboundTool, normalizeConfig } from './config.js';
import { createAudit } from './audit.js';
import { createVault, defaultDataDir } from './vault.js';

function dataDirFor(config) {
  return config.dataDir || process.env.DSH_WHALE_PRIVACY_DIR || defaultDataDir();
}

function categories(list) {
  return list.map((item) => `${item.category}:${item.count}`);
}

function textOf(result) {
  if (!result || !Array.isArray(result.content)) return [];
  return result.content.filter((block) => block && block.type === 'text' && typeof block.text === 'string');
}

const PROMPT = [
  '隐私规则（dsh-whale-privacy）：',
  '从私聊、私人记忆、本机文件或凭据中得到的事实，默认只能用于私聊，且只允许发回主人（owner）；发给其他私聊对象、群聊、公开评论或公开发布之前，先调用 privacy_recall 检查它是否允许出现在当前受众。',
  '外发工具会被隐私闸门检查；不要通过改写、编码、拆分或换工具来绕过检查。',
  '需要长期保留的私密事实用 privacy_remember 标注 audience=private；只有明确允许公开的事实才用 audience=public。',
  '当闸门拒绝时，向用户解释哪一类信息被拦下，不要复述原文。',
].join('\n');

export function createGuard({ ctx, config: rawConfig, logger = console } = {}) {
  const config = normalizeConfig(rawConfig);
  const dataDir = dataDirFor(config);
  const vault = createVault({ dataDir, ttlDays: config.vault.ttlDays, logger });
  const audit = createAudit({ dataDir, maxEntries: config.audit.maxEntries, logger });
  const counters = {
    blocked: 0,
    warned: 0,
    allowed: 0,
    redactedResults: 0,
    lastAt: null,
    lastReason: null,
  };

  const mark = () => { counters.lastAt = new Date().toISOString(); };

  const scan = ({ text, audience, toolName = 'privacy_scan' } = {}) => {
    const decision = evaluate({
      tool: toolName,
      args: { text: String(text ?? '') },
      config,
      terms: vault.allTerms(),
      audience,
    });
    counters.scan = (counters.scan || 0) + 1;
    return decision;
  };

  const recordAudit = (event, data) => {
    try {
      audit.append(event, data);
    } catch (error) {
      logger?.warn?.(`[dsh-whale-privacy] audit append failed: ${String(error?.message || error)}`);
    }
  };

  const remember = async ({ text, terms, audience = 'private', scope, ttlDays } = {}) => {
    const record = await vault.add({ text, terms, audience, scope, ttlDays });
    recordAudit('remember', { audience: record.audience, decision: 'stored', reasons: [record.scope] });
    return { ...record, text: undefined, chars: String(text || '').length };
  };

  const recall = ({ audience = 'private', scope = '', query = '', limit = 10 } = {}) => {
    const result = vault.recall({ audience, scope, query, limit });
    recordAudit('recall', { audience, decision: 'read', reasons: [`visible:${result.allowed.length}`, `hidden:${result.hidden}`] });
    return result;
  };

  const forget = async (id) => {
    const removed = await vault.remove(id);
    recordAudit('forget', { decision: removed ? 'removed' : 'missing', reasons: [String(id || '').slice(0, 40)] });
    return removed;
  };

  const status = () => ({
    enabled: config.enabled,
    action: config.action,
    policy: {
      secrets: config.secrets,
      paths: config.paths,
      pii: config.pii,
      privateTerms: config.privateTerms,
      unknownAudience: config.unknownAudience,
      private: config.privateRequiresOwner ? 'owner-only' : 'any',
      owners: config.owners.length,
    },
    vault: vault.stats(),
    audit: audit.stats(),
    counters: { ...counters },
  });

  const preTool = async (exec, next) => {
    if (!config.enabled) return next();
    if (!exec || !isOutboundTool(exec.name, config)) return next();
    let decision;
    try {
      decision = evaluate({
        tool: exec.name,
        args: exec.arguments,
        config,
        terms: vault.allTerms(),
      });
    } catch (error) {
      logger?.warn?.(`[dsh-whale-privacy] scan failed: ${String(error?.message || error)}`);
      return next();
    }
    const reasons = [...categories(decision.blocked), ...categories(decision.warned)];
    if (decision.wouldBlock) {
      counters.blocked += 1;
      counters.lastReason = decision.reason;
      mark();
      recordAudit('outbound-blocked', {
        tool: exec.name,
        audience: decision.audience,
        decision: config.action,
        reasons,
      });
      return {
        kind: config.action,
        reason: decision.reason,
        info: {
          name: 'PrivacyGuard',
          code: 'WHALE_PRIVACY_BLOCKED',
          audience: decision.audience,
          categories: reasons,
        },
      };
    }
    if (decision.warned.length) {
      counters.warned += 1;
      counters.lastReason = decision.reason;
      mark();
      recordAudit('outbound-warned', {
        tool: exec.name,
        audience: decision.audience,
        decision: 'allow',
        reasons,
      });
    } else {
      counters.allowed += 1;
      if (config.audit.logAllow) {
        recordAudit('outbound-allowed', {
          tool: exec.name,
          audience: decision.audience,
          decision: 'allow',
          reasons: [],
        });
      }
    }
    return next();
  };

  const postTool = async (exec, result, next) => {
    if (!config.enabled || !config.scanToolResults) return next();
    if (!exec || String(exec.name || '').startsWith('privacy_')) return next();
    const blocks = textOf(result);
    if (!blocks.length) return next();
    const mode = config.resultRedaction;
    if (mode === 'off') return next();
    let changed = false;
    try {
      for (const block of blocks) {
        const decision = evaluate({
          tool: 'privacy_result',
          args: { text: block.text },
          config,
          terms: [],
          audience: 'private',
        });
        if (!decision.findings.length) continue;
        block.text = redact(block.text, decision.findings, mode);
        changed = true;
      }
    } catch (error) {
      logger?.warn?.(`[dsh-whale-privacy] result redaction failed: ${String(error?.message || error)}`);
      return next();
    }
    if (changed) {
      counters.redactedResults += 1;
      mark();
      recordAudit('result-redacted', { tool: exec.name, decision: 'redacted', reasons: [mode] });
    }
    return next();
  };

  const api = {
    config,
    scan,
    remember,
    recall,
    forget,
    status,
    audit: (limit) => audit.read(limit),
    preTool,
    postTool,
  };

  const promptSection = () => {
    if (!config.promptPolicy || typeof ctx.get !== 'function') return null;
    const systemPrompt = ctx.get('systemPrompt', false);
    if (!systemPrompt || typeof systemPrompt.section !== 'function') return null;
    try {
      return systemPrompt.section({ name: 'whale-privacy', order: 900, text: PROMPT });
    } catch (error) {
      logger?.warn?.(`[dsh-whale-privacy] prompt section failed: ${String(error?.message || error)}`);
      return null;
    }
  };

  return { ...api, promptSection, dataDir };
}

function redact(text, findings, mode) {
  const allowed = new Set(mode === 'secrets-pii' ? ['secret', 'pii', 'path'] : ['secret', 'path']);
  const selected = findings
    .filter((finding) => allowed.has(finding.category))
    .sort((a, b) => b.start - a.start);
  let out = String(text ?? '');
  for (const finding of selected) {
    const tag = finding.category === 'secret' ? 'SECRET'
      : finding.category === 'pii' ? 'PII'
        : finding.category === 'path' ? 'PATH' : 'PRIVATE';
    out = `${out.slice(0, finding.start)}[REDACTED:${tag}]${out.slice(finding.end)}`;
  }
  return out;
}

export { PROMPT };
