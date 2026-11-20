import { categorySummary } from './config.js';

const OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: true,
    properties: {
      text: { type: 'string', description: 'Human-readable, redacted result.' },
    },
  },
  render(args, value) {
    return [{ type: 'text', text: value?.text ?? '(no output)' }];
  },
};

function lines(value) {
  return String(value ?? '').replace(/\s+$/g, '');
}

function statusText(status) {
  const policy = status.policy;
  return lines([
    'dsh-whale-privacy 状态',
    `enabled: ${status.enabled} · action: ${status.action}`,
    `policy: secrets=${policy.secrets} paths=${policy.paths} pii=${policy.pii} privateTerms=${policy.privateTerms} unknown=${policy.unknownAudience}`,
    `vault: ${status.vault.count} 条 · ${status.vault.encrypted ? 'AES-256-GCM 加密' : '未加密'} · ${status.vault.path}`,
    `audit: ${status.audit.count} 条 · chain ${status.audit.ok ? 'OK' : 'BROKEN'} · ${status.audit.path}`,
    `counters: blocked=${status.counters.blocked} warned=${status.counters.warned} allowed=${status.counters.allowed} redactedResults=${status.counters.redactedResults}`,
    status.vault.error ? `vault error: ${status.vault.error}` : '',
    status.audit.error ? `audit error: ${status.audit.error}` : '',
  ].filter(Boolean).join('\n'));
}

function scanText(decision) {
  const found = categorySummary(decision.counts) || 'none';
  return lines([
    `audience: ${decision.audience}${decision.scope ? ` (${decision.scope})` : ''}`,
    `findings: ${found}`,
    `decision: ${decision.wouldBlock ? 'BLOCK' : decision.warned.length ? 'WARN' : 'ALLOW'}`,
    decision.reason ? `reason: ${decision.reason}` : '',
    '注意：这里只返回类别和数量，不返回命中的原文。',
  ].filter(Boolean).join('\n'));
}

export function createToolSpecs(guard) {
  const specs = [];

  specs.push({
    name: 'privacy_status',
    description: 'Read the dsh-whale-privacy guard status: policy, encrypted vault count, audit chain health, and counters. Use when the user asks whether the privacy guard is on.',
    parameters: { type: 'object', additionalProperties: false, properties: {} },
    output: OUTPUT,
    async execute() {
      return { text: statusText(guard.status()) };
    },
  });

  specs.push({
    name: 'privacy_scan',
    description: 'Dry-run the privacy gate on a piece of text without sending it. Returns audience, finding categories/counts and the decision; never returns the matched secrets. Use before composing a group/public message that may contain private facts.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['text'],
      properties: {
        text: { type: 'string', description: 'The exact text that would be sent.' },
        audience: { type: 'string', enum: ['private', 'group', 'public', 'unknown'], description: 'Override the inferred audience; omit to infer from the context.' },
        toolName: { type: 'string', description: 'Optional outbound tool name used for audience inference.' },
      },
    },
    output: OUTPUT,
    async execute(args) {
      const decision = guard.scan({ text: args?.text, audience: args?.audience, toolName: args?.toolName });
      return { text: scanText(decision) };
    },
  });

  specs.push({
    name: 'privacy_remember',
    description: 'Store a private fact in the encrypted, audience-scoped vault. audience=private means it can only be recalled in private; group means only the same group scope; public means any audience. Returns only an id and counts, not the text.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['text'],
      properties: {
        text: { type: 'string', description: 'The fact to remember.' },
        audience: { type: 'string', enum: ['private', 'group', 'public'], description: 'Who may receive this fact later. Default private.' },
        scope: { type: 'string', description: 'For group facts: the group scope, e.g. qq:group:123456.' },
        terms: { type: 'array', items: { type: 'string' }, description: 'Short phrases that identify this fact in outbound text.' },
        ttlDays: { type: 'integer', minimum: 1, maximum: 36500, description: 'Expiry in days; default follows config.' },
      },
    },
    output: OUTPUT,
    async execute(args) {
      const record = await guard.remember(args || {});
      return {
        text: lines([
          `stored: ${record.id}`,
          `audience: ${record.audience}`,
          `scope: ${record.scope}`,
          `terms: ${record.terms?.length ?? 0} · expires: ${record.expiresAt}`,
          `chars: ${record.chars}`,
        ].join('\n')),
      };
    },
  });

  specs.push({
    name: 'privacy_recall',
    description: 'Recall only the private facts allowed for the current audience. Private facts stay hidden from group/public recall. Use before writing a group or public reply that depends on memory.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        query: { type: 'string', description: 'Optional substring filter.' },
        audience: { type: 'string', enum: ['private', 'group', 'public'], description: 'Current target audience. Default private.' },
        scope: { type: 'string', description: 'Current group scope when audience=group.' },
        limit: { type: 'integer', minimum: 1, maximum: 50, description: 'Max facts. Default 10.' },
      },
    },
    output: OUTPUT,
    async execute(args) {
      const result = guard.recall(args || {});
      const body = result.allowed.length
        ? result.allowed.map((record) => `- ${record.id} [${record.audience}] ${record.text}`).join('\n')
        : '(no visible fact)';
      return {
        text: lines([
          `visible: ${result.allowed.length} · hidden: ${result.hidden} · total: ${result.total}`,
          body,
        ].join('\n')),
      };
    },
  });

  specs.push({
    name: 'privacy_forget',
    description: 'Delete one private fact by id. Use when the user asks to forget something; there is no undo.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['id'],
      properties: { id: { type: 'string', description: 'The p_… id returned by privacy_remember or privacy_recall.' } },
    },
    output: OUTPUT,
    async execute(args) {
      const removed = await guard.forget(args?.id);
      return { text: removed ? `removed: ${args.id}` : `not found: ${args?.id ?? ''}` };
    },
  });

  specs.push({
    name: 'privacy_audit',
    description: 'Read the tamper-evident audit trail (Hash chain, no message text). Use to explain what the gate blocked or allowed.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        limit: { type: 'integer', minimum: 1, maximum: 200, description: 'Number of recent entries. Default 20.' },
      },
    },
    output: OUTPUT,
    async execute(args) {
      const limit = Number(args?.limit) || 20;
      const entries = guard.audit(limit);
      const check = guard.status().audit;
      const body = entries.map((entry) => [
        `#${entry.seq}`,
        entry.ts,
        entry.event,
        entry.tool || '-',
        entry.audience || '-',
        entry.decision || '-',
        (entry.reasons || []).join(','),
      ].join(' · ')).join('\n') || '(empty)';
      return {
        text: lines([
          `chain: ${check.ok ? 'OK' : 'BROKEN'} · entries: ${check.count}`,
          body,
        ].join('\n')),
      };
    },
  });

  return specs;
}
