/**
 * Zero-dependency detectors used by both the outbound gate and the `privacy_scan`
 * tool. They are intentionally conservative: a match never includes the secret
 * itself in the returned finding, so an audit log or a tool result cannot become
 * the leak it is trying to prevent.
 */

const SECRET_PATTERNS = [
  ['openai-key', /\bsk-[A-Za-z0-9_-]{16,}\b/g],
  ['github-token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g],
  ['github-pat', /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g],
  ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g],
  ['aws-key', /\bAKIA[0-9A-Z]{16}\b/g],
  ['bearer', /\bBearer\s+[A-Za-z0-9._~+/-]{12,}=*/g],
  ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g],
  ['cookie', /\b(?:SESSDATA|bili_jct|buvid3|sessionid|csrf_token|ct0|auth_token)=([^;\s]{6,})/gi],
  ['api-key-assignment', /\b(?:api[_-]?key|secret[_-]?key|access[_-]?key|client[_-]?secret|token|password|passwd)\b\s*[:=]\s*['"]?([^\s'",;]{8,})/gi],
  ['private-key', /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g],
];

const PII_PATTERNS = [
  ['phone-cn', /(?<!\d)1[3-9]\d{9}(?!\d)/g],
  ['email', /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
  ['id-cn', /(?<!\d)\d{17}[\dXx](?!\d)/g],
  ['ipv4', /(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)/g],
];

const PATH_PATTERNS = [
  ['mac-home', /\/Users\/[^/\s]+\/[^\s"'<>]*/g],
  ['linux-home', /\/home\/[^/\s]+\/[^\s"'<>]*/g],
  ['windows-home', /[A-Za-z]:\\Users\\[^\\\s"'<>]+(?:\\[^\s"'<>]+)*/g],
  ['dsh-home', /(?:~\/\.dsh|\$DSH_HOME|\/\.dsh\/)[^\s"'<>]*/g],
];

const SECRET_LABELS = new Map([
  ['openai-key', 'API key'],
  ['github-token', 'GitHub token'],
  ['github-pat', 'GitHub PAT'],
  ['slack-token', 'Slack token'],
  ['aws-key', 'AWS key'],
  ['bearer', 'Bearer token'],
  ['jwt', 'JWT'],
  ['cookie', 'session cookie'],
  ['api-key-assignment', 'credential assignment'],
  ['private-key', 'private key'],
]);

const PII_LABELS = new Map([
  ['phone-cn', 'phone number'],
  ['email', 'email address'],
  ['id-cn', 'national ID'],
  ['ipv4', 'IP address'],
]);

const PATH_LABELS = new Map([
  ['mac-home', 'home path'],
  ['linux-home', 'home path'],
  ['windows-home', 'home path'],
  ['dsh-home', 'DSH data path'],
]);

function luhnValid(digits) {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = Number(digits[i]);
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

function collect(text, patterns, category, labels, out, max) {
  if (out.length >= max) return;
  for (const [type, regex] of patterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(text)) !== null) {
      if (match[0].length === 0) {
        regex.lastIndex += 1;
        continue;
      }
      if (category === 'pii' && type === 'id-cn' && !/^\d{17}[\dXx]$/.test(match[0])) continue;
      out.push({
        category,
        type,
        label: labels.get(type) || type,
        start: match.index,
        end: match.index + match[0].length,
        severity: category === 'secret' ? 'critical' : category === 'path' ? 'high' : 'medium',
      });
      if (out.length >= max) return;
    }
  }
}

/** Chinese bank cards are usually 16-19 digits; only report ones that pass Luhn. */
function collectBankCards(text, out, max) {
  const regex = /(?<!\d)(?:\d[ -]?){15,18}\d(?!\d)/g;
  let match;
  while ((match = regex.exec(text)) !== null && out.length < max) {
    const digits = match[0].replace(/[ -]/g, '');
    if (digits.length < 16 || digits.length > 19) continue;
    if (!luhnValid(digits)) continue;
    out.push({
      category: 'pii',
      type: 'bank-card',
      label: 'bank card',
      start: match.index,
      end: match.index + match[0].length,
      severity: 'high',
    });
  }
}

function collectPrivateTerms(text, terms, out, max) {
  const needle = String(text).toLowerCase();
  for (const item of terms) {
    if (out.length >= max) return;
    const term = String(typeof item === 'string' ? item : item?.term || '').toLowerCase();
    if (term.length < 2) continue;
    let from = 0;
    for (;;) {
      const index = needle.indexOf(term, from);
      if (index < 0) break;
      out.push({
        category: 'private-term',
        type: 'private-term',
        label: 'private fact',
        termId: (typeof item === 'object' && item?.id) || null,
        start: index,
        end: index + term.length,
        severity: 'high',
      });
      from = index + term.length;
      if (out.length >= max) return;
    }
  }
}

/** Drop overlaps so a phone number inside a secret is not counted twice. */
function dedupe(findings) {
  const sorted = findings.slice().sort((a, b) => a.start - b.start || b.end - a.end);
  const out = [];
  let lastEnd = -1;
  for (const finding of sorted) {
    if (finding.start < lastEnd) continue;
    out.push(finding);
    lastEnd = finding.end;
  }
  return out;
}

/**
 * @param {string} text
 * @param {{terms?: Array<{id?: string, term: string}>, maxFindings?: number}} options
 */
export function scanText(text, options = {}) {
  const source = String(text ?? '');
  const max = Math.max(1, Math.min(Number(options.maxFindings) || 200, 1000));
  const findings = [];
  collect(source, SECRET_PATTERNS, 'secret', SECRET_LABELS, findings, max);
  collect(source, PII_PATTERNS, 'pii', PII_LABELS, findings, max);
  collect(source, PATH_PATTERNS, 'path', PATH_LABELS, findings, max);
  collectBankCards(source, findings, max);
  if (Array.isArray(options.terms)) collectPrivateTerms(source, options.terms, findings, max);
  const deduped = dedupe(findings);
  const counts = {};
  for (const finding of deduped) counts[finding.category] = (counts[finding.category] || 0) + 1;
  return { findings: deduped, counts, truncated: findings.length >= max };
}

export function redactText(text, findings, mode = 'all') {
  const allowed = findings
    .filter((finding) => mode === 'all' || finding.category === mode || finding.category === 'secret')
    .slice()
    .sort((a, b) => b.start - a.start);
  let out = String(text ?? '');
  for (const finding of allowed) {
    const placeholder = finding.category === 'private-term'
      ? '[REDACTED:PRIVATE]'
      : finding.category === 'secret'
        ? '[REDACTED:SECRET]'
        : finding.category === 'path'
          ? '[REDACTED:PATH]'
          : '[REDACTED:PII]';
    out = out.slice(0, finding.start) + placeholder + out.slice(finding.end);
  }
  return out;
}

export function describeFinding(finding) {
  return `${finding.category}:${finding.type} (${finding.label})`;
}
