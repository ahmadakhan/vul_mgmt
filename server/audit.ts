import type { AuditLog } from '../src/types/index.ts';

type Context = NonNullable<AuditLog['context']>;
const sensitive = /password|passphrase|secret|token|authorization|cookie|api[_-]?key|credential/i;

export function auditText(value: unknown, maximum: number): string {
  return Buffer.from(String(value ?? '')
    .replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]+/g, ' ')
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [redacted]')
    .replace(/(?:https?|postgres(?:ql)?|smtps?):\/\/[^\s"'<>]+/gi, (candidate) => {
      try {
        const url = new URL(candidate);
        if (url.username || url.password) { url.username = ''; url.password = ''; }
        for (const key of [...url.searchParams.keys()])
          if (sensitive.test(key)) url.searchParams.set(key, '[redacted]');
        return url.href;
      } catch { return '[invalid URL]'; }
    })
    .replace(/\b([A-Za-z0-9_.-]*(?:password|passphrase|secret|token|authorization|cookie|api[_-]?key|credential)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;&]+)/gi, '$1=[redacted]')
    .trim().slice(0, maximum), 'utf8').toString('utf8');
}

export function auditContext(context: Partial<Context> | undefined, level: AuditLog['level']): Context {
  const result: Context = { outcome: context?.outcome && ['SUCCESS', 'FAILURE', 'DENIED', 'RECORDED'].includes(context.outcome)
    ? context.outcome : level === 'ERROR' ? 'FAILURE' : 'RECORDED' };
  for (const [field, maximum] of [
    ['action', 100], ['resourceType', 80], ['resourceId', 256], ['requestId', 128],
  ] as const) {
    const value = context?.[field];
    if (typeof value === 'string' && value.trim()) result[field] = auditText(value, maximum);
  }
  if (Array.isArray(context?.fields)) {
    result.fields = [...new Set(context.fields.filter((field) => typeof field === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{0,79}$/.test(field)))].sort().slice(0, 40);
  }
  return result;
}

export function commandAudit(action: string, id: string, data: unknown): {
  event: string; details: string; category: AuditLog['category']; context: Context;
} {
  const [entity, operation] = action.split('.');
  const labels: Record<string, string> = {
    feed: 'Threat feed', asset: 'Monitored product', recipient: 'Recipient', webhook: 'Webhook',
    cve: 'Vulnerability record', alias: 'Alias', settings: 'Workspace settings',
    email: 'Email provider configuration', template: 'Advisory template',
    dailyDigestTemplate: 'Daily digest template', finding: 'Finding',
  };
  const operations: Record<string, string> = {
    save: 'updated', configure: 'updated', delete: 'removed', toggle: 'state changed',
    import: 'imported', promote: 'promoted', revoke: 'revoked', status: 'status changed',
  };
  const category: AuditLog['category'] = entity === 'feed' || entity === 'cve' ? 'FEED'
    : entity === 'asset' || entity === 'alias' ? 'WATCHLIST'
    : entity === 'webhook' ? 'WEBHOOK'
    : ['recipient', 'email', 'template', 'dailyDigestTemplate'].includes(entity) ? 'EMAIL' : 'SECURITY';
  const fields = data && typeof data === 'object' && !Array.isArray(data) ? Object.keys(data) : [];
  const context = auditContext({ action, resourceType: entity, resourceId: id, outcome: 'SUCCESS', fields }, 'INFO');
  return {
    event: `${labels[entity] ?? 'Workspace record'} ${operations[operation] ?? 'changed'}`,
    details: `Resource: ${id}${context.fields?.length ? `. Fields supplied: ${context.fields.join(', ')}` : ''}`,
    category, context,
  };
}