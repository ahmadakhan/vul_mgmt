import type { Db } from '../db.ts';
import { enqueue } from '../delivery.ts';
import type { EmailRecipient, WebhookEndpoint } from '../../src/types/index.ts';
import { readNativeEvidence } from './notificationEvidence.ts';

/**
 * Escapes a feed-derived value for an HTML text node or attribute.
 *
 * The correlation alert carries article titles, URLs and match reasons straight
 * from ingested feeds. Rendering them uneescaped would let a hostile source
 * inject markup into a delivered email.
 */
const submitSafe = (value: string) =>
  value.replace(/[&<>"']/g, (character) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!,
  );
/** Runs inside a transaction: event claim and existing outbox insertion commit together. */
export async function queueNativeNotifications(db: Db): Promise<number> {
  const policy = await db.query<{ notifications_enabled: boolean }>('SELECT notifications_enabled FROM correlation_policy WHERE id=1');
  if (!policy.rows[0]?.notifications_enabled) return 0;
  const recipientRows = await db.query<{
    data: EmailRecipient;
  }>(`SELECT data FROM records WHERE kind='recipients'
    AND data->>'enabled'='true' AND data->>'subscriptionTier'='ALL_SEVERITIES' ORDER BY id LIMIT 1001`);
  const hookRows = await db.query<{ data: WebhookEndpoint }>(`SELECT data FROM records WHERE kind='webhooks'
    AND data->>'enabled'='true' AND (data->'events') ? 'ALL' ORDER BY id LIMIT 1001`);
  if (recipientRows.rows.length > 1000 || hookRows.rows.length > 1000)
    throw new Error('NOTIFICATION_FANOUT_LIMIT');
  const recipients = recipientRows.rows.map((row) => row.data),
    hooks = hookRows.rows.map((row) => row.data);
  if (!recipients.length && !hooks.length) return 0;
  const articles = await db.query<{ advisory_id: string }>(
    `SELECT DISTINCT m.advisory_id FROM correlation_matches m
    CROSS JOIN correlation_policy p LEFT JOIN correlation_notifications n ON n.advisory_id=m.advisory_id
    WHERE p.id=1 AND p.notifications_enabled AND m.created_at>=p.notifications_since
    AND (n.advisory_id IS NULL OR m.created_at>n.queued_at)
    AND EXISTS (
      SELECT 1 FROM correlation_matches candidate
      JOIN correlation_match_evidence e ON e.advisory_id=candidate.advisory_id AND e.asset_id=candidate.asset_id
      JOIN correlation_asset_inventory i ON i.id=candidate.asset_id
      WHERE candidate.advisory_id=m.advisory_id AND e.asset_revision=i.revision
    )
    AND (SELECT count(*) FROM (SELECT 1 FROM correlation_matches fanout WHERE fanout.advisory_id=m.advisory_id LIMIT 1001) bounded)<=1000
    AND ($1::boolean OR NOT EXISTS(SELECT 1 FROM correlation_matches other WHERE other.advisory_id=m.advisory_id AND other.confidence<>'HIGH'))
    ORDER BY m.advisory_id LIMIT 20`,
    [recipients.length > 0],
  );
  if (!articles.rowCount) return 0;
  let queued = 0;
  for (const { advisory_id: advisoryId } of articles.rows) {
    const evidence = await readNativeEvidence(db, advisoryId);
    if (!evidence) continue;
    const eligibleRecipients = recipients.filter(
      (rec) => rec.enabled && rec.subscriptionTier === 'ALL_SEVERITIES',
    );
    const eligibleHooks =
      evidence.confidence === 'HIGH'
        ? hooks.filter((hook) => hook.enabled && hook.events.includes('ALL'))
        : [];
    if (!eligibleRecipients.length && !eligibleHooks.length) continue;
    const claim = await db.query(
      `INSERT INTO correlation_notifications(advisory_id,evidence_hash) VALUES($1,$2)
      ON CONFLICT(advisory_id) DO UPDATE SET evidence_hash=EXCLUDED.evidence_hash,queued_at=now()
      WHERE correlation_notifications.evidence_hash<>EXCLUDED.evidence_hash RETURNING advisory_id`,
      [advisoryId, evidence.evidenceHash],
    );
    if (!claim.rowCount) {
      await db.query(
        'UPDATE correlation_notifications SET queued_at=now() WHERE advisory_id=$1 AND evidence_hash=$2',
        [advisoryId, evidence.evidenceHash],
      );
      continue;
    }
    const nativeCorrelation = {
      advisoryId,
      evidenceHash: evidence.evidenceHash,
      confidence: evidence.confidence,
    };
    const subject =
      `[Threat intelligence] [${evidence.confidence} confidence] ${evidence.article.title}`.replace(
        /[\r\n]/g,
        ' ',
      );
    const reasonLines = evidence.matches
      .map((match) => `${match.vendor} / ${match.product} (${match.assetId}): ${match.reason}`)
      .join('\n');
    const lowConfidenceNotice =
      'Low confidence notice: at least one correlation is a MEDIUM-confidence match. ' +
      'Confirm the affected version against vendor guidance before remediation.';
    const text =
      `${evidence.article.title}\n\nEvidence confidence: ${evidence.confidence}\nSource: ${evidence.article.url}\n\n` +
      reasonLines +
      (evidence.confidence === 'MEDIUM' ? `\n\n${lowConfidenceNotice}` : '') +
      '\n\nThis is an applicability signal. Confirm source authenticity and affected versions before remediation.';
    // A body is required: the worker sends `payload.html` whenever it is present,
    // so a native alert without one shipped a message part that dropped the
    // confidence statement entirely.
    const html =
      '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
      `<title>${submitSafe(subject)}</title></head>` +
      '<body style="margin:0;padding:24px;background:#f1f3f5;font-family:Arial,Helvetica,sans-serif;">' +
      '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #dfe4e8;border-top:4px solid #1e40af;">' +
      '<tr><td style="padding:20px 24px;border-bottom:1px solid #dfe4e8;">' +
      '<p style="margin:0;font-size:14px;font-weight:700;color:#17212b;">VulnStream Enterprise</p>' +
      '<p style="margin:3px 0 0;font-size:12px;color:#52606d;">THREAT INTELLIGENCE / CORRELATION SIGNAL</p></td></tr>' +
      '<tr><td style="padding:24px;">' +
      `<p style="margin:0 0 12px;"><span style="display:inline-block;padding:4px 9px;border-radius:4px;background:${evidence.confidence === 'HIGH' ? '#1e40af' : '#b7791f'};color:#ffffff;font-size:11px;font-weight:700;">${submitSafe(evidence.confidence)} CONFIDENCE</span></p>` +
      `<h1 style="margin:0 0 12px;font-size:20px;line-height:28px;color:#111827;">${submitSafe(evidence.article.title)}</h1>` +
      `<p style="margin:0 0 4px;font-size:13px;color:#374151;"><strong>Source:</strong> ${submitSafe(evidence.article.url)}</p>` +
      `<p style="margin:0 0 12px;font-size:13px;color:#374151;"><strong>Evidence confidence:</strong> ${submitSafe(evidence.confidence)}</p>` +
      `<pre style="margin:0;padding:12px;background:#f7f8fa;border-left:3px solid #b7791f;font-size:13px;line-height:20px;color:#374151;white-space:pre-wrap;word-break:break-word;">${submitSafe(reasonLines)}</pre>` +
      (evidence.confidence === 'MEDIUM'
        ? `<p style="margin:12px 0 0;padding:8px 10px;background:#fffbeb;border-left:3px solid #b7791f;font-size:13px;line-height:19px;color:#7c2d12;"><strong>Low confidence notice:</strong> ${submitSafe(lowConfidenceNotice.replace('Low confidence notice: ', ''))}</p>`
        : '') +
      '<p style="margin:12px 0 0;font-size:13px;line-height:20px;color:#52606d;">This is an applicability signal. Confirm source authenticity and affected versions before remediation.</p>' +
      '</td></tr></table></body></html>';
    const payload = { subject, text, html, cveIds: [], nativeCorrelation };
    const identity = `native:${advisoryId}:${evidence.evidenceHash}`;
    for (const recipient of eligibleRecipients) {
      // Every recipient is queued for delivery, whatever the evidence confidence
      // or delivery group: there is no review queue. The subject names the
      // confidence and the body states that the signal needs confirmation, so a
      // MEDIUM-confidence correlation is disclosed rather than withheld.
      if (
        await enqueue(
          db,
          'email',
          recipient.id,
          `NATIVE:${advisoryId}`,
          { ...payload, recipientEmail: recipient.email },
          `${identity}:email:${recipient.id}`,
          'QUEUED',
        )
      )
        queued++;
    }
    for (const hook of eligibleHooks)
      if (
        await enqueue(
          db,
          'webhook',
          hook.id,
          `NATIVE:${advisoryId}`,
          payload,
          `${identity}:webhook:${hook.id}`,
        )
      )
        queued++;
  }
  return queued;
}
