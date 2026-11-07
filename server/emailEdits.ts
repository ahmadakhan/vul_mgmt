import type { ReviewEdits } from '../src/types/index.ts';

/**
 * Operator review-time edits are a *layer* over the rendered advisory body.
 *
 * The HTML stored in `outbox.payload.html` is the unmodified render produced by
 * the advisory template. Operator edits (audience notice, reviewer note, or a
 * full body override) are applied when the message is previewed and when it is
 * actually handed to the transport. Keeping the two paths on the same helper is
 * what guarantees the PDF attachment is rendered from exactly the body that is
 * emailed: both `buildPdfAttachment` and the provider payload consume the output
 * of this module.
 *
 * The marker comments make the transform idempotent. Approval historically
 * baked the notice/comment into `payload.html`; retries and the Action Center
 * re-apply edits before sending. Stripping seeded blocks first means an already
 * merged body is never duplicated.
 */

export const AUDIENCE_NOTICE_START = '<!-- vulnstream:audience-notice:start -->';
export const AUDIENCE_NOTICE_END = '<!-- vulnstream:audience-notice:end -->';
export const REVIEWER_COMMENT_START = '<!-- vulnstream:reviewer-comment:start -->';
export const REVIEWER_COMMENT_END = '<!-- vulnstream:reviewer-comment:end -->';

const MAX_SUBJECT_LENGTH = 200;

export const escapeHtml = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
  );

/**
 * Email subjects are header values. An operator-supplied CR/LF or control
 * character must never reach the transport: it would let the subject forge
 * adjacent headers. Newlines collapse to spaces; other control characters are
 * dropped; the result is bounded by the RFC 5322 practical line length.
 */
export function normalizeEmailSubject(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, '')
    .replace(/\s{2,}/g, ' ')
    .trim()
    .slice(0, MAX_SUBJECT_LENGTH);
  return normalized || undefined;
}

/** Escaped, styled block for the audience notice. */
export function audienceNoticeHtml(value: string): string {
  return `${AUDIENCE_NOTICE_START}<div style="margin:16px 0;padding:12px 16px;border-left:3px solid #2563eb;background:#f0f9ff;border-radius:6px;font-size:13px;line-height:20px;color:#0c4a6e;">${escapeHtml(value).replace(/\n/g, '<br/>')}</div>${AUDIENCE_NOTICE_END}`;
}

/** Escaped, styled block for the reviewer note (optionally attributed). */
export function reviewerCommentHtml(value: string, reviewerName?: string): string {
  const byLine = reviewerName ? ` by ${escapeHtml(reviewerName)}` : '';
  return `${REVIEWER_COMMENT_START}<div style="margin:16px 0;padding:12px 16px;border-left:3px solid #f59e0b;background:#fffbeb;border-radius:6px;font-size:13px;line-height:20px;color:#78350f;"><strong>Reviewer note:${byLine}</strong> ${escapeHtml(value).replace(/\n/g, '<br/>')}</div>${REVIEWER_COMMENT_END}`;
}

/** Backwards-compatible block pair used by the approval route. */
export const safeNoticeHtml = (edits: ReviewEdits): { noticeBlock: string; commentBlock: string } => ({
  noticeBlock: edits.audienceNotice ? audienceNoticeHtml(edits.audienceNotice) : '',
  commentBlock: edits.reviewerComment
    ? reviewerCommentHtml(edits.reviewerComment, edits.reviewerName)
    : '',
});

/** Removes every occurrence of a marked block, including the markers. */
function stripMarkedBlock(html: string, start: string, end: string): string {
  let output = html;
  for (let guard = 0; guard < 100; guard++) {
    const from = output.indexOf(start);
    if (from === -1) return output;
    const to = output.indexOf(end, from + start.length);
    // A truncated block (marker without its terminator) is left untouched rather
    // than truncating the operator's message. A later render will keep it.
    if (to === -1) return output;
    output = output.slice(0, from) + output.slice(to + end.length);
  }
  return output;
}

/** Strips previously seeded edit blocks so rendering is repeatable. */
export function stripReviewEdits(html: string): string {
  return stripMarkedBlock(
    stripMarkedBlock(html, REVIEWER_COMMENT_START, REVIEWER_COMMENT_END),
    AUDIENCE_NOTICE_START,
    AUDIENCE_NOTICE_END,
  );
}

const insertAfterBodyOpen = (html: string, block: string): string =>
  /<body\b[^>]*>/i.test(html) ? html.replace(/<body\b[^>]*>/i, (match) => `${match}${block}`) : block + html;

const insertBeforeBodyClose = (html: string, block: string): string =>
  /<\/body>/i.test(html) ? html.replace(/<\/body>/i, (match) => `${block}${match}`) : html + block;

/**
 * Returns the effective HTML body for an operator-edited message.
 *
 * - `edits.customBodyOverride` fully replaces the rendered template when set.
 * - `edits.audienceNotice` is inserted at the top of the body.
 * - `edits.reviewerComment` (and optional `reviewerName`) is inserted at the end.
 *
 * Passing `edits` as an empty object still strips stale blocks, so clearing a
 * notice in the editor removes it on the next preview/send.
 */
export function renderReviewEdits(html: string | undefined, edits?: ReviewEdits | null): string {
  const base =
    edits && typeof edits.customBodyOverride === 'string' && edits.customBodyOverride.trim()
      ? edits.customBodyOverride
      : html ?? '';
  if (!edits) return base;
  let output = stripReviewEdits(base);
  if (edits.audienceNotice?.trim()) output = insertAfterBodyOpen(output, audienceNoticeHtml(edits.audienceNotice));
  if (edits.reviewerComment?.trim())
    output = insertBeforeBodyClose(
      output,
      reviewerCommentHtml(edits.reviewerComment, edits.reviewerName),
    );
  return output;
}

/**
 * Plain-text companion to {@link renderReviewEdits}. Mail clients that prefer
 * `text/plain` must still see the operator's additions; otherwise the same
 * message carries different content depending on the client.
 */
export function renderReviewText(text: string | undefined, edits?: ReviewEdits | null): string {
  let output = text ?? '';
  if (!edits) return output;
  if (edits.audienceNotice?.trim())
    output = `AUDIENCE NOTICE\n${edits.audienceNotice.trim()}\n\n${output}`;
  if (edits.reviewerComment?.trim()) {
    const byLine = edits.reviewerName ? ` by ${edits.reviewerName}` : '';
    output = `${output}\n\nREVIEWER NOTE${byLine}\n${edits.reviewerComment.trim()}`;
  }
  return output;
}

/** Subject override for a job, falling back to the queued subject. */
export function effectiveSubject(queuedSubject: string | undefined, edits?: ReviewEdits | null): string {
  return normalizeEmailSubject(edits?.subject) ?? queuedSubject ?? '';
}
