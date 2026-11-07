import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AUDIENCE_NOTICE_START,
  AUDIENCE_NOTICE_END,
  REVIEWER_COMMENT_START,
  REVIEWER_COMMENT_END,
  effectiveSubject,
  normalizeEmailSubject,
  renderReviewEdits,
  renderReviewText,
} from '../server/emailEdits.ts';

const baseHtml = '<html><body><p>Original body</p></body></html>';
const count = (haystack: string, needle: string) => haystack.split(needle).length - 1;

test('normalizeEmailSubject strips header injection and bounds the line', () => {
  assert.equal(normalizeEmailSubject('  Patch\r\nBcc: attacker@example.invalid\t now  '), 'Patch Bcc: attacker@example.invalid now');
  assert.equal(normalizeEmailSubject('a\u0000b\u001fc'), 'abc');
  assert.equal(normalizeEmailSubject('   '), undefined);
  assert.equal(normalizeEmailSubject(undefined), undefined);
  assert.equal(normalizeEmailSubject(42), undefined);
  assert.equal(normalizeEmailSubject('x'.repeat(250))?.length, 200);
});

test('renderReviewEdits applies the notice and reviewer comment in place', () => {
  const output = renderReviewEdits(baseHtml, {
    audienceNotice: 'Apply the patch tonight.',
    reviewerComment: 'Validated against production.',
    reviewerName: 'Ops',
  });
  assert.ok(output.startsWith(`<html><body>${AUDIENCE_NOTICE_START}`));
  assert.ok(output.includes('Apply the patch tonight.'));
  assert.ok(output.includes('Validated against production.'));
  assert.ok(output.includes(' by Ops'));
  assert.ok(output.indexOf(AUDIENCE_NOTICE_START) < output.indexOf('<p>Original body</p>'));
  assert.ok(output.indexOf(REVIEWER_COMMENT_START) > output.indexOf('<p>Original body</p>'));
  assert.ok(output.trimEnd().endsWith(`</body></html>`));
});

test('renderReviewEdits is idempotent across repeated sends', () => {
  const edits = { audienceNotice: 'Notice', reviewerComment: 'Comment', reviewerName: 'Ops' };
  const once = renderReviewEdits(baseHtml, edits);
  const twice = renderReviewEdits(once, edits);
  assert.equal(twice, once);
  assert.equal(count(twice, AUDIENCE_NOTICE_START), 1);
  assert.equal(count(twice, AUDIENCE_NOTICE_END), 1);
  assert.equal(count(twice, REVIEWER_COMMENT_START), 1);
  assert.equal(count(twice, REVIEWER_COMMENT_END), 1);
});

test('renderReviewEdits clears edits that are no longer present', () => {
  const withEdits = renderReviewEdits(baseHtml, {
    audienceNotice: 'Old notice',
    reviewerComment: 'Old comment',
  });
  const cleared = renderReviewEdits(withEdits, {});
  assert.equal(cleared, baseHtml);
  assert.ok(!cleared.includes(AUDIENCE_NOTICE_START));
  assert.ok(!cleared.includes(REVIEWER_COMMENT_START));
});

test('renderReviewEdits escapes operator HTML', () => {
  const output = renderReviewEdits(baseHtml, {
    audienceNotice: '<img src=x onerror=alert(1)>',
    reviewerComment: '<script>alert(1)</script>',
  });
  assert.ok(!output.includes('<img src=x'));
  assert.ok(!output.includes('<script>'));
  assert.ok(output.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(output.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
});

test('customBodyOverride replaces the template and still carries the edit layer', () => {
  const output = renderReviewEdits(baseHtml, {
    customBodyOverride: '<html><body><p>Replacement</p></body></html>',
    audienceNotice: 'Notice',
  });
  assert.ok(output.includes('Replacement'));
  assert.ok(!output.includes('Original body'));
  assert.ok(output.includes(AUDIENCE_NOTICE_START));
});

test('renderReviewText mirrors the HTML additions for plain-text clients', () => {
  const output = renderReviewText('Body text', {
    audienceNotice: 'Notice text',
    reviewerComment: 'Comment text',
    reviewerName: 'Ops',
  });
  assert.ok(output.startsWith('AUDIENCE NOTICE\nNotice text\n\nBody text'));
  assert.ok(output.endsWith('REVIEWER NOTE by Ops\nComment text'));
});

test('effectiveSubject prefers a normalized override, else the queued subject', () => {
  assert.equal(effectiveSubject('Queued subject', { subject: '  Updated\nsubject ' }), 'Updated subject');
  assert.equal(effectiveSubject('Queued subject', {}), 'Queued subject');
  assert.equal(effectiveSubject('Queued subject', { subject: '   ' }), 'Queued subject');
  assert.equal(effectiveSubject(undefined, undefined), '');
});
