import { test } from 'node:test';
import assert from 'node:assert/strict';
import { advisoryEmail } from '../server/advisoryEmail';
import type { Advisory } from '../src/types/index.ts';
const advisory: Advisory = { id: 'SECURITY-12345', title: 'Widget vulnerability', severity: 'HIGH',
  cveIds: ['CVE-2026-98001'], findingIds: ['finding'], createdDate: new Date().toISOString(),
  deliveryStatus: 'PENDING', recipientCount: 1, executiveSummary: 'Investigate widget',
  affectedSystems: ['widget'], remediationInstructions: 'Apply the vendor patch' };
test('advisory email carries the prefixed identifier in subject, text and custom HTML', () => {
  const email = advisoryEmail(advisory, '<html><body><p>Security notice</p></body></html>');
  assert.equal(email.subject, '[SECURITY-12345] [HIGH] Widget vulnerability');
  assert.match(email.text, /^Advisory ID: SECURITY-12345/);
  assert.match(email.html!, /<body><p[^>]*>Advisory ID: <strong>SECURITY-12345/);
  assert.equal(advisoryEmail(advisory).html, undefined);
});
test('advisory emails retain the original identifier on resends and do not duplicate template identifiers', () => {
  const html = '<p>Advisory SECURITY-12345</p>';
  assert.equal(advisoryEmail(advisory, html).html, html);
  assert.deepEqual(advisoryEmail(advisory, html), advisoryEmail(advisory, html));
});
test('automatically inserted advisory identifiers are escaped in HTML', () => {
  const email = advisoryEmail({ ...advisory, id: '<img src=x onerror=alert(1)>' }, '<p>Notice</p>');
  assert.ok(!email.html!.includes('<img'));
  assert.match(email.html!, /&lt;img/);
});
