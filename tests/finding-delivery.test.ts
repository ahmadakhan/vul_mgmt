import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isFindingDelivery } from '../src/utils/findingDelivery.ts';

test('only finding advisories enter the follow-up action queue', () => {
  assert.equal(isFindingDelivery('ADV-1234'), true);
  assert.equal(isFindingDelivery('CUSTOM-PREFIX-9'), true);
  assert.equal(isFindingDelivery('TEST'), false);
  assert.equal(isFindingDelivery('NEWS:item-1'), false);
  assert.equal(isFindingDelivery('ZERODAY:2026-11-03'), false);
  assert.equal(isFindingDelivery('UNVERIFIABLE:a,b'), false);
  assert.equal(isFindingDelivery('ADV-DAILY_20261103'), false);
  assert.equal(isFindingDelivery('ADV-DAILY-PREVIEW'), false);
  assert.equal(isFindingDelivery(undefined), false);
  assert.equal(isFindingDelivery(''), false);
});
