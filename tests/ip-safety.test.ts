import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPublicAddress } from '../src/utils/ipSafety.ts';
import { publicAddress } from '../server/network.ts';
import { validateSsrfSafety } from '../src/engine/pipelineEngine.ts';

test('public unicast addresses are permitted', () => {
  for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
    assert.equal(isPublicAddress(address), true, address);
    assert.equal(publicAddress(address), true, address);
  }
});

test('private, loopback, link-local, and carrier-grade NAT are rejected', () => {
  for (const address of [
    '10.0.0.1',
    '172.16.5.4',
    '192.168.1.1',
    '127.0.0.1',
    '169.254.169.254',
    '100.64.0.1',
    '0.0.0.0',
    '224.0.0.1',
    '::1',
    'fe80::1',
    'fd00::1',
  ]) {
    assert.equal(isPublicAddress(address), false, address);
  }
});

test('IPv4-mapped IPv6 is normalised before the public-address check', () => {
  assert.equal(isPublicAddress('::ffff:127.0.0.1'), false);
  assert.equal(isPublicAddress('::ffff:10.0.0.1'), false);
  assert.equal(isPublicAddress('::ffff:8.8.8.8'), true);
});

test('NAT64, 6to4, and Teredo transition prefixes are rejected', () => {
  for (const address of [
    '64:ff9b::a00:1',
    '64:ff9b:1::a00:1',
    '2002:0a00:0001::',
    '2001::1',
    '2001:2::1',
    '2001:10::1',
  ]) {
    assert.equal(isPublicAddress(address), false, address);
  }
});

test('save-time URL screening rejects transition-prefix literals', () => {
  for (const url of [
    'https://[64:ff9b::a00:1]/',
    'https://[2002:0a00:0001::]/',
    'https://[2001::1]/',
  ]) {
    assert.equal(validateSsrfSafety(url).safe, false, url);
  }
  assert.equal(validateSsrfSafety('https://[2606:4700:4700::1111]/').safe, true);
});
