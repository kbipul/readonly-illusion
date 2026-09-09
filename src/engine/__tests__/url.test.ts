import { describe, expect, it } from 'vitest';
import {
  canonicalizeIpv4,
  highEntropyLabel,
  hostAllowed,
  hostMatchesPattern,
  hostnameOf,
  isPrivateDestination,
  normalizeHostname,
  shannonEntropy,
} from '../url';

describe('normalizeHostname', () => {
  it('lowercases, strips the root dot and drops the port', () => {
    expect(normalizeHostname('API.Corp.Example.COM.')).toBe('api.corp.example.com');
    expect(normalizeHostname('api.corp.example.com:8443')).toBe('api.corp.example.com');
  });

  it('leaves a bracketed IPv6 literal intact', () => {
    expect(normalizeHostname('[::1]:8080')).toBe('[::1]');
  });
});

describe('hostnameOf', () => {
  it('extracts the host and ignores the port', () => {
    expect(hostnameOf('https://api.corp.example.com:8443/x')).toBe('api.corp.example.com');
  });

  it('returns an empty string for an unparseable URL', () => {
    expect(hostnameOf('not a url')).toBe('');
  });
});

describe('canonicalizeIpv4', () => {
  it('expands the decimal form of the metadata address', () => {
    expect(canonicalizeIpv4('2852039166')).toBe('169.254.169.254');
  });

  it('expands the hex form', () => {
    expect(canonicalizeIpv4('0x7f000001')).toBe('127.0.0.1');
  });

  it('leaves ordinary hostnames alone', () => {
    expect(canonicalizeIpv4('docs.example.com')).toBe('docs.example.com');
  });

  it('ignores integers outside the IPv4 range', () => {
    expect(canonicalizeIpv4('99999999999')).toBe('99999999999');
  });
});

describe('isPrivateDestination', () => {
  it.each([
    '127.0.0.1',
    '10.4.2.9',
    '172.16.0.5',
    '172.31.255.254',
    '192.168.1.1',
    '169.254.169.254',
    '100.72.0.1',
    'localhost',
    'metadata.google.internal',
    'vault.svc.internal',
  ])('flags %s', (h) => {
    expect(isPrivateDestination(h)).toBe(true);
  });

  it.each(['docs.example.com', '8.8.8.8', '172.32.0.1', '192.169.1.1', '11.0.0.1'])(
    'does not flag %s',
    (h) => {
      expect(isPrivateDestination(h)).toBe(false);
    },
  );

  it('sees through the decimal-encoded metadata address', () => {
    expect(isPrivateDestination('2852039166')).toBe(true);
  });
});

describe('hostMatchesPattern', () => {
  it('matches an exact host', () => {
    expect(hostMatchesPattern('docs.example.com', 'docs.example.com')).toBe(true);
    expect(hostMatchesPattern('other.example.com', 'docs.example.com')).toBe(false);
  });

  it('matches subdomains and the apex under a wildcard', () => {
    expect(hostMatchesPattern('api.corp.example.com', '*.corp.example.com')).toBe(true);
    expect(hostMatchesPattern('corp.example.com', '*.corp.example.com')).toBe(true);
  });

  it('refuses a suffix that is not on a label boundary', () => {
    // The classic allowlist walk-past: endsWith() alone would accept this.
    expect(hostMatchesPattern('corp.example.com.attacker.net', '*.corp.example.com')).toBe(false);
    expect(hostMatchesPattern('evilcorp.example.com', 'corp.example.com')).toBe(false);
    expect(hostMatchesPattern('notdocs.example.com', 'docs.example.com')).toBe(false);
  });

  it('is case and trailing-dot insensitive', () => {
    expect(hostMatchesPattern('API.Corp.Example.com.', '*.corp.example.com')).toBe(true);
  });
});

describe('hostAllowed', () => {
  it('permits anything when the allowlist is empty', () => {
    expect(hostAllowed('anywhere.example', [])).toBe(true);
  });

  it('requires a match when the allowlist is populated', () => {
    expect(hostAllowed('docs.example.com', ['docs.example.com'])).toBe(true);
    expect(hostAllowed('evil.example', ['docs.example.com'])).toBe(false);
  });
});

describe('shannonEntropy', () => {
  it('is zero for a single repeated character', () => {
    expect(shannonEntropy('aaaaaaaa')).toBe(0);
  });

  it('is one bit for a balanced two-symbol string', () => {
    expect(shannonEntropy('abab')).toBeCloseTo(1, 10);
  });

  it('is zero for the empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });
});

describe('highEntropyLabel', () => {
  it('flags a base32 payload label', () => {
    const host = 'mfrggzdfmztwq2lknnwg23tpobyc4ylvo53xo.collect.example.net';
    expect(highEntropyLabel(host)).toBe('mfrggzdfmztwq2lknnwg23tpobyc4ylvo53xo');
  });

  it('does not flag ordinary long service names', () => {
    expect(highEntropyLabel('api-gateway-production-eu-west.example.com')).toBeNull();
    expect(highEntropyLabel('telemetry.vendor-analytics.com')).toBeNull();
    expect(highEntropyLabel('docs.example.com')).toBeNull();
  });

  it('does not flag a long but low-entropy label', () => {
    expect(highEntropyLabel('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com')).toBeNull();
  });
});
