import { describe, expect, it } from 'vitest';
import { CORPUS } from '../corpus';
import { ALL_METHODS, PRESETS, decodedQuery, evaluate, evaluateAll, presetById, score } from '../policy';
import type { Policy, RequestShape } from '../types';

const byId = (id: string): RequestShape => {
  const r = CORPUS.find((c) => c.id === id);
  if (!r) throw new Error(`no corpus entry ${id}`);
  return r;
};

const verdictOf = (id: string, policy: Policy) => evaluate(byId(id), policy).verdict;

describe('decodedQuery', () => {
  it('percent-decodes the query string so encoded payloads are visible', () => {
    expect(decodedQuery('https://a.example/graphql?query=mutation%7Bx%7D')).toContain('mutation{x}');
  });

  it('survives a malformed percent escape', () => {
    expect(decodedQuery('https://a.example/?x=%E0%A4')).toContain('x=');
  });

  it('returns empty for an unparseable URL', () => {
    expect(decodedQuery('::::')).toBe('');
  });
});

describe('verb-only policy — the DseWiki shape', () => {
  const p = presetById('verb-only');

  it('lets a wiki edit through because it travels on a GET', () => {
    const d = evaluate(byId('mediawiki-get-edit'), p);
    expect(d.allowed).toBe(true);
    expect(d.verdict).toBe('breach');
    expect(d.firedRules).toHaveLength(0);
  });

  it.each([
    'method-override-param',
    'method-override-header',
    'graphql-mutation-over-get',
    'webhook-get-trigger',
    'one-click-confirm',
    'head-counter',
    'options-recon',
    'dns-label-exfil',
    'querystring-exfil-allowlisted',
  ])('is fooled by %s', (id) => {
    expect(verdictOf(id, p)).toBe('breach');
  });

  it('blocks a harmless search because it is a POST', () => {
    const d = evaluate(byId('search-over-post'), p);
    expect(d.verdict).toBe('over-block');
    expect(d.firedRules.map((f) => f.rule)).toEqual(['method-allowlist']);
  });

  it('allows the one request the policy exists to permit', () => {
    expect(verdictOf('docs-read', p)).toBe('correct-allow');
  });

  it('scores 11 breaches against 1 correct allow', () => {
    expect(score(evaluateAll(CORPUS, p))).toEqual({
      breach: 11,
      overBlock: 1,
      correctAllow: 1,
      correctBlock: 0,
      dangerousReadsAllowed: 1,
    });
  });
});

describe('destination allowlist', () => {
  const p = presetById('verb-domain');

  it('stops the wiki edit — by destination, not by understanding it', () => {
    const d = evaluate(byId('mediawiki-get-edit'), p);
    expect(d.allowed).toBe(false);
    expect(d.firedRules.map((f) => f.rule)).toEqual(['domain-allowlist']);
  });

  it('still leaks through an allowlisted telemetry host', () => {
    expect(verdictOf('querystring-exfil-allowlisted', p)).toBe('breach');
  });

  it('cuts breaches from 11 to 3', () => {
    const s = score(evaluateAll(CORPUS, p));
    expect(s.breach).toBe(3);
    expect(s.correctBlock).toBe(8);
    expect(s.overBlock).toBe(1);
    expect(s.correctAllow).toBe(1);
  });
});

describe('hardened verb policy — patching the known tricks', () => {
  const p = presetById('verb-hardened');

  it.each([
    ['mediawiki-get-edit', 'write-intent-params'],
    ['method-override-param', 'method-override'],
    ['method-override-header', 'method-override'],
    ['graphql-mutation-over-get', 'write-intent-params'],
    ['dns-label-exfil', 'dns-label-entropy'],
    ['imds-credentials', 'private-destination'],
  ])('closes %s via %s', (id, rule) => {
    const d = evaluate(byId(id), p);
    expect(d.allowed).toBe(false);
    expect(d.firedRules.map((f) => f.rule)).toContain(rule);
  });

  it.each(['webhook-get-trigger', 'one-click-confirm', 'head-counter', 'options-recon'])(
    'still cannot see %s, because nothing about it looks like a write',
    (id) => {
      expect(verdictOf(id, p)).toBe('breach');
    },
  );

  it('leaves 5 breaches and still over-blocks the POST search', () => {
    const s = score(evaluateAll(CORPUS, p));
    expect(s.breach).toBe(5);
    expect(s.overBlock).toBe(1);
  });

  it('is beaten by the plain destination allowlist on breach count', () => {
    const hardened = score(evaluateAll(CORPUS, presetById('verb-hardened'))).breach;
    const allowlisted = score(evaluateAll(CORPUS, presetById('verb-domain'))).breach;
    expect(allowlisted).toBeLessThan(hardened);
  });
});

describe('effect-based gate', () => {
  const p = presetById('effect-based');

  it('reaches zero breaches and zero over-blocks', () => {
    expect(score(evaluateAll(CORPUS, p))).toEqual({
      breach: 0,
      overBlock: 0,
      correctAllow: 2,
      correctBlock: 11,
      dangerousReadsAllowed: 0,
    });
  });

  it('restores the POST search the verb policy was blocking', () => {
    expect(verdictOf('search-over-post', p)).toBe('correct-allow');
  });

  it('blocks every non-read on the declared effect alone', () => {
    for (const r of CORPUS.filter((c) => c.effect !== 'read')) {
      expect(evaluate(r, p).firedRules.map((f) => f.rule)).toContain('effect-gate');
    }
  });

  it('does NOT catch the metadata credential read — it is a genuine read', () => {
    const effectOnly: Policy = {
      ...presetById('effect-based'),
      blockPrivateDestinations: false,
      blockHighEntropyHostLabels: false,
    };
    const d = evaluate(byId('imds-credentials'), effectOnly);
    expect(d.allowed).toBe(true);
    expect(d.verdict).toBe('breach');
    expect(score(evaluateAll(CORPUS, effectOnly)).dangerousReadsAllowed).toBe(1);
  });
});

describe('engine invariants', () => {
  it('records every rule that fires, not just the first', () => {
    const strict: Policy = {
      ...presetById('verb-hardened'),
      domainAllowlist: ['docs.example.com'],
    };
    const d = evaluate(byId('mediawiki-get-edit'), strict);
    expect(d.firedRules.map((f) => f.rule).sort()).toEqual(['domain-allowlist', 'write-intent-params']);
  });

  it('allows only when no rule fires', () => {
    for (const preset of PRESETS) {
      for (const d of evaluateAll(CORPUS, preset)) {
        expect(d.allowed).toBe(d.firedRules.length === 0);
      }
    }
  });

  it('scores every request exactly once', () => {
    for (const preset of PRESETS) {
      const s = score(evaluateAll(CORPUS, preset));
      expect(s.breach + s.overBlock + s.correctAllow + s.correctBlock).toBe(CORPUS.length);
    }
  });

  it('is deterministic', () => {
    for (const preset of PRESETS) {
      expect(evaluateAll(CORPUS, preset)).toEqual(evaluateAll(CORPUS, preset));
    }
  });

  it('is case-insensitive about the declared verb', () => {
    const p = presetById('verb-only');
    const lower: RequestShape = { ...byId('docs-read'), method: 'get' };
    expect(evaluate(lower, p).allowed).toBe(true);
  });

  it('presetById returns an isolated copy', () => {
    const a = presetById('verb-domain');
    a.domainAllowlist.push('attacker.example');
    expect(presetById('verb-domain').domainAllowlist).not.toContain('attacker.example');
  });

  it('rejects an unknown preset id', () => {
    expect(() => presetById('nope')).toThrow(/unknown preset/);
  });

  it('every preset only allows verbs from the known set', () => {
    for (const p of PRESETS) {
      for (const m of p.allowedMethods) expect(ALL_METHODS).toContain(m as (typeof ALL_METHODS)[number]);
    }
  });
});
