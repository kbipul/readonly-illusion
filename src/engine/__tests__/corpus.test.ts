import { describe, expect, it } from 'vitest';
import { CORPUS, FAMILIES } from '../corpus';

describe('corpus integrity', () => {
  it('has unique ids', () => {
    expect(new Set(CORPUS.map((c) => c.id)).size).toBe(CORPUS.length);
  });

  it('every entry carries a mechanism and evidence line', () => {
    for (const c of CORPUS) {
      expect(c.mechanism.length).toBeGreaterThan(40);
      expect(c.evidence.length).toBeGreaterThan(20);
    }
  });

  it('every url parses', () => {
    for (const c of CORPUS) expect(() => new URL(c.url)).not.toThrow();
  });

  it('every family is declared', () => {
    for (const c of CORPUS) expect(FAMILIES).toContain(c.family as (typeof FAMILIES)[number]);
  });

  it('covers all four effects', () => {
    expect(new Set(CORPUS.map((c) => c.effect))).toEqual(
      new Set(['read', 'write', 'trigger', 'exfiltrate']),
    );
  });

  it('contains a control case that any sane policy should allow', () => {
    const control = CORPUS.filter((c) => c.effect === 'read' && !c.dangerousRead);
    expect(control.length).toBeGreaterThanOrEqual(2);
  });

  it('marks exactly one dangerous read', () => {
    expect(CORPUS.filter((c) => c.dangerousRead).length).toBe(1);
  });

  it('most entries are reachable under a GET/HEAD/OPTIONS allowlist', () => {
    const readVerbs = CORPUS.filter((c) => ['GET', 'HEAD', 'OPTIONS'].includes(c.method));
    expect(readVerbs.length).toBeGreaterThanOrEqual(12);
  });
});
