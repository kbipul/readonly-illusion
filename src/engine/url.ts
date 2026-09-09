/**
 * Host analysis helpers.
 *
 * Deliberately dependency-free and deterministic: everything here runs in the
 * browser with no network access, so the same input always produces the same
 * verdict.
 */

/** Lowercase, strip the root-zone trailing dot, drop any port. */
export function normalizeHostname(host: string): string {
  let h = host.trim().toLowerCase();
  if (h.startsWith('[') && h.includes(']')) return h.slice(0, h.indexOf(']') + 1);
  const colon = h.lastIndexOf(':');
  if (colon > -1 && /^\d+$/.test(h.slice(colon + 1))) h = h.slice(0, colon);
  while (h.endsWith('.')) h = h.slice(0, -1);
  return h;
}

export function hostnameOf(url: string): string {
  try {
    return normalizeHostname(new URL(url).hostname);
  } catch {
    return '';
  }
}

/**
 * Expand the integer and hex forms of an IPv4 address into dotted quad.
 * `http://2852039166/` is a real and frequently-used way to reach
 * 169.254.169.254 past a naive string check.
 */
export function canonicalizeIpv4(host: string): string {
  const h = normalizeHostname(host);
  let n: number | null = null;
  if (/^\d+$/.test(h)) {
    const v = Number(h);
    if (Number.isSafeInteger(v) && v >= 0 && v <= 0xffffffff) n = v;
  } else if (/^0x[0-9a-f]+$/.test(h)) {
    const v = Number.parseInt(h.slice(2), 16);
    if (Number.isSafeInteger(v) && v >= 0 && v <= 0xffffffff) n = v;
  }
  if (n === null) return h;
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

const PRIVATE_SUFFIXES = ['.internal', '.local', '.localdomain'];
const PRIVATE_NAMES = ['localhost', 'metadata.google.internal'];

/** Loopback, RFC1918, link-local (incl. the cloud metadata address) and CGNAT. */
export function isPrivateDestination(host: string): boolean {
  const h = canonicalizeIpv4(host);
  if (!h) return false;
  if (PRIVATE_NAMES.includes(h)) return true;
  if (PRIVATE_SUFFIXES.some((s) => h.endsWith(s))) return true;
  if (h === '[::1]' || h === '::1') return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 127 || a === 0) return true;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

/**
 * Does `host` match an allowlist pattern?
 * `example.com` matches only that host. `*.example.com` matches any subdomain
 * of it. Crucially, neither matches `example.com.attacker.net` — suffix
 * matching without the dot boundary is how allowlists get walked past.
 */
export function hostMatchesPattern(host: string, pattern: string): boolean {
  const h = normalizeHostname(host);
  const p = normalizeHostname(pattern);
  if (!h || !p) return false;
  if (p.startsWith('*.')) {
    const base = p.slice(2);
    return h === base || h.endsWith('.' + base);
  }
  return h === p;
}

export function hostAllowed(host: string, allowlist: string[]): boolean {
  if (allowlist.length === 0) return true;
  return allowlist.some((p) => hostMatchesPattern(host, p));
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let e = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

export const ENTROPY_MIN_LENGTH = 24;
export const ENTROPY_MIN_BITS = 4.0;

/**
 * Flag hostnames whose leftmost labels look like encoded payload rather than
 * names. Heuristic, and it has a real false-positive mode: content-addressed
 * CDN hosts and some UUID-per-tenant schemes look the same from outside.
 * Returns the offending label, or null.
 */
export function highEntropyLabel(host: string): string | null {
  const h = normalizeHostname(host);
  for (const label of h.split('.')) {
    if (label.length < ENTROPY_MIN_LENGTH) continue;
    if (shannonEntropy(label) >= ENTROPY_MIN_BITS) return label;
  }
  return null;
}
