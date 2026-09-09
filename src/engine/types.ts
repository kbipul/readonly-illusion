/**
 * Core model.
 *
 * The whole point of this tool is the gap between two different things that
 * network policies routinely conflate:
 *
 *   - the DECLARED METHOD of a request (what verb the harness sees), and
 *   - the REAL EFFECT of the request (what happens on the other end).
 *
 * A policy expressed as "allow GET, HEAD, OPTIONS" is a statement about the
 * first. Every entry in the corpus is a case where the second disagrees.
 */

/** What the request actually does at the destination. */
export type Effect =
  /** Returns data. Changes nothing. */
  | 'read'
  /** Creates, updates or deletes state at the destination. */
  | 'write'
  /** Fires an action with consequences elsewhere (webhook, job, counter). */
  | 'trigger'
  /** Carries data out of the trust boundary. */
  | 'exfiltrate';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface RequestShape {
  id: string;
  label: string;
  /** The verb the agent harness sees and filters on. */
  method: string;
  url: string;
  headers?: Record<string, string>;
  /** What actually happens at the destination. */
  effect: Effect;
  /** One line: how a "read-only" request achieves that effect. */
  mechanism: string;
  /** Where this is documented or observed in the wild. */
  evidence: string;
  severity: Severity;
  family: string;
  /**
   * True for requests that are genuinely reads — no state changes — but that
   * hand back something that should never have left the destination. An
   * effect-based gate allows these by construction. Naming them is the honest
   * part: switching from verbs to effects closes one category, not all of them.
   */
  dangerousRead?: boolean;
}

export interface Policy {
  id: string;
  name: string;
  note: string;
  /** Uppercase verbs the harness permits. */
  allowedMethods: string[];
  /** Host patterns. Empty means any host. `*.example.com` matches subdomains. */
  domainAllowlist: string[];
  /** Reject `_method=` params and `X-HTTP-Method-Override` headers. */
  blockMethodOverride: boolean;
  /** Reject GETs whose query string carries a documented mutation intent. */
  blockWriteIntentParams: boolean;
  /** Reject loopback, private, link-local and cloud-metadata destinations. */
  blockPrivateDestinations: boolean;
  /** Reject hostnames carrying a long high-entropy label (DNS exfiltration). */
  blockHighEntropyHostLabels: boolean;
  /** The fix: judge by declared effect, not by verb. */
  effectGate: boolean;
}

export interface FiredRule {
  rule: string;
  detail: string;
}

export type Verdict =
  /** Allowed, and it really was a read. The policy did its job. */
  | 'correct-allow'
  /** Allowed, but it writes, triggers or exfiltrates. The policy was fooled. */
  | 'breach'
  /** Blocked, but it was only a read. The agent lost a capability for nothing. */
  | 'over-block'
  /** Blocked, and it needed blocking. */
  | 'correct-block';

export interface Decision {
  request: RequestShape;
  allowed: boolean;
  firedRules: FiredRule[];
  verdict: Verdict;
}

export interface Scoreboard {
  breach: number;
  overBlock: number;
  correctAllow: number;
  correctBlock: number;
  /** Reads that are allowed by every gate here yet still leak a secret. */
  dangerousReadsAllowed: number;
}
