import { useState } from 'react';
import { evaluate } from '../engine/policy';
import type { Effect, Policy, RequestShape } from '../engine/types';

const EFFECTS: Effect[] = ['read', 'write', 'trigger', 'exfiltrate'];

export function CustomRequest({ policy }: { policy: Policy }) {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('https://wiki.internal.example/index.php?title=Ops&action=edit&text=hi');
  const [effect, setEffect] = useState<Effect>('write');

  let result: ReturnType<typeof evaluate> | null = null;
  let error = '';
  try {
    new URL(url);
    const req: RequestShape = {
      id: 'custom',
      label: 'Your request',
      method,
      url,
      effect,
      mechanism: '',
      evidence: '',
      severity: 'medium',
      family: 'Genuine reads',
    };
    result = evaluate(req, policy);
  } catch {
    error = 'That URL will not parse — include the scheme, e.g. https://';
  }

  return (
    <section className="custom">
      <h2 className="section__h">Try your own</h2>
      <p className="section__p">
        Describe a request your agent makes and what it really does at the other end. The policy on
        the left decides.
      </p>
      <div className="custom__form">
        <select value={method} onChange={(e) => setMethod(e.target.value)} aria-label="Method">
          {['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => (
            <option key={m}>{m}</option>
          ))}
        </select>
        <input
          className="custom__url"
          value={url}
          spellCheck={false}
          onChange={(e) => setUrl(e.target.value)}
          aria-label="URL"
        />
        <select
          value={effect}
          onChange={(e) => setEffect(e.target.value as Effect)}
          aria-label="Real effect"
        >
          {EFFECTS.map((x) => (
            <option key={x} value={x}>
              really {x}s
            </option>
          ))}
        </select>
      </div>
      {error ? (
        <p className="custom__err" role="status">{error}</p>
      ) : (
        result && (
          <div className={`custom__out custom__out--${result.verdict}`} role="status">
            <b>{result.allowed ? 'Allowed' : 'Blocked'}</b>
            {result.firedRules.length === 0
              ? ' — no rule fired.'
              : ` — ${result.firedRules.map((f) => f.rule).join(', ')}.`}
            {result.verdict === 'breach' && ' This is a breach: the policy let a non-read through.'}
            {result.verdict === 'over-block' && ' This is an over-block: a harmless read was stopped.'}
          </div>
        )
      )}
    </section>
  );
}
