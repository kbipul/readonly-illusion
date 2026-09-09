import type { Decision } from '../engine/types';

const VERDICT_LABEL: Record<Decision['verdict'], string> = {
  breach: 'Breach',
  'over-block': 'Over-block',
  'correct-allow': 'Allowed',
  'correct-block': 'Blocked',
};

const EFFECT_LABEL: Record<string, string> = {
  read: 'reads',
  write: 'writes',
  trigger: 'triggers',
  exfiltrate: 'exfiltrates',
};

export function RequestRow({
  decision,
  open,
  onToggle,
}: {
  decision: Decision;
  open: boolean;
  onToggle: () => void;
}) {
  const { request: r, verdict, firedRules } = decision;
  return (
    <li className={`row row--${verdict}`}>
      <button type="button" className="row__head" onClick={onToggle} aria-expanded={open}>
        <span className="row__verdict">{VERDICT_LABEL[verdict]}</span>
        <span className="row__main">
          <span className="row__label">{r.label}</span>
          <span className="row__url">
            <code className="method">{r.method}</code> {r.url}
          </span>
        </span>
        <span className="row__effect" data-effect={r.effect}>
          {EFFECT_LABEL[r.effect]}
          {r.dangerousRead ? ' ⚠' : ''}
        </span>
        <span className="row__chev">{open ? '−' : '+'}</span>
      </button>

      {open && (
        <div className="row__body">
          <p className="row__mech">{r.mechanism}</p>
          {r.headers && (
            <pre className="row__pre">
              {Object.entries(r.headers)
                .map(([k, v]) => `${k}: ${v}`)
                .join('\n')}
            </pre>
          )}
          <div className="row__rules">
            {firedRules.length === 0 ? (
              <span className="rule rule--none">no rule fired — the policy had nothing to say about this</span>
            ) : (
              firedRules.map((f) => (
                <span key={f.rule} className="rule">
                  <b>{f.rule}</b> — {f.detail}
                </span>
              ))
            )}
          </div>
          <p className="row__evidence">
            <span className="row__evidence-k">Where this comes from</span> {r.evidence}
          </p>
        </div>
      )}
    </li>
  );
}
