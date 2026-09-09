import { ALL_METHODS } from '../engine/policy';
import type { Policy } from '../engine/types';

interface Props {
  policy: Policy;
  onChange: (p: Policy) => void;
}

const TOGGLES: { key: keyof Policy; label: string; hint: string }[] = [
  {
    key: 'blockMethodOverride',
    label: 'Block verb overrides',
    hint: 'Reject _method= parameters and X-HTTP-Method-Override headers.',
  },
  {
    key: 'blockWriteIntentParams',
    label: 'Block write-intent query params',
    hint: 'Reject action=edit, do=save, op=delete and GraphQL mutations sent over GET.',
  },
  {
    key: 'blockPrivateDestinations',
    label: 'Block private + link-local destinations',
    hint: 'Loopback, RFC1918, 169.254.0.0/16 and the cloud metadata address — including its decimal form.',
  },
  {
    key: 'blockHighEntropyHostLabels',
    label: 'Block high-entropy hostname labels',
    hint: 'Heuristic for DNS tunnelling. Will occasionally flag content-addressed CDN hosts.',
  },
  {
    key: 'effectGate',
    label: 'Effect-based gate',
    hint: 'Ignore the verb. Require each request to declare what it does, and allow only reads.',
  },
];

export function PolicyPanel({ policy, onChange }: Props) {
  const toggleMethod = (m: string) => {
    const has = policy.allowedMethods.includes(m);
    onChange({
      ...policy,
      allowedMethods: has ? policy.allowedMethods.filter((x) => x !== m) : [...policy.allowedMethods, m],
    });
  };

  return (
    <aside className="panel">
      <h2 className="panel__h">Policy</h2>

      <div className="field">
        <div className="field__label">Allowed verbs</div>
        <div className="chips">
          {ALL_METHODS.map((m) => (
            <button
              key={m}
              type="button"
              className={`chip ${policy.allowedMethods.includes(m) ? 'chip--on' : ''}`}
              aria-pressed={policy.allowedMethods.includes(m)}
              onClick={() => toggleMethod(m)}
            >
              {m}
            </button>
          ))}
        </div>
        <p className="field__hint">
          The filter almost every agent harness actually ships. It is a statement about the verb on
          the wire, not about what happens at the other end.
        </p>
      </div>

      <div className="field">
        <label className="field__label" htmlFor="allowlist">
          Destination allowlist
        </label>
        <textarea
          id="allowlist"
          className="ta"
          rows={4}
          spellCheck={false}
          placeholder={'one host per line\ndocs.example.com\n*.corp.example.com'}
          value={policy.domainAllowlist.join('\n')}
          onChange={(e) =>
            onChange({
              ...policy,
              domainAllowlist: e.target.value
                .split('\n')
                .map((s) => s.trim())
                .filter(Boolean),
            })
          }
        />
        <p className="field__hint">Empty means any host. Wildcards match on label boundaries only.</p>
      </div>

      {TOGGLES.map((t) => (
        <label key={String(t.key)} className="toggle">
          <input
            type="checkbox"
            checked={Boolean(policy[t.key])}
            onChange={(e) => onChange({ ...policy, [t.key]: e.target.checked })}
          />
          <span>
            <span className="toggle__label">{t.label}</span>
            <span className="toggle__hint">{t.hint}</span>
          </span>
        </label>
      ))}
    </aside>
  );
}
