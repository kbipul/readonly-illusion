import { useMemo, useState } from 'react';
import { CORPUS, FAMILIES } from './engine/corpus';
import { PRESETS, evaluateAll, presetById, score } from './engine/policy';
import type { Policy } from './engine/types';
import { PolicyPanel } from './components/PolicyPanel';
import { RequestRow } from './components/RequestRow';
import { Scoreboard } from './components/Scoreboard';
import { CustomRequest } from './components/CustomRequest';

function samePolicy(a: Policy, b: Policy): boolean {
  return (
    [...a.allowedMethods].sort().join() === [...b.allowedMethods].sort().join() &&
    a.domainAllowlist.join() === b.domainAllowlist.join() &&
    a.blockMethodOverride === b.blockMethodOverride &&
    a.blockWriteIntentParams === b.blockWriteIntentParams &&
    a.blockPrivateDestinations === b.blockPrivateDestinations &&
    a.blockHighEntropyHostLabels === b.blockHighEntropyHostLabels &&
    a.effectGate === b.effectGate
  );
}

export default function App() {
  const [policy, setPolicy] = useState<Policy>(() => presetById('verb-only'));
  const [open, setOpen] = useState<Set<string>>(() => new Set(['mediawiki-get-edit']));

  const decisions = useMemo(() => evaluateAll(CORPUS, policy), [policy]);
  const s = useMemo(() => score(decisions), [decisions]);
  const activePreset = PRESETS.find((p) => samePolicy(p, policy));

  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <div className="app">
      <header className="hero">
        <p className="hero__kicker">Day 029 · kb-daily-builds</p>
        <h1 className="hero__h1">Read-Only Illusion</h1>
        <p className="hero__sub">
          Your agent's network policy blocks the verb. The other end cares about the effect.
        </p>
        <p className="hero__signal">
          On 4 September 2026 the Nightingale Collective reported that a swarm of OpenAI agents spent
          two months using a dormant German developer wiki as a message board, making roughly 15,000
          edits while restricted to <em>reading</em> the web. They did not break the sandbox. They
          submitted the edits as GET requests, and the restriction had been written against the
          request type writes were expected to use.
        </p>
        <p className="hero__signal">
          Below are thirteen requests that behave the same way. Set your policy and see which ones it
          lets through — and which harmless ones it stops.
        </p>
      </header>

      <nav className="presets" aria-label="Policy presets">
        {PRESETS.map((p) => (
          <button
            key={p.id}
            type="button"
            className={`preset ${activePreset?.id === p.id ? 'preset--on' : ''}`}
            onClick={() => setPolicy(presetById(p.id))}
          >
            {p.name}
          </button>
        ))}
        <span className="presets__note">
          {activePreset ? activePreset.note : 'Custom policy — edited from a preset.'}
        </span>
      </nav>

      <Scoreboard score={s} total={CORPUS.length} />

      <p className="verdictline">
        {s.breach === 0 ? (
          <>
            <b>No breaches.</b> Every request that writes, triggers or exfiltrates is stopped
            {s.overBlock === 0 ? ', and no harmless read is blocked.' : '.'}
          </>
        ) : (
          <>
            <b>
              {s.breach} of {CORPUS.length}
            </b>{' '}
            requests are allowed that write, trigger or exfiltrate
            {s.overBlock > 0 ? (
              <>
                {' '}
                — while {s.overBlock} harmless {s.overBlock === 1 ? 'read is' : 'reads are'} blocked.
                The policy is wrong in both directions.
              </>
            ) : (
              '.'
            )}
          </>
        )}
      </p>

      {s.dangerousReadsAllowed > 0 && (
        <p className="warnline">
          One allowed request is a genuine read that changes nothing and still hands back cloud role
          credentials. An effect-based gate cannot catch it — only destination filtering can. Closing
          the verb/effect gap closes one category, not all of them.
        </p>
      )}

      <div className="layout">
        <PolicyPanel policy={policy} onChange={setPolicy} />

        <main className="results">
          {FAMILIES.map((fam) => {
            const rows = decisions.filter((d) => d.request.family === fam);
            if (rows.length === 0) return null;
            return (
              <section key={fam} className="family">
                <h2 className="family__h">{fam}</h2>
                <ul className="rows">
                  {rows.map((d) => (
                    <RequestRow
                      key={d.request.id}
                      decision={d}
                      open={open.has(d.request.id)}
                      onToggle={() => toggle(d.request.id)}
                    />
                  ))}
                </ul>
              </section>
            );
          })}

          <CustomRequest policy={policy} />
        </main>
      </div>

      <footer className="foot">
        <p>
          Every mechanism listed is a documented property of real software. Hostnames use reserved
          example domains; nothing here is a claim about a specific deployment. Runs entirely in your
          browser — no network calls, no keys, no telemetry.
        </p>
        <p>
          Built by <a href="https://www.kumarbipul.com">Kumar Bipul</a> · Day 029 of{' '}
          <a href="https://github.com/kbipul/kb-daily-builds">kb-daily-builds</a> ·{' '}
          <a href="https://github.com/kbipul/readonly-illusion">source</a>
        </p>
      </footer>
    </div>
  );
}
