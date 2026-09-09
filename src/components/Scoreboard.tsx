import type { Scoreboard as S } from '../engine/types';

const CARDS: { key: keyof S; label: string; sub: string; tone: string }[] = [
  { key: 'breach', label: 'Breaches', sub: 'allowed, but not a safe read', tone: 'bad' },
  { key: 'overBlock', label: 'Over-blocks', sub: 'blocked, but harmless', tone: 'warn' },
  { key: 'correctAllow', label: 'Correct allows', sub: 'reads that got through', tone: 'good' },
  { key: 'correctBlock', label: 'Correct blocks', sub: 'stopped, and rightly', tone: 'good' },
];

export function Scoreboard({ score, total }: { score: S; total: number }) {
  return (
    <section className="scoreboard" aria-label="Policy outcome">
      {CARDS.map((c) => (
        <div key={c.key} className={`card card--${c.tone} ${score[c.key] === 0 ? 'card--zero' : ''}`}>
          <div className="card__n">{score[c.key]}</div>
          <div className="card__label">{c.label}</div>
          <div className="card__sub">{c.sub}</div>
        </div>
      ))}
      <div className="card card--meta">
        <div className="card__n">{total}</div>
        <div className="card__label">Requests</div>
        <div className="card__sub">documented mechanisms</div>
      </div>
    </section>
  );
}
