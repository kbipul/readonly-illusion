// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import App from '../App';
import { CORPUS } from '../engine/corpus';

afterEach(cleanup);

/**
 * The curl smoke test in CI proves the server returns bytes at the Pages path.
 * It cannot prove the app mounts. These do — a blank-screen regression fails
 * here rather than in front of a visitor.
 */
describe('App renders', () => {
  it('mounts and shows the headline', () => {
    render(<App />);
    expect(screen.getByRole('heading', { level: 1, name: 'Read-Only Illusion' })).toBeTruthy();
  });

  it('lists every corpus request', () => {
    render(<App />);
    for (const c of CORPUS) expect(screen.getByText(c.label)).toBeTruthy();
  });

  it('opens on the read-only preset and reports 11 breaches', () => {
    render(<App />);
    const board = screen.getByLabelText('Policy outcome');
    const breaches = within(board).getByText('Breaches').parentElement!;
    expect(within(breaches).getByText('11')).toBeTruthy();
  });

  it('switching to the effect-based gate drops breaches to zero', () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Effect-based gate' }));
    const board = screen.getByLabelText('Policy outcome');
    const breaches = within(board).getByText('Breaches').parentElement!;
    expect(within(breaches).getByText('0')).toBeTruthy();
    expect(screen.getByText(/No breaches\./)).toBeTruthy();
  });

  it('surfaces the dangerous-read caveat under the verb-only policy only', () => {
    const { unmount } = render(<App />);
    expect(screen.getByText(/hands back cloud role\s+credentials/)).toBeTruthy();
    unmount();
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: 'Effect-based gate' }));
    expect(screen.queryByText(/hands back cloud role\s+credentials/)).toBeNull();
  });

  it('expands a row to show why no rule fired', () => {
    render(<App />);
    fireEvent.click(screen.getByText('Automation webhook fired by fetching a URL'));
    expect(screen.getAllByText(/no rule fired/).length).toBeGreaterThan(0);
  });

  it('evaluates a custom request live', () => {
    render(<App />);
    const url = screen.getByLabelText('URL') as HTMLInputElement;
    fireEvent.change(url, { target: { value: 'https://docs.example.com/page' } });
    fireEvent.change(screen.getByLabelText('Real effect'), { target: { value: 'read' } });
    expect(screen.getByRole('status').textContent).toMatch(/^Allowed/);
  });

  it('reports an unparseable custom URL instead of crashing', () => {
    render(<App />);
    fireEvent.change(screen.getByLabelText('URL'), { target: { value: 'nonsense' } });
    expect(screen.getByRole('status').textContent).toMatch(/will not parse/);
  });
});
