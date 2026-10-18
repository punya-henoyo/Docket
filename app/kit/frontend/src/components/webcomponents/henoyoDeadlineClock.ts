// <henoyo-deadline-clock>: regulatory or contractual deadlines measured from one anchor event.

import { kitDayMonth } from './colourScheme';
import {
  HenoyoElement,
  DAY_MS,
  defineElement,
  downloadCsv,
  emit,
  esc,
  finite,
  fmtDateTime,
  glyph,
  ms,
  span,
  type KitStat,
} from './henoyoKit';

export interface HenoyoDeadline {
  id: string;
  label: string;
  due?: string;
  offsetHours?: number;
  metAt?: string;
  extensionUntil?: string;
  basis?: string;
  withoutDelay?: boolean;
}

export interface HenoyoDeadlineAnchor {
  label: string;
  at: string;
}

type DeadlineState = 'met' | 'late' | 'running' | 'missed' | 'nodue';

interface Computed {
  d: HenoyoDeadline;
  due: number | null;
  met: number | null;
  ext: number | null;
  state: DeadlineState;
  text: string;
  delta: string;
}

const HOUR_MS = 3_600_000;
const STATE_LABEL: Record<DeadlineState, string> = {
  met: 'Met',
  late: 'Met late',
  running: 'Running',
  missed: 'Missed',
  nodue: 'No due date',
};
const STATE_GLYPH: Record<DeadlineState, string> = {
  met: 'check',
  late: 'clock',
  running: 'hourglass',
  missed: 'circle-alert',
  nodue: '',
};
const STATE_TONE: Record<DeadlineState, string> = {
  met: 'ok',
  late: 'warn',
  running: 'info',
  missed: 'bad',
  nodue: 'neutral',
};

/** Hours precision under 3 days, the kit's span() wording beyond. */
function dur(diff: number): string {
  const a = Math.abs(diff);
  if (a >= 3 * DAY_MS) return span(a / DAY_MS);
  const minutes = Math.round(a / 60_000);
  if (minutes < 60) return `${minutes}m`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return m === 0 ? `${h}h` : `${h}h ${m}m`;
}

/** The finding: how many are overdue and when the next one falls due. */
export function deadlineFinding(overdue: number, untilNext: number | null): string {
  if (overdue === 0) return 'All on time';
  const next = untilNext === null ? '' : ` · next due in ${span(untilNext / DAY_MS)}`;
  return `${overdue} overdue${next}`;
}

export class HenoyoDeadlineClock extends HenoyoElement {
  private _heading: string | undefined;
  private _subject: string | undefined;
  private _anchor: HenoyoDeadlineAnchor | undefined;
  private _deadlines: HenoyoDeadline[] = [];
  private _now: string | undefined;
  private _exportEnabled: boolean | undefined;

  constructor() {
    super();
    this.root.addEventListener('click', (e) => {
      const target = (e.target as Element | null)?.closest<HTMLElement>('[data-act]');
      if (!target) return;
      const arg = target.dataset.arg ?? '';
      if (target.dataset.act === 'select') emit(this, 'henoyo:deadline-selected', { id: arg });
      else if (target.dataset.act === 'export') this.exportCsv();
    });
  }

  get heading(): string | undefined {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v;
    this.invalidate();
  }
  get subject(): string | undefined {
    return this._subject;
  }
  set subject(v: string | undefined) {
    this._subject = v;
    this.invalidate();
  }
  get anchor(): HenoyoDeadlineAnchor | undefined {
    return this._anchor;
  }
  set anchor(v: HenoyoDeadlineAnchor | undefined) {
    this._anchor = v;
    this.invalidate();
  }
  get deadlines(): HenoyoDeadline[] {
    return this._deadlines;
  }
  set deadlines(v: HenoyoDeadline[]) {
    this._deadlines = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  get now(): string | undefined {
    return this._now;
  }
  set now(v: string | undefined) {
    this._now = v;
    this.invalidate();
  }
  get exportEnabled(): boolean | undefined {
    return this._exportEnabled;
  }
  set exportEnabled(v: boolean | undefined) {
    this._exportEnabled = v;
    this.invalidate();
  }

  private nowMs(): number {
    return ms(this._now) ?? Date.now();
  }

  private compute(anchorAt: number, now: number): Computed[] {
    const anchorLabel = this._anchor?.label ?? 'anchor';
    return this._deadlines
      .filter((d) => d !== null && typeof d === 'object')
      .map((d) => {
        let due: number | null = null;
        let ext: number | null = null;
        if (!d.withoutDelay) {
          due = ms(d.due);
          const offset = finite(d.offsetHours);
          if (due === null && offset !== null) due = anchorAt + offset * HOUR_MS;
          const extAt = ms(d.extensionUntil);
          if (extAt !== null && (due === null || extAt > due)) {
            due = extAt;
            ext = extAt;
          }
        }
        const met = ms(d.metAt);
        const after = met === null ? '' : `Met ${dur(met - anchorAt)} after ${anchorLabel}`;
        let state: DeadlineState;
        let text: string;
        let delta: string;
        if (due === null) {
          state = 'nodue';
          delta = '';
          text = met === null ? `${dur(now - anchorAt)} since ${anchorLabel}` : after;
        } else if (met !== null) {
          state = met <= due ? 'met' : 'late';
          delta = met <= due ? `${dur(due - met)} early` : `${dur(met - due)} late`;
          text = `${after} · ${delta}`;
        } else if (now <= due) {
          state = 'running';
          delta = `${dur(due - now)} left`;
          text = delta;
        } else {
          state = 'missed';
          delta = `Overdue by ${dur(now - due)}`;
          text = delta;
        }
        return { d, due, met, ext, state, text, delta };
      });
  }

  private exportCsv(): void {
    const anchorAt = ms(this._anchor?.at);
    if (anchorAt === null) return;
    const iso = (t: number | null): string => {
      if (t === null) return '';
      const d = new Date(t);
      return Number.isNaN(d.getTime()) ? '' : d.toISOString();
    };
    downloadCsv(
      this,
      'deadlines',
      ['label', 'basis', 'due_utc', 'met_utc', 'state', 'delta'],
      this.compute(anchorAt, this.nowMs()).map((c) => [
        c.d.label,
        c.d.basis ?? '',
        iso(c.due),
        iso(c.met),
        STATE_LABEL[c.state],
        c.delta,
      ]),
    );
  }

  protected styles(): string {
    return `
.lane, .scale { display:grid; grid-template-columns:minmax(120px,1.1fr) 3fr minmax(140px,1.3fr); gap:6px 16px; align-items:center; width:100%; }
.lane { min-height:var(--h-kit-lane, 48px); padding:8px 4px; background:none; border:0; border-top:1px solid var(--k-hairline); text-align:left; cursor:pointer; }
.lane:hover { background:var(--k-surface-2); }
.lbl { min-width:0; font-size:13px; font-weight:600; overflow-wrap:anywhere; }
.lbl .muted { display:block; font-size:11.5px; font-weight:400; }
.track { position:relative; height:26px; }
.bar, .fill, .over { position:absolute; top:8px; height:10px; border-radius:5px; }
.bar { background:var(--k-neutral-soft); }
.fill { background:var(--k-info-soft); }
.over.late { background:var(--k-warn-soft); }
.over.missed { background:var(--k-bad-soft); border:1px dashed var(--k-bad); }
.anch { position:absolute; left:0; top:4px; width:2px; height:18px; background:var(--k-text-2); border-radius:1px; }
.nowl { position:absolute; top:1px; width:2px; height:24px; background:var(--k-text); border-radius:1px; margin-left:-1px; }
.tick { position:absolute; top:3px; width:2px; height:20px; background:var(--k-text-2); margin-left:-1px; }
.dot { position:absolute; top:4px; width:18px; height:18px; margin-left:-9px; border-radius:50%; display:grid; place-items:center; }
.dot.met { background:var(--k-ok); color:var(--k-surface); }
.dot.late { background:var(--k-surface); color:var(--k-warn); border:2px solid var(--k-warn); }
.nd { font-size:12.5px; color:var(--k-text-3); }
.res { display:flex; flex-direction:column; align-items:flex-start; gap:3px; font-size:12.5px; color:var(--k-text-2); }
.pill { gap:4px; }
.pill.ok { background:var(--k-ok-soft); color:var(--k-ok); }
.pill.warn { background:var(--k-warn-soft); color:var(--k-warn); }
.pill.bad { background:var(--k-bad-soft); color:var(--k-bad); }
.pill.info { background:var(--k-info-soft); color:var(--k-info); }
.pill.neutral { background:var(--k-neutral-soft); color:var(--k-neutral); }
.ext { font-size:11.5px; color:var(--k-text-3); }
.scale { margin-top:4px; }
.axis { position:relative; height:34px; border-top:1px solid var(--k-hairline-2); }
.at { position:absolute; top:3px; font-size:11px; color:var(--k-text-3); white-space:nowrap; transform:translateX(-50%); }
.at.first { transform:none; }
.at.last { transform:translateX(-100%); }
.nowt { position:absolute; top:17px; font-size:11px; font-weight:700; color:var(--k-text); transform:translateX(-50%); }
@media (max-width: 560px) { .lane, .scale { grid-template-columns:1fr; } .scale > :first-child { display:none; } }
`;
  }

  private scale(anchorAt: number, end: number, pct: (t: number) => number): string {
    const spanMs = end - anchorAt;
    const days = spanMs / DAY_MS < 4;
    const unit = days ? HOUR_MS : DAY_MS;
    const steps = days ? [1, 2, 3, 4, 6, 12, 24, 48] : [1, 2, 7, 14, 30, 60, 90, 180, 365];
    const total = spanMs / unit;
    const step = steps.find((x) => total / x <= 5) ?? steps[steps.length - 1]!;
    const ticks: number[] = [];
    for (let k = 0; k * step <= total + 1e-9 && ticks.length < 7; k++) ticks.push(k * step);
    return ticks
      .map((k, i) => {
        const t = anchorAt + k * unit;
        const label = days ? (k === 0 ? '0' : `+${k}h`) : kitDayMonth(t);
        const pos = i === 0 ? ' first' : pct(t) > 90 ? ' last' : '';
        return `<span class="at${pos}" style="left:${pct(t)}%">${esc(label)}</span>`;
      })
      .join('');
  }

  protected view(): string {
    const anchorAt = ms(this._anchor?.at);
    const rows = anchorAt === null ? [] : this.compute(anchorAt, this.nowMs());
    if (anchorAt === null || rows.length === 0)
      return this.emptyCard('Deadlines', this._heading ?? 'Deadline clock');
    const now = this.nowMs();
    const count = (s: DeadlineState): number => rows.filter((r) => r.state === s).length;
    const missed = count('missed');
    const late = count('late');
    const running = count('running');
    const met = count('met');
    const end = Math.max(
      anchorAt + HOUR_MS,
      now,
      ...rows.map((r) => r.due ?? 0),
      ...rows.map((r) => r.met ?? 0),
    );
    const pct = (t: number): number =>
      Math.min(100, Math.max(0, ((t - anchorAt) / (end - anchorAt)) * 100));
    const anchorLabel = this._anchor?.label ?? '';
    const sub = [
      this._subject ? esc(this._subject) : '',
      `${esc(anchorLabel)} ${esc(fmtDateTime(anchorAt))}`,
    ]
      .filter(Boolean)
      .join(' · ');

    const lane = (r: Computed): string => {
      const parts: string[] = ['<span class="anch" aria-hidden="true"></span>'];
      if (r.due !== null) {
        parts.push(`<span class="bar" style="left:0;width:${pct(r.due)}%"></span>`);
        if (r.state === 'running')
          parts.push(`<span class="fill" style="left:0;width:${pct(now)}%"></span>`);
        const overEnd = r.met ?? now;
        if ((r.state === 'late' || r.state === 'missed') && overEnd > r.due)
          parts.push(
            `<span class="over ${r.state}" style="left:${pct(r.due)}%;width:${Math.max(0.5, pct(overEnd) - pct(r.due))}%"></span>`,
          );
        parts.push(`<span class="tick" style="left:${pct(r.due)}%" title="Due"></span>`);
      }
      parts.push(`<span class="nowl" style="left:${pct(now)}%"></span>`);
      if (r.met !== null)
        parts.push(
          `<span class="dot ${r.state === 'late' ? 'late' : 'met'}" style="left:${pct(r.met)}%">${glyph(r.state === 'late' ? 'clock' : 'check', 12)}</span>`,
        );
      const dueText = r.due === null ? 'no due date' : `due ${fmtDateTime(r.due)}`;
      const extText = r.ext === null ? '' : `Extended to ${fmtDateTime(r.ext)}`;
      const aria = `${r.d.label}${r.d.basis ? `, ${r.d.basis}` : ''}: ${STATE_LABEL[r.state]}, ${r.text}, ${dueText}${extText ? `, ${extText}` : ''}`;
      return `<button class="lane" type="button" data-act="select" data-arg="${esc(r.d.id)}" aria-label="${esc(aria)}">
  <span class="lbl">${esc(r.d.label)}${r.d.basis ? `<span class="muted">${esc(r.d.basis)}</span>` : ''}</span>
  ${r.due === null ? `<span class="nd">${esc(r.text)}</span>` : `<span class="track" aria-hidden="true">${parts.join('')}</span>`}
  <span class="res"><span class="pill ${STATE_TONE[r.state]}">${STATE_GLYPH[r.state] ? glyph(STATE_GLYPH[r.state]!, 12) : ''}${STATE_LABEL[r.state]}</span>${r.due === null ? '' : `<span>${esc(r.text)}</span>`}${extText ? `<span class="ext">${esc(extText)}</span>` : ''}</span>
</button>`;
    };

    const exportBtn =
      this._exportEnabled === false
        ? ''
        : `<button class="btn" type="button" data-act="export">Export CSV</button>`;
    const upcoming = rows.flatMap((r) => (r.state === 'running' && r.due !== null ? [r.due] : []));
    const next = upcoming.length === 0 ? null : Math.min(...upcoming);
    const counted: (KitStat & { n: number })[] = [
      { tone: 'bad', icon: 'circle-alert', text: `${missed} overdue`, n: missed },
      { tone: 'warn', icon: 'clock', text: `${late} late`, n: late },
      { tone: 'info', icon: 'hourglass', text: `${running} running`, n: running },
      { tone: 'ok', icon: 'check', text: `${met} met`, n: met },
    ];
    const stats = counted.filter((x) => x.n > 0);
    return `<div class="card">
  ${this.head(
    this._heading ?? 'Deadlines',
    deadlineFinding(missed, next === null ? null : next - now),
    {
      sub,
      stats,
      actions: exportBtn,
    },
  )}
  <div class="body"><div role="list">${rows.map((r) => `<div role="listitem">${lane(r)}</div>`).join('')}</div>
    <div class="scale" aria-hidden="true"><span></span><div class="axis">${this.scale(anchorAt, end, pct)}<span class="nowt" style="left:${pct(now)}%">Now</span></div><span></span></div>
  </div>
  ${this.foot()}
</div>`;
  }
}

defineElement('henoyo-deadline-clock', HenoyoDeadlineClock);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-deadline-clock': HenoyoDeadlineClock;
  }
}
