// <docket-pipeline>: what ran on one scan, in what order, for how long, and who built it.
// A Gantt: one lane per scanner or agent, a bar from its start to its end, grouped by phase.
// Henoyo-native lanes are verdant; third-party tools are neutral; a required scanner that
// did not run is a dashed amber outline in the slot it should have filled.
//
// Henoyo web-component contract: Custom Element v1, open shadow root, data in through
// properties, events out as composed CustomEvents (`docket:lane`), colours from --h-* tokens.

import { HenoyoElement, defineElement, esc, KIT_STYLE, legend, type KitStat } from './henoyoKit';
import { DOCKET_STYLE, dg, originChip, type Origin } from './docketKit';

export type LaneState = 'done' | 'running' | 'queued' | 'error' | 'skipped' | 'not_run';

export interface DocketLane {
  id: string;
  label: string;
  /** Tool name for a third-party lane ("Semgrep"); ignored for Henoyo lanes. */
  tool?: string;
  origin: Origin;
  group: string;
  state: LaneState;
  /** One of the Docket glyph names. */
  icon?: string;
  /** Seconds from the run start. A not_run lane carries the slot it should have taken. */
  start?: number;
  end?: number;
  /** The policy requires this scanner for the application. */
  required?: boolean;
  requiredBy?: string[];
  candidates?: number;
  proven?: number;
  summary?: string;
  cost?: number;
  /** Nested under another lane: the exploit swarm's specialists. */
  parentId?: string;
}

export interface DocketLaneGroup {
  key: string;
  label: string;
  sub?: string;
}

const STATE_WORD: Record<LaneState, string> = {
  done: 'Done',
  running: 'Running',
  queued: 'Queued',
  error: 'Failed',
  skipped: 'Skipped',
  not_run: 'Not run',
};

const STEPS = [5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600];

export function clock(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return h > 0
    ? `${h}:${String(m).padStart(2, '0')}:${String(r).padStart(2, '0')}`
    : `${m}:${String(r).padStart(2, '0')}`;
}

export function spoken(seconds: number): string {
  const s = Math.round(seconds);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return r === 0 ? `${m} min` : `${m} min ${r} s`;
}

export class DocketPipeline extends HenoyoElement {
  private _heading = 'Scan pipeline';
  private _lanes: DocketLane[] = [];
  private _groups: DocketLaneGroup[] = [];
  private _elapsed: number | undefined;
  private _policy: string | undefined;

  set heading(v: string | undefined) {
    this._heading = v ?? 'Scan pipeline';
    this.invalidate();
  }
  set lanes(v: DocketLane[]) {
    this._lanes = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  set groups(v: DocketLaneGroup[]) {
    this._groups = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  /** Seconds since the run began; set while it is running to draw the "now" line. */
  set elapsed(v: number | undefined) {
    this._elapsed = v;
    this.invalidate();
  }
  set policy(v: string | undefined) {
    this._policy = v;
    this.invalidate();
  }

  protected styles(): string {
    return (
      DOCKET_STYLE +
      `
.gantt { padding:0 var(--h-kit-pad, 22px) 6px; overflow-x:auto; }
.axis, .lane { display:grid; grid-template-columns:minmax(150px, 236px) minmax(240px, 1fr) minmax(104px, 150px); column-gap:14px; align-items:center; }
.axis { position:sticky; top:0; font-size:11px; color:var(--k-text-3); padding:2px 0 6px; border-bottom:1px solid var(--k-hairline); }
.axis .ticks { position:relative; height:16px; }
.axis .tick { position:absolute; top:0; transform:translateX(-50%); font-variant-numeric:tabular-nums; }
.axis .tick:first-child { transform:none; }
.axis .res-h { text-align:right; }
.grp { padding:14px 0 4px; display:flex; gap:10px; align-items:baseline; }
.grp .gl { font-size:11px; font-weight:600; letter-spacing:.1em; text-transform:uppercase; color:var(--k-text-2); }
.grp .gs { font-size:12px; color:var(--k-text-3); }
.lane { width:100%; min-height:var(--h-kit-lane, 46px); padding:5px 0; border:0; border-bottom:1px solid var(--k-hairline); background:none; text-align:left; font:inherit; color:inherit; cursor:pointer; position:relative; }
.lane:hover, .lane:focus-visible { background:var(--k-surface-2); }
.lane.child { min-height:34px; }
.lbl { display:flex; gap:9px; align-items:center; min-width:0; }
.lane.child .lbl { padding-left:22px; }
.lbl .ic { width:26px; height:26px; border-radius:7px; display:inline-grid; place-items:center; flex:none; background:var(--k-surface-2); color:var(--k-text-2); border:1px solid var(--k-hairline); }
.lane[data-origin='henoyo'] .lbl .ic { background:rgb(var(--h-verdant-50, 233 239 235)); color:rgb(var(--h-verdant-700, 43 74 53)); border-color:rgb(var(--h-verdant-200, 168 191 175)); }
.lane.child .lbl .ic { width:20px; height:20px; border-radius:5px; }
.lbl .nm { font-size:13px; font-weight:600; line-height:1.25; }
.lane.child .lbl .nm { font-weight:500; font-size:12.5px; }
.lbl .meta { display:flex; gap:6px; align-items:center; margin-top:2px; flex-wrap:wrap; }
.req { display:inline-flex; align-items:center; gap:3px; font-size:10.5px; font-weight:600; color:var(--k-text-2); }
.track { position:relative; height:24px; }
.track::before { content:''; position:absolute; left:0; right:0; top:50%; border-top:1px dashed var(--k-hairline-2); opacity:.55; }
.gl-line { position:absolute; top:-6px; bottom:-6px; border-left:1px solid var(--k-hairline); }
.bar { position:absolute; top:3px; height:18px; min-width:6px; border-radius:5px; display:flex; align-items:center; padding:0 7px; font-size:11px; font-weight:600; font-variant-numeric:tabular-nums; overflow:hidden; white-space:nowrap; }
.lane.child .bar { top:6px; height:12px; border-radius:4px; padding:0; }
.bar.h { background:rgb(var(--h-verdant-600, 59 96 71)); color:rgb(var(--h-text-inverse, 248 246 241)); }
.bar.t { background:rgb(var(--h-surface-3, 227 223 212)); color:var(--k-text); border:1px solid var(--k-hairline-2); }
.bar.running { background-image:repeating-linear-gradient(135deg, rgb(255 255 255 / .22) 0 6px, transparent 6px 12px); }
.bar.t.running { background-color:rgb(var(--h-surface-3, 227 223 212)); background-image:repeating-linear-gradient(135deg, rgb(0 0 0 / .07) 0 6px, transparent 6px 12px); }
.bar.error { background:var(--k-bad-soft); color:var(--k-bad); border:1px solid var(--k-sev-critical); }
.bar.skipped, .bar.queued { background:transparent; color:var(--k-text-3); border:1px dashed var(--k-hairline-2); }
.bar.not_run { background:rgb(var(--h-sev-high-soft, 255 251 235)); color:var(--k-warn); border:1.5px dashed rgb(var(--h-sev-high, 217 122 26)); }
.untimed { position:absolute; left:0; top:4px; font-size:11px; color:var(--k-text-3); font-style:italic; }
.now { position:absolute; top:-8px; bottom:-8px; border-left:2px solid var(--k-sev-critical); z-index:2; }
.now::after { content:'now'; position:absolute; top:-2px; left:4px; font-size:10px; font-weight:700; color:var(--k-sev-critical); }
.res { text-align:right; font-size:12px; line-height:1.35; font-variant-numeric:tabular-nums; color:var(--k-text-2); }
.res .pv { color:var(--k-sev-critical); font-weight:700; }
.res .st { font-weight:600; }
.res .st.error { color:var(--k-bad); } .res .st.not_run { color:var(--k-warn); } .res .st.running { color:var(--k-ok); }
.lane .tipbox { top:calc(100% - 2px); left:auto; right:0; }
.lane:hover .tipbox, .lane:focus-visible .tipbox { display:block; }
@media (max-width:760px) { .axis, .lane { grid-template-columns:minmax(120px, 160px) minmax(180px, 1fr); } .res, .res-h { display:none; } }
`
    );
  }

  private timing(): { total: number; lanes: Map<string, { start: number; end: number }> } {
    const timed = new Map<string, { start: number; end: number }>();
    let total = 0;
    for (const l of this._lanes) {
      if (l.start === undefined) continue;
      const end = l.end ?? this._elapsed ?? l.start;
      timed.set(l.id, { start: l.start, end });
      total = Math.max(total, end);
    }
    if (this._elapsed !== undefined) total = Math.max(total, this._elapsed);
    // A lane with no slot (a not_run lane with no estimate) goes after everything else.
    let tail = total;
    for (const l of this._lanes) {
      if (timed.has(l.id)) continue;
      const w = Math.max(total * 0.08, 8);
      timed.set(l.id, { start: tail, end: tail + w });
      tail += w;
    }
    return { total: Math.max(tail, 1), lanes: timed };
  }

  private finding(): { title: string; sub: string; stats: KitStat[] } {
    const lanes = this._lanes.filter((l) => l.parentId === undefined);
    const required = lanes.filter((l) => l.required);
    const ranRequired = required.filter((l) => l.state === 'done' || l.state === 'running' || l.state === 'error');
    const proven = lanes.reduce((n, l) => n + (l.proven ?? 0), 0);
    const missing = required.filter((l) => l.state === 'not_run');
    const failed = lanes.filter((l) => l.state === 'error');
    const { total } = this.timing();
    const running = lanes.some((l) => l.state === 'running');
    let title: string;
    if (required.length > 0)
      title = `${ranRequired.length} of ${required.length} required scanners ran`;
    else title = `${lanes.filter((l) => l.state === 'done').length} of ${lanes.length} stages complete`;
    // Name the scanners only while the sentence stays readable; past two, count them.
    const who = (ls: DocketLane[]): string => (ls.length <= 2 ? ls.map((l) => l.label).join(' and ') : `${ls.length} of them`);
    if (missing.length > 0) title += `; ${who(missing)} did not`;
    else if (failed.length > 0) title += `; ${who(failed)} failed`;
    const bits = [running ? `${spoken(total)} so far` : spoken(total) + ' end to end'];
    bits.push(proven > 0 ? `${proven} exploit${proven === 1 ? '' : 's'} proven` : 'no exploit proven');
    if (this._policy) bits.push(`policy: ${this._policy}`);
    const hn = lanes.filter((l) => l.origin === 'henoyo').length;
    const stats: KitStat[] = [
      { text: `${hn} Henoyo stages`, tone: 'ok', icon: 'check' },
      { text: `${lanes.length - hn} third-party`, tone: 'neutral' },
    ];
    if (missing.length > 0) stats.push({ text: `${missing.length} not run`, tone: 'warn', icon: 'triangle-alert' });
    else if (failed.length > 0) stats.push({ text: `${failed.length} failed`, tone: 'bad', icon: 'circle-x' });
    return { title, sub: bits.join(' · '), stats };
  }

  protected view(): string {
    if (this._lanes.length === 0) return this.emptyCard(this._heading, 'Nothing has run yet.', 'The pipeline appears after the first scan.');
    const { total, lanes: timed } = this.timing();
    const step = STEPS.find((s) => total / s <= 7) ?? 3600;
    const ticks: number[] = [];
    for (let t = 0; t <= total + 0.001; t += step) ticks.push(t);
    const pct = (t: number): number => (t / total) * 100;
    const f = this.finding();
    const groups = this._groups.length > 0 ? this._groups : [{ key: '', label: '' }];
    const lines = ticks.map((t) => `<span class="gl-line" style="left:${pct(t)}%"></span>`).join('');
    const now =
      this._elapsed === undefined
        ? ''
        : `<span class="now" style="left:${Math.min(100, pct(this._elapsed))}%"></span>`;

    const row = (l: DocketLane): string => {
      const t = timed.get(l.id)!;
      const child = l.parentId !== undefined;
      const left = pct(t.start);
      const width = Math.max(pct(t.end - t.start), 0.8);
      const dur = l.state === 'not_run' ? 'Not run' : l.state === 'queued' ? 'Queued' : clock(t.end - t.start);
      const barCls = `${l.origin === 'henoyo' ? 'h' : 't'} ${l.state}`;
      // A report from before stage timings were recorded knows a stage ran but not when: say so
      // rather than draw a bar that implies a time.
      const untimed = l.start === undefined && l.state !== 'not_run';
      const reqBy = l.requiredBy ?? [];
      const req = l.required
        ? `<span class="req" title="Required by the security policy">${dg('lock', 10)}Required</span>`
        : '';
      const res: string[] = [];
      if (l.state === 'not_run') res.push(`<span class="st not_run">Not run</span>`);
      else if (l.state === 'error') res.push(`<span class="st error">Failed</span>`);
      else if (l.state === 'running') res.push(`<span class="st running">Running</span>`);
      if ((l.proven ?? 0) > 0) res.push(`<span class="pv">${l.proven} proven</span>`);
      if ((l.candidates ?? 0) > 0) res.push(`${l.candidates} candidate${l.candidates === 1 ? '' : 's'}`);
      if (l.summary && res.length < 2) res.push(esc(l.summary));
      if (l.cost !== undefined && l.cost > 0) res.push(`$${l.cost.toFixed(2)}`);
      const tip =
        `<b>${esc(l.label)}</b> · ${STATE_WORD[l.state]}<br>` +
        (l.state === 'not_run'
          ? `Required${reqBy.length ? ' by ' + esc(reqBy.join('; ')) : ' by policy'}, but it did not run.`
          : `${clock(t.start)} to ${clock(t.end)} (${spoken(t.end - t.start)})`) +
        (l.summary ? `<br>${esc(l.summary)}` : '') +
        (reqBy.length && l.state !== 'not_run' ? `<br>Required by ${esc(reqBy.join('; '))}` : '');
      return `<button type="button" class="lane${child ? ' child' : ''}" data-id="${esc(l.id)}" data-origin="${l.origin}" aria-label="${esc(l.label)}, ${STATE_WORD[l.state]}, ${l.origin === 'henoyo' ? 'Henoyo' : 'third-party'}">
        <div class="lbl"><span class="ic">${dg(l.icon ?? 'scan', child ? 12 : 15)}</span><div><div class="nm">${esc(l.label)}</div>${
          child ? '' : `<div class="meta">${originChip(l.origin, l.tool)}${req}</div>`
        }</div></div>
        <div class="track">${lines}${
          untimed
            ? `<span class="untimed">No timing recorded</span>`
            : `<span class="bar ${barCls}" style="left:${left}%;width:${width}%">${child ? '' : esc(dur)}</span>`
        }${now}</div>
        <div class="res">${res.slice(0, 3).join('<br>')}</div>
        <span class="tipbox" role="tooltip">${tip}</span>
      </button>`;
    };

    const body = groups
      .map((g) => {
        const members = this._lanes.filter((l) => l.group === g.key || (g.key === '' && true));
        const top = members.filter((l) => l.parentId === undefined);
        const rows = top
          .map((l) => row(l) + members.filter((c) => c.parentId === l.id).map(row).join(''))
          .join('');
        const head =
          g.label === ''
            ? ''
            : `<div class="grp"><span class="gl">${esc(g.label)}</span>${g.sub ? `<span class="gs">${esc(g.sub)}</span>` : ''}</div>`;
        return head + rows;
      })
      .join('');

    const axis = `<div class="axis"><div>Stage</div><div class="ticks">${ticks
      .map((t) => `<span class="tick" style="left:${pct(t)}%">${clock(t)}</span>`)
      .join('')}</div><div class="res-h">Result</div></div>`;

    return `<div class="card">${this.head(this._heading, f.title, { sub: f.sub, stats: f.stats })}
      <div class="gantt" role="group" aria-label="${esc(this._heading)}">${axis}${body}</div>
      <div class="body" style="padding-top:0">${legend([
        { label: 'Henoyo-native', color: 'rgb(var(--h-verdant-600, 59 96 71))' },
        {
          label: 'Third-party tool',
          color: 'rgb(var(--h-surface-3, 227 223 212))',
          swatchStyle: 'border:1px solid var(--k-hairline-2)',
        },
        {
          label: 'Required, not run',
          color: 'rgb(var(--h-sev-high-soft, 255 251 235))',
          swatchStyle: 'border:1.5px dashed rgb(var(--h-sev-high, 217 122 26))',
        },
      ])}</div>${this.foot()}</div>`;
  }

  protected afterRender(): void {
    for (const el of this.root.querySelectorAll<HTMLElement>('.lane'))
      el.addEventListener('click', () =>
        this.dispatchEvent(
          new CustomEvent('docket:lane', { detail: { id: el.dataset['id'] }, bubbles: true, composed: true }),
        ),
      );
  }
}

defineElement('docket-pipeline', DocketPipeline);
void KIT_STYLE;
