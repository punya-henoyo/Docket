// <docket-policy-flow>: a policy drawn as one left-to-right picture.
//
//   Starts -> Before the agents -> Docket agents -> Guidelines -> Gate -> Outcome
//
// It is honest about what a policy is: Docket runs a FIXED pipeline, and the policy JUDGES it
// (what must have run, how recently, what a gap means). So the stations sit in the order Docket
// runs them, there is no reordering, `planned` tools are visible but never selectable, and the
// Starts node is stated, not editable. Two modes:
//   design  stations are buttons (docket:station), "+" ghosts add (docket:add-station,
//           docket:add-guideline). Nothing here ever shows a result.
//   run     the same flow, each station showing the REAL state from `runLanes`. The Gate shows a
//           conclusion only when handed `gateResult`; otherwise "No gate result recorded".
//           Stations emit docket:lane, as <docket-pipeline> does.
//
// Henoyo web-component contract: Custom Element v1, open shadow root, data in through
// properties, events out as composed CustomEvents, colours from the --h-* tokens.

import { HenoyoElement, defineElement, esc, KIT_STYLE } from './henoyoKit';
import { DOCKET_STYLE, dg, originChip, type Origin } from './docketKit';
import { clock, type DocketLane } from './docketPipeline';

export type FlowAvailability = 'runs' | 'imports' | 'planned';
export type FlowGroup = 'pre' | 'agents' | 'guidelines';
export type FlowEffect = 'blocks' | 'flags' | 'advises';

/** One step of a policy, hydrated with its catalog slot. */
export interface FlowStep {
  id: string;
  /** Capability label of the slot ("Static analysis"). */
  label: string;
  /** Display name of the chosen tool ("CodeQL"). For a Henoyo step the origin chip says Henoyo. */
  tool?: string;
  origin: Origin;
  availability?: FlowAvailability;
  required: boolean;
  /** "At least every 7 days", "After every scanner run". */
  cadence?: string;
  what?: string;
  produces?: string;
  command?: string;
  icon?: string;
  /** Defaults from the slot id: scanners before the agents, the compliance reader with the guidelines. */
  group?: FlowGroup;
}

export interface FlowPolicy {
  id: string;
  name: string;
  applies?: string;
  cadence_days?: number | null;
  steps: FlowStep[];
  /** Pack ids; used only when `guidelines` carries no hydrated packs. */
  guidelines?: string[];
}

export interface FlowStart {
  kind: string;
  label: string;
  availability: 'works' | 'planned';
  note?: string;
}

export interface FlowGuideline {
  id: string;
  authority: string;
  title: string;
  controls?: number;
  observable?: number;
}

export interface FlowGate {
  effect: FlowEffect;
  text: string;
}

export interface FlowOutcome {
  label: string;
  note?: string;
  icon?: string;
}

const PRE_IDS = ['trivy', 'semgrep', 'nuclei', 'apisec'];

const OUTCOMES: FlowOutcome[] = [
  { label: 'Pull-request check', note: 'A status on the pull request', icon: 'git-pull-request' },
  { label: 'Report', note: 'Findings, proof and what ran', icon: 'file-text' },
  { label: 'Fix pull request', note: 'A patch for each proven exploit', icon: 'wrench' },
];

const CAPTIONS = ['a run begins', 'candidates go to triage', 'what was proven and judged', 'advice only, never a block'];
const OUT_CAPTION = 'a reproduced exploit blocks';

const AVAIL_WORD: Record<FlowAvailability, string> = { runs: 'Runs in Docket', imports: 'Imports SARIF', planned: 'Planned' };
const AVAIL_TIP: Record<FlowAvailability, string> = {
  runs: 'Docket runs this tool itself.',
  imports: 'Docket reads the results this tool wrote as a SARIF file and records that the step ran.',
  planned: 'Not available yet. The policy cannot use it.',
};
const STATE_WORD: Record<string, string> = {
  done: 'Done', running: 'Running', queued: 'Queued', error: 'Failed', skipped: 'Skipped', not_run: 'Not run',
};

/** Local 24x24 glyphs the kit does not ship; anything else falls through to docketKit's set. */
const PG: Record<string, string> = {
  play: '<path d="M7 4.5v15l12-7.5z"/>',
  'git-pull-request': '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="19" r="2"/><path d="M6 7v10M18 17V9a3 3 0 0 0-3-3h-3"/><path d="m14 3-2 3 2 3"/>',
  'file-text': '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/>',
  repeat: '<path d="M4 11V9a3 3 0 0 1 3-3h11l-3-3M20 13v2a3 3 0 0 1-3 3H6l3 3"/>',
  tag: '<path d="M3 12V4h8l10 10-8 8z"/><circle cx="7.5" cy="8.5" r="1.2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  book: '<path d="M5 4h11a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3z"/><path d="M5 17a3 3 0 0 1 3-3h11"/>',
  gate: '<path d="M4 20V8l8-4 8 4v12"/><path d="M9 20v-6h6v6"/>',
  inbox: '<path d="M4 13 6 5h12l2 8v6H4z"/><path d="M4 13h5a3 3 0 0 0 6 0h5"/>',
};
function pg(name: string, size = 14): string {
  const body = PG[name];
  if (body === undefined) return dg(name, size);
  return `<svg class="g" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}

function groupOf(s: FlowStep): FlowGroup {
  if (s.group) return s.group;
  if (s.id === 'compliance') return 'guidelines';
  return PRE_IDS.includes(s.id) ? 'pre' : 'agents';
}

export class DocketPolicyFlow extends HenoyoElement {
  private _policy: FlowPolicy | undefined;
  private _starts: FlowStart[] = [];
  private _guidelines: FlowGuideline[] = [];
  private _gate: FlowGate[] = [];
  private _outcomes: FlowOutcome[] = OUTCOMES;
  private _mode: 'design' | 'run' = 'design';
  private _runLanes: DocketLane[] = [];
  private _selected: string | undefined;
  private _warnings: string[] = [];
  private _gateResult: { effect: FlowEffect; text: string } | null = null;
  private _runLabel: string | undefined;

  set policy(v: FlowPolicy | undefined) { this._policy = v; this.invalidate(); }
  set starts(v: FlowStart[]) { this._starts = Array.isArray(v) ? v : []; this.invalidate(); }
  /** Hydrated packs selected by the policy. */
  set guidelines(v: FlowGuideline[]) { this._guidelines = Array.isArray(v) ? v : []; this.invalidate(); }
  /** The fixed gate wording, read-only (portfolio/policy.py GATE). */
  set gate(v: FlowGate[]) { this._gate = Array.isArray(v) ? v : []; this.invalidate(); }
  set outcomes(v: FlowOutcome[] | undefined) { this._outcomes = Array.isArray(v) && v.length > 0 ? v : OUTCOMES; this.invalidate(); }
  set mode(v: 'design' | 'run') { this._mode = v === 'run' ? 'run' : 'design'; this.invalidate(); }
  set runLanes(v: DocketLane[]) { this._runLanes = Array.isArray(v) ? v : []; this.invalidate(); }
  set selected(v: string | undefined) { this._selected = v; this.invalidate(); }
  /** Floor warnings: "Banking customer-facing applications: no exploit swarm". */
  set warnings(v: string[]) { this._warnings = Array.isArray(v) ? v : []; this.invalidate(); }
  /** What the gate would conclude for the run shown. Never invented: absent means "No gate result recorded". */
  set gateResult(v: { effect: FlowEffect; text: string } | null | undefined) { this._gateResult = v ?? null; this.invalidate(); }
  /** One line naming the run shown, for run mode ("Card Payments API, 18 Oct, full scan"). */
  set runLabel(v: string | undefined) { this._runLabel = v; this.invalidate(); }

  protected styles(): string {
    return (
      DOCKET_STYLE +
      `
:host { container-type:inline-size; }
.card { height:auto; }
.ban { margin:0 var(--h-kit-pad, 22px) 4px; padding:8px 12px; border-radius:9px; background:var(--k-surface-2); border:1px solid var(--k-hairline); display:flex; flex-wrap:wrap; gap:6px 10px; align-items:center; font-size:12.5px; color:var(--k-text-2); }
.ban .ic { color:var(--k-text-3); display:inline-flex; }
.warnchip { display:inline-flex; align-items:center; gap:5px; height:22px; padding:0 9px; border-radius:999px; font-size:11.5px; font-weight:600; background:rgb(var(--h-status-warning-soft, 255 251 235)); color:rgb(var(--h-status-warning, 180 83 9)); border:1px solid rgb(var(--h-sev-high, 217 122 26) / .55); }
.flow { display:grid; grid-template-columns:minmax(0,.8fr) 62px minmax(0,1.36fr) 62px minmax(0,1.36fr) 62px minmax(0,1.06fr) 62px minmax(0,1.1fr); padding:12px var(--h-kit-pad, 22px) 18px; align-items:stretch; }
.col { display:flex; flex-direction:column; min-width:0; }
.frame { flex:1; display:flex; flex-direction:column; gap:8px; padding:10px; border:1px dashed var(--k-hairline-2); border-radius:12px; background:rgb(var(--h-canvas, 251 248 241) / .55); min-width:0; }
.frame > .ft { display:flex; align-items:baseline; gap:8px; flex-wrap:wrap; padding:0 2px 2px; }
.frame > .ft b { font-family:var(--k-serif); font-weight:500; font-size:15px; letter-spacing:-.005em; }
.frame > .ft small { font-size:11px; color:var(--k-text-3); }
.conn { display:flex; flex-direction:column; align-items:center; justify-content:center; gap:3px; padding:0 2px; min-width:0; }
.conn svg { width:44px; height:20px; color:var(--k-text-3); flex:none; }
.conn span { font-size:10px; line-height:1.25; text-align:center; color:var(--k-text-3); max-width:62px; }
.conn.down { flex-direction:row; justify-content:center; padding:5px 0; }
.conn.down svg { transform:rotate(90deg); width:30px; height:20px; }
.conn.down span { max-width:none; font-size:10.5px; text-align:left; }

button.st, .node { all:unset; box-sizing:border-box; display:block; position:relative; width:100%; padding:9px 10px 9px 12px; border-radius:10px; background:var(--k-surface); border:1px solid var(--k-hairline-2); border-left:3px solid rgb(var(--h-verdant-600, 59 96 71)); }
button.st { cursor:pointer; }
button.st:hover { border-color:var(--k-text-3); border-left-color:rgb(var(--h-verdant-600, 59 96 71)); box-shadow:0 2px 10px -4px rgb(26 31 28 / .25); }
button.st:focus-visible { outline:2px solid var(--k-brand); outline-offset:2px; }
button.st.opt, .node.opt { background:rgb(var(--h-surface-2, 246 243 236) / .7); border-color:var(--k-hairline); border-left:3px solid var(--k-hairline-2); }
button.st.opt .cap { font-weight:500; color:var(--k-text-2); }
button.st.sel { border-color:var(--k-brand); box-shadow:0 0 0 2px rgb(var(--h-verdant-600, 59 96 71) / .35); background:rgb(var(--h-verdant-50, 233 239 235) / .7); }
button.st.planned { opacity:.8; }
.r1 { display:flex; align-items:center; gap:7px; min-width:0; }
.ic { width:24px; height:24px; border-radius:7px; display:inline-grid; place-items:center; flex:none; background:var(--k-surface-2); color:var(--k-text-2); border:1px solid var(--k-hairline); }
.st[data-origin='henoyo'] .ic { background:rgb(var(--h-verdant-50, 233 239 235)); color:rgb(var(--h-verdant-700, 43 74 53)); border-color:rgb(var(--h-verdant-200, 168 191 175)); }
.cap { font-size:12.5px; font-weight:600; line-height:1.2; flex:1; min-width:0; }
.ord { font-size:10px; font-weight:700; color:var(--k-text-3); font-variant-numeric:tabular-nums; margin-right:-2px; }
.r2 { display:flex; gap:5px; flex-wrap:wrap; align-items:center; margin-top:7px; }
.rq { display:inline-flex; align-items:center; gap:3px; height:18px; padding:0 7px; border-radius:999px; font-size:10.5px; font-weight:600; white-space:nowrap; flex:none; }
.rq.y { background:rgb(var(--h-verdant-50, 233 239 235)); color:rgb(var(--h-verdant-700, 43 74 53)); border:1px solid rgb(var(--h-verdant-200, 168 191 175)); }
.rq.n { color:var(--k-text-3); border:1px solid var(--k-hairline-2); }
.avl { display:inline-flex; align-items:center; height:18px; padding:0 7px; border-radius:999px; font-size:10.5px; font-weight:600; white-space:nowrap; width:auto; }
.avl.runs { background:var(--k-ok-soft); color:var(--k-ok); }
.avl.imports { background:var(--k-info-soft); color:var(--k-info); }
.avl.planned { background:transparent; color:var(--k-text-3); border:1px dashed var(--k-hairline-2); }
.cad { margin-top:6px; font-size:11.5px; color:var(--k-text-2); display:flex; gap:5px; align-items:flex-start; line-height:1.35; }
.cad svg { flex:none; margin-top:1px; color:var(--k-text-3); }
.prod { margin-top:3px; font-size:11.5px; color:var(--k-text-3); line-height:1.35; }
.ghost { all:unset; box-sizing:border-box; cursor:pointer; display:flex; align-items:center; justify-content:center; gap:6px; width:100%; min-height:34px; padding:6px 10px; border-radius:10px; border:1.5px dashed var(--k-hairline-2); color:var(--k-text-3); font-size:12px; font-weight:600; }
.ghost:hover, .ghost:focus-visible { color:var(--k-text); border-color:var(--k-text-3); background:var(--k-surface); }
.ghost.sm { min-height:26px; width:auto; padding:3px 10px; border-radius:999px; }

.node .nt { display:flex; align-items:center; gap:7px; font-size:12.5px; font-weight:600; }
.node .nn { margin-top:3px; font-size:11.5px; color:var(--k-text-2); line-height:1.35; }
.node.start { border-left-color:var(--k-hairline-2); }
.node.start.planned { background:transparent; border-style:dashed; border-left-style:dashed; }
.chips { display:flex; flex-wrap:wrap; gap:6px; }
.pack { display:flex; align-items:center; gap:7px; width:100%; padding:5px 9px 5px 6px; border-radius:10px; line-height:1.3; background:var(--k-surface); border:1px solid var(--k-hairline-2); font-size:11.5px; font-weight:600; max-width:100%; }
.pack .au { flex:none; height:18px; padding:0 7px; border-radius:999px; display:inline-grid; place-items:center; font-size:10px; font-weight:700; letter-spacing:.04em; background:rgb(var(--h-status-info-soft, 208 220 230)); color:rgb(var(--h-status-info, 30 54 76)); }
.note { font-size:11.5px; color:var(--k-text-3); line-height:1.4; margin:0; }
.eff { display:inline-block; flex:none; font-size:10.5px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; padding:1px 8px; border-radius:999px; }
.eff.blocks { background:var(--k-bad-soft); color:var(--k-sev-critical); border:1px solid var(--k-sev-critical); }
.eff.flags { background:rgb(var(--h-status-warning-soft, 255 251 235)); color:rgb(var(--h-status-warning, 180 83 9)); border:1px solid rgb(var(--h-sev-high, 217 122 26) / .5); }
.eff.advises { background:var(--k-neutral-soft); color:var(--k-neutral); }
.grow { display:grid; gap:7px; justify-items:start; }
.grow > div { display:grid; gap:3px; font-size:11.5px; line-height:1.4; color:var(--k-text-2); }
.rules summary { cursor:pointer; font-size:11.5px; font-weight:600; color:var(--k-text-2); margin:2px 0 6px; }
.gres { padding:8px 10px; border-radius:9px; border:1px solid var(--k-hairline-2); background:var(--k-surface); font-size:12px; line-height:1.4; color:var(--k-text-2); }
.gres.none { border-style:dashed; color:var(--k-text-3); }
.gres .eff { margin-bottom:4px; }

/* run mode */
.rs { margin-top:7px; font-size:12px; line-height:1.4; color:var(--k-text-2); display:grid; gap:2px; }
.rs .w { display:flex; align-items:center; gap:5px; font-weight:700; }
.rs .w.done { color:var(--k-ok); } .rs .w.running { color:var(--k-ok); } .rs .w.error { color:var(--k-bad); }
.rs .w.not_run.req { color:var(--k-sev-critical); }
.rs .w.not_run, .rs .w.skipped, .rs .w.queued { color:var(--k-text-3); }
.rs .pv { color:var(--k-sev-critical); font-weight:700; }
.rs small { font-size:11.5px; color:var(--k-text-3); }
button.st.gap { border-style:dashed; border-left-style:dashed; background:transparent; }
button.st.gap.reqgap { border-color:var(--k-sev-critical); background:var(--k-bad-soft); border-left-color:var(--k-sev-critical); }
button.st.gap.optgap { border-color:var(--k-hairline-2); }
button.st.running { background-image:repeating-linear-gradient(135deg, rgb(var(--h-verdant-600, 59 96 71) / .09) 0 6px, transparent 6px 12px); }
button.st.error { border-color:var(--k-sev-critical); }
.runnote { margin:0 var(--h-kit-pad, 22px) 4px; font-size:12.5px; color:var(--k-text-2); }

.tipbox { left:8px; top:calc(100% - 4px); min-width:220px; z-index:9; }
.tipbox code { font-family:"JetBrains Mono", ui-monospace, monospace; font-size:11px; word-break:break-all; }
button.st:hover .tipbox, button.st:focus-visible .tipbox { display:block; }

@container (max-width: 900px) {
  .flow { grid-template-columns:minmax(0,1fr); row-gap:0; }
  .conn { flex-direction:row; padding:6px 0; }
  .conn svg { transform:rotate(90deg); width:30px; }
  .conn span { max-width:none; font-size:10.5px; text-align:left; }
}
`
    );
  }

  private capChip(s: FlowStep): string {
    return `<span class="rq ${s.required ? 'y' : 'n'}">${s.required ? dg('lock', 10) + 'Required' : 'Optional'}</span>`;
  }

  private availChip(s: FlowStep): string {
    const a = s.availability ?? 'runs';
    return `<span class="avl ${a}" title="${esc(AVAIL_TIP[a])}">${AVAIL_WORD[a]}</span>`;
  }

  private tip(s: FlowStep): string {
    const bits = [`<b>${esc(s.label)}</b>`];
    if (s.what) bits.push(esc(s.what));
    if (s.command) bits.push(`<code>${esc(s.command)}</code>`);
    return `<span class="tipbox" role="tooltip">${bits.join('<br>')}</span>`;
  }

  private laneFor(id: string): DocketLane | undefined {
    return this._runLanes.find((l) => l.id === id && l.parentId === undefined);
  }

  private station(s: FlowStep, n: number | null): string {
    const run = this._mode === 'run';
    const sel = this._selected === s.id;
    const lane0 = run ? this.laneFor(s.id) : undefined;
    const toolShown = lane0?.tool && s.origin !== 'henoyo' ? lane0.tool : s.tool;
    const planned = s.availability === 'planned';
    const head = `<div class="r1">${n === null ? '' : `<span class="ord" title="Run order">${n}</span>`}<span class="ic">${dg(s.icon ?? 'scan', 14)}</span><span class="cap">${esc(s.label)}</span></div>
      <div class="r2">${this.capChip(s)}${originChip(s.origin, toolShown)}${toolShown === s.tool ? this.availChip(s) : ''}</div>`;
    let body = '';
    let cls = s.required ? 'req' : 'opt';
    if (!run) {
      body = `${s.cadence ? `<div class="cad">${dg('clock', 11)}<span>${esc(s.cadence)}</span></div>` : ''}${s.produces ? `<div class="prod">Produces: ${esc(s.produces)}</div>` : ''}`;
    } else {
      const l = this.laneFor(s.id);
      if (l === undefined || l.state === 'not_run') {
        cls += s.required ? ' gap reqgap' : ' gap optgap';
        body = `<div class="rs"><span class="w not_run${s.required ? ' req' : ''}">${dg('x', 12)}${s.required ? 'Required, not run' : 'Not run'}</span>${l?.summary ? `<small>${esc(l.summary)}</small>` : ''}</div>`;
      } else {
        const dur = l.start !== undefined && l.end !== undefined ? clock(l.end - l.start) : '';
        const icon = l.state === 'done' ? 'check' : l.state === 'error' ? 'alert' : l.state === 'running' ? 'clock' : 'minus';
        const lines: string[] = [];
        if ((l.proven ?? 0) > 0) lines.push(`<span class="pv">${l.proven} proven</span>`);
        if ((l.candidates ?? 0) > 0) lines.push(`${l.candidates} candidate${l.candidates === 1 ? '' : 's'}`);
        if (l.state === 'skipped' || l.state === 'queued') cls += ' gap optgap';
        if (l.state === 'running') cls += ' running';
        if (l.state === 'error') cls += ' error';
        body = `<div class="rs"><span class="w ${l.state}">${dg(icon, 12)}${STATE_WORD[l.state]}${dur && l.state === 'done' ? ` <span style="font-weight:500;color:var(--k-text-2)">· ${dur}</span>` : ''}</span>${lines.length ? `<span>${lines.join(' · ')}</span>` : ''}${l.summary ? `<small>${esc(l.summary)}</small>` : ''}</div>`;
      }
    }
    const aria = `${s.label}, ${s.required ? 'required' : 'optional'}${s.tool ? ', ' + s.tool : ''}`;
    return `<button type="button" class="st ${cls}${sel ? ' sel' : ''}${planned ? ' planned' : ''}" data-id="${esc(s.id)}" data-origin="${s.origin}" aria-pressed="${sel}" aria-label="${esc(aria)}">${head}${body}${this.tip(s)}</button>`;
  }

  private startsCol(): string {
    const days = this._policy?.cadence_days;
    const cards = this._starts
      .map((st) => {
        const planned = st.availability === 'planned';
        const icon = { manual: 'play', pull_request: 'git-pull-request', schedule: 'repeat', release: 'tag' }[st.kind] ?? 'play';
        const label = st.label.replace(/\bN\b/, days ? String(days) : 'N');
        return `<div class="node start${planned ? ' planned' : ''}"><div class="nt"><span class="ic">${pg(icon, 14)}</span><span class="cap">${esc(label)}</span></div>
          <div class="r2" style="margin-top:6px"><span class="avl ${planned ? 'planned' : 'runs'}">${planned ? 'Planned' : 'Works today'}</span></div>
          ${st.note ? `<div class="nn">${esc(st.note)}</div>` : ''}</div>`;
      })
      .join('');
    return `<div class="col"><div class="frame"><div class="ft"><b>Starts</b><small>How a run begins</small></div>${cards}
      <p class="note">Stated, not configured. The policy judges runs, however they start.</p></div></div>`;
  }

  private arrow(i: number): string {
    return `<div class="conn" aria-hidden="true"><svg viewBox="0 0 44 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 10h38M33 4l7 6-7 6"/></svg><span>${esc(CAPTIONS[i] ?? '')}</span></div>`;
  }

  private groupCol(title: string, sub: string, group: FlowGroup, steps: FlowStep[], startN: number): string {
    const design = this._mode === 'design';
    const ghost = design
      ? `<button type="button" class="ghost" data-add="${group}" aria-label="Add a step to ${esc(title)}">${pg('plus', 13)}Add a step</button>`
      : '';
    return `<div class="col"><div class="frame"><div class="ft"><b>${esc(title)}</b><small>${esc(sub)}</small></div>${steps
      .map((s, i) => this.station(s, startN + i))
      .join('')}${steps.length === 0 ? '<p class="note">No steps here.</p>' : ''}${ghost}</div></div>`;
  }

  private guidelinesCol(reader: FlowStep | undefined): string {
    const design = this._mode === 'design';
    const packs: FlowGuideline[] = this._guidelines.length
      ? this._guidelines
      : (this._policy?.guidelines ?? []).map((id) => ({ id, authority: id.split('-')[0]!.toUpperCase(), title: id }));
    const chips = packs
      .map((g) => `<span class="pack" title="${esc(g.title)}${g.controls ? ` · ${g.controls} controls, ${g.observable ?? 0} readable from code` : ''}"><span class="au">${esc(g.authority)}</span><span>${esc(g.title)}</span></span>`)
      .join('');
    const add = design
      ? `<button type="button" class="ghost sm" data-addg="1" aria-label="Add a guideline">${pg('plus', 12)}${packs.length ? 'Add' : 'Add a guideline'}</button>`
      : '';
    return `<div class="col"><div class="frame"><div class="ft"><b>Guidelines</b><small>Advisory</small></div>
      ${reader ? this.station(reader, null) : ''}
      <div class="chips">${chips}${add}</div>
      <p class="note">${packs.length ? 'A reader checks the code against these. It advises; it never blocks.' : 'No guideline selected. Choosing one adds the optional Compliance reader.'}</p></div></div>`;
  }

  private gateOutCol(): string {
    const run = this._mode === 'run';
    const rows = this._gate
      .map((g) => `<div><span class="eff ${g.effect}">${g.effect === 'blocks' ? 'Blocks' : g.effect === 'flags' ? 'Flags' : 'Advises'}</span><span>${esc(g.text)}</span></div>`)
      .join('');
    let result = '';
    if (run) {
      const r = this._gateResult;
      result = r
        ? `<div class="gres"><span class="eff ${r.effect}">${r.effect === 'blocks' ? 'Blocks' : r.effect === 'flags' ? 'Flags' : 'Advises'}</span><br>${esc(r.text)}</div>`
        : `<div class="gres none">No gate result recorded for this run.</div>`;
    }
    const outs = this._outcomes
      .map((o) => `<div class="node" style="border-left-color:var(--k-hairline-2)"><div class="nt"><span class="ic">${pg(o.icon ?? 'file-text', 13)}</span><span class="cap">${esc(o.label)}</span></div>${o.note ? `<div class="nn">${esc(o.note)}</div>` : ''}</div>`)
      .join('');
    return `<div class="col"><div class="frame" style="flex:none"><div class="ft"><b>Gate</b><small>${run ? 'This run' : 'Fixed wording'}</small></div>${result}${run ? `<details class="rules"><summary>The fixed rules</summary><div class="grow">${rows}</div></details>` : `<div class="grow">${rows}</div>`}
      <p class="note">The policy cannot change this.</p></div>
      <div class="conn down" aria-hidden="true"><svg viewBox="0 0 44 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 10h38M33 4l7 6-7 6"/></svg><span>${esc(OUT_CAPTION)}</span></div>
      <div class="frame"><div class="ft"><b>Outcome</b><small>What people get</small></div>${outs}</div></div>`;
  }

  protected view(): string {
    const p = this._policy;
    if (!p) return this.emptyCard('Policy flow', 'No policy selected.', 'Choose a policy to see how it is judged.');
    const run = this._mode === 'run';
    const steps = p.steps;
    const pre = steps.filter((s) => groupOf(s) === 'pre');
    const agents = steps.filter((s) => groupOf(s) === 'agents');
    const reader = steps.find((s) => groupOf(s) === 'guidelines');
    const req = steps.filter((s) => s.required).length;
    let stats;
    if (run) {
      const ran = steps.filter((s) => s.required && ['done', 'running', 'error'].includes(this.laneFor(s.id)?.state ?? 'not_run')).length;
      stats = [{ text: `${ran} of ${req} required ran`, tone: ran === req ? ('ok' as const) : ('warn' as const), icon: ran === req ? 'check' : 'triangle-alert' }];
    } else {
      stats = [
        { text: `${req} required`, tone: 'ok' as const, icon: 'check' },
        { text: `${steps.length - req} optional`, tone: 'neutral' as const },
      ];
    }
    const banner = run
      ? `<p class="runnote">${this._runLabel ? `<b>${esc(this._runLabel)}.</b> ` : ''}This is what the last run did, station by station. A dashed slot is a step the policy requires that did not run.</p>`
      : `<div class="ban"><span class="ic">${dg('lock', 13)}</span><span>Docket runs a fixed pipeline. This policy decides what must have run, how recently, and what a gap means.</span>${this._warnings
          .map((w) => `<span class="warnchip">${dg('alert', 12)}${esc(/^Thinner/.test(w) ? w : 'Thinner than the baseline for ' + w)}</span>`)
          .join('')}</div>`;
    return `<div class="card">${this.head(run ? 'Last run against the policy' : 'Policy flow', p.name, {
      sub: p.applies ?? '',
      stats,
    })}${banner}<div class="flow" role="group" aria-label="${esc(p.name)} flow">
      ${this.startsCol()}${this.arrow(0)}
      ${this.groupCol('Before the agents', 'Scanners, any vendor', 'pre', pre, 1)}${this.arrow(1)}
      ${this.groupCol('Docket agents', 'Henoyo validation', 'agents', agents, pre.length + 1)}${this.arrow(2)}
      ${this.guidelinesCol(reader)}${this.arrow(3)}
      ${this.gateOutCol()}
    </div>${this.foot()}</div>`;
  }

  protected afterRender(): void {
    const emit = (type: string, detail: Record<string, unknown>): void => {
      this.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true }));
    };
    for (const b of this.root.querySelectorAll<HTMLElement>('button.st'))
      b.addEventListener('click', () => emit(this._mode === 'run' ? 'docket:lane' : 'docket:station', { id: b.dataset['id'] }));
    for (const b of this.root.querySelectorAll<HTMLElement>('[data-add]'))
      b.addEventListener('click', () => emit('docket:add-station', { group: b.dataset['add'] }));
    for (const b of this.root.querySelectorAll<HTMLElement>('[data-addg]'))
      b.addEventListener('click', () => emit('docket:add-guideline', {}));
  }
}

defineElement('docket-policy-flow', DocketPolicyFlow);
void KIT_STYLE;
