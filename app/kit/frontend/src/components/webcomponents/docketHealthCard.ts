// <docket-health-card>: how one application is doing, and whether a busy person should worry.
// Three registers, top to bottom, borrowed from places that already solved "tell me fast":
//   1. a caution plate (avionics master caution): one word, one sentence, the reasons;
//   2. an annunciator panel: one lit tile per dimension that matters (secrets, proven
//      exploits, dependencies, coverage, freshness, compliance);
//   3. a lab report: each measure with its result, a reference-range bar, a flag in words
//      and the last few results as a sparkline.
// Colour never carries meaning alone: every state has a word.

import { HenoyoElement, defineElement, esc, KIT_STYLE } from './henoyoKit';
import { DOCKET_STYLE, LEVEL_WORD, dg, type Level } from './docketKit';

export type Tone = 'ok' | 'warn' | 'bad';

export interface Annunciator {
  key: string;
  label: string;
  state: Tone | 'off';
  value: string;
  hint?: string;
  /** A reading that never gates (compliance). Drawn dashed and never as a fault lamp. */
  advisory?: boolean;
}

export interface RangeBand {
  from: number;
  to: number;
  tone: Tone;
}

export interface Analyte {
  key: string;
  label: string;
  hint?: string;
  value: number;
  /** What the result says, as text ("2", "9 d", "3 of 4"). */
  display: string;
  scaleMax: number;
  bands: RangeBand[];
  /** The reference range as text ("0", "7 d or less"). */
  ref: string;
  flag: Tone | 'unknown';
  flagWord: string;
  trend?: number[];
  previous?: string;
  /** True when a higher result is better (required scanners that ran). Default: lower is better. */
  higherIsBetter?: boolean;
}

const TONE_WORD: Record<Tone, string> = { ok: 'In range', warn: 'Watch', bad: 'Out of range' };

function spark(values: number[], tone: Tone | 'unknown'): string {
  if (values.length < 2) return '';
  const w = 84;
  const h = 24;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const pts = values.map((v, i) => [
    (i / (values.length - 1)) * (w - 6) + 3,
    h - 3 - ((v - min) / span) * (h - 6),
  ]);
  const last = pts[pts.length - 1]!;
  const colour = tone === 'bad' ? 'var(--k-sev-critical)' : tone === 'warn' ? 'rgb(var(--h-sev-high, 217 122 26))' : 'var(--k-text-3)';
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="Last ${values.length} results: ${values.join(', ')}">
    <polyline points="${pts.map((p) => p.map((n) => n.toFixed(1)).join(',')).join(' ')}" fill="none" stroke="var(--k-hairline-2)" stroke-width="1.5" stroke-linejoin="round"/>
    <circle cx="${last[0]!.toFixed(1)}" cy="${last[1]!.toFixed(1)}" r="3" fill="${colour}"/></svg>`;
}

/** "Worse than last scan (was 1)": the sparkline shows shape, the words say which way. */
function delta(a: Analyte): string {
  const t = a.trend;
  if (!t || t.length < 2) return a.previous ? `<div class="prev">Last scan: ${esc(a.previous)}</div>` : '';
  const now = t[t.length - 1]!;
  const was = t[t.length - 2]!;
  if (now === was) return `<div class="prev">Same as last scan</div>`;
  const worse = a.higherIsBetter ? now < was : now > was;
  return `<div class="prev ${worse ? 'worse' : 'better'}">${worse ? 'Worse' : 'Better'} than last scan${a.previous ? ` (was ${esc(a.previous)})` : ''}</div>`;
}

export class DocketHealthCard extends HenoyoElement {
  private _heading = 'Application health';
  private _subject = '';
  private _level: Level = 'unknown';
  private _verdict = '';
  private _reasons: string[] = [];
  private _ann: Annunciator[] = [];
  private _analytes: Analyte[] = [];

  set heading(v: string | undefined) {
    this._heading = v ?? 'Application health';
    this.invalidate();
  }
  set subject(v: string | undefined) {
    this._subject = v ?? '';
    this.invalidate();
  }
  set level(v: Level) {
    this._level = v;
    this.invalidate();
  }
  set verdict(v: string | undefined) {
    this._verdict = v ?? '';
    this.invalidate();
  }
  set reasons(v: string[]) {
    this._reasons = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  set annunciators(v: Annunciator[]) {
    this._ann = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  set analytes(v: Analyte[]) {
    this._analytes = Array.isArray(v) ? v : [];
    this.invalidate();
  }

  protected styles(): string {
    return (
      DOCKET_STYLE +
      `
.plate { display:grid; grid-template-columns:auto 1fr; gap:18px; align-items:stretch; margin:2px var(--h-kit-pad, 22px) 0; }
.cap { display:flex; flex-direction:column; justify-content:center; gap:4px; min-width:148px; padding:12px 16px; border-radius:12px; border:1.5px solid var(--lv); background:var(--lv-soft); }
.cap .k { font:500 10.5px/1 "JetBrains Mono", ui-monospace, monospace; letter-spacing:.12em; text-transform:uppercase; color:var(--k-text-2); }
.cap .v { display:flex; align-items:center; gap:9px; font-family:var(--k-serif); font-size:26px; font-weight:500; letter-spacing:-.01em; color:var(--lv); line-height:1.1; }
.cap .v .lamp { width:14px; height:14px; background:var(--lv); }
.why .ans { font-family:var(--k-serif); font-size:17px; font-weight:500; margin:2px 0 6px; }
.why ul { margin:0; padding:0; list-style:none; display:grid; gap:4px; }
.why li { display:flex; gap:8px; font-size:13px; color:var(--k-text-2); line-height:1.4; }
.why li svg { flex:none; margin-top:2px; color:var(--lv); }
[data-level='action'] { --lv:var(--k-sev-critical); --lv-soft:var(--k-bad-soft); }
[data-level='attention'] { --lv:rgb(var(--h-status-warning, 180 83 9)); --lv-soft:rgb(var(--h-status-warning-soft, 255 251 235)); }
[data-level='clear'] { --lv:var(--k-ok); --lv-soft:var(--k-ok-soft); }
[data-level='unknown'] { --lv:var(--k-neutral); --lv-soft:var(--k-neutral-soft); }
.ann { display:flex; flex-wrap:wrap; gap:6px; padding:14px var(--h-kit-pad, 22px) 2px; }
.tile { display:inline-flex; align-items:center; gap:7px; padding:5px 11px 5px 9px; border-radius:999px; border:1px solid var(--k-hairline); background:var(--k-surface); }
.tile .tl { font:500 10px/1.1 "JetBrains Mono", ui-monospace, monospace; letter-spacing:.08em; text-transform:uppercase; color:var(--k-text-2); }
.tile .tv { font-family:var(--k-serif); font-size:14px; font-weight:600; line-height:1.15; font-variant-numeric:tabular-nums; }
.tile .th { display:none; }
.tile.ok { background:var(--k-ok-soft); border-color:transparent; } .tile.ok .tv { color:var(--k-ok); }
.tile.warn { background:rgb(var(--h-status-warning-soft, 255 251 235)); border-color:rgb(var(--h-sev-high, 217 122 26) / .5); } .tile.warn .tv { color:rgb(var(--h-status-warning, 180 83 9)); }
.tile.bad { background:var(--k-bad-soft); border-color:var(--k-sev-critical); } .tile.bad .tv { color:var(--k-sev-critical); }
.tile.off { background:var(--k-surface-2); border-style:dashed; } .tile.off .tv { color:var(--k-text-3); }
.tile.adv { background:var(--k-surface); border-style:dashed; border-color:var(--k-hairline-2); } .tile.adv .tv { color:var(--k-text-2); } .tile.adv .lamp { background:transparent; box-shadow:0 0 0 1.5px var(--k-text-3); }
.lab { padding:14px var(--h-kit-pad, 22px) 8px; overflow-x:auto; }
.lab table { width:100%; border-collapse:collapse; min-width:620px; }
.lab th { text-align:left; font:600 10.5px/1 Inter, sans-serif; letter-spacing:.1em; text-transform:uppercase; color:var(--k-text-3); padding:6px 10px 8px 0; border-bottom:1px solid var(--k-hairline-2); }
.lab td { padding:10px 10px 10px 0; border-bottom:1px solid var(--k-hairline); vertical-align:middle; }
.lab tr:last-child td { border-bottom:0; }
.lab .m { font-size:13px; font-weight:600; } .lab .mh { font-size:11.5px; color:var(--k-text-3); margin-top:1px; max-width:30ch; }
.lab .r { font-family:var(--k-serif); font-size:18px; font-weight:500; font-variant-numeric:tabular-nums; white-space:nowrap; }
.lab .r small { font:500 11px Inter, sans-serif; color:var(--k-text-3); margin-left:3px; }
.flag { display:inline-flex; align-items:center; gap:5px; margin-top:3px; font-size:11px; font-weight:700; padding:1px 8px; border-radius:999px; white-space:nowrap; }
.flag.ok { background:var(--k-ok-soft); color:var(--k-ok); } .flag.warn { background:rgb(var(--h-status-warning-soft, 255 251 235)); color:rgb(var(--h-status-warning, 180 83 9)); border:1px solid rgb(var(--h-sev-high, 217 122 26) / .5); }
.flag.bad { background:var(--k-bad-soft); color:var(--k-sev-critical); border:1px solid var(--k-sev-critical); } .flag.unknown { background:var(--k-neutral-soft); color:var(--k-neutral); }
.rng { position:relative; height:10px; border-radius:5px; background:var(--k-surface-2); min-width:150px; overflow:visible; }
.rng .bd { position:absolute; top:0; bottom:0; }
.rng .bd.ok { background:rgb(var(--h-verdant-100, 210 223 214)); } .rng .bd.warn { background:rgb(var(--h-sev-high, 217 122 26) / .28); } .rng .bd.bad { background:rgb(var(--h-sev-critical, 181 52 31) / .26); }
.rng .bd:first-child { border-radius:5px 0 0 5px; } .rng .bd:last-of-type { border-radius:0 5px 5px 0; }
.rng .mk { position:absolute; top:-4px; width:3px; height:18px; margin-left:-1.5px; border-radius:2px; background:var(--k-text); box-shadow:0 0 0 2px var(--k-surface); }
.refl { margin-top:7px; font-size:11px; color:var(--k-text-3); }
.prev { font-size:11px; color:var(--k-text-3); margin-top:2px; } .prev.worse { color:var(--k-sev-critical); font-weight:600; } .prev.better { color:var(--k-ok); font-weight:600; }
@media (max-width:720px) { .plate { grid-template-columns:1fr; } }
`
    );
  }

  protected view(): string {
    const lv = LEVEL_WORD[this._level];
    const reasons = this._reasons
      .slice(0, 4)
      .map((r) => `<li>${dg(this._level === 'clear' ? 'check' : 'alert', 14)}<span>${esc(r)}</span></li>`)
      .join('');
    const plate = `<div class="plate" data-level="${this._level}">
      <div class="cap" role="status"><span class="k">Needs attention?</span><span class="v"><span class="lamp"></span>${esc(lv.word)}</span></div>
      <div class="why"><div class="ans">${esc(lv.answer)}</div>${this._verdict ? `<div class="sub" style="margin:0 0 6px">${esc(this._verdict)}</div>` : ''}<ul>${reasons}</ul></div></div>`;

    const ann = this._ann
      .map(
        (a) => `<div class="tile ${a.advisory ? 'adv' : a.state}" role="group" aria-label="${esc(a.label)}: ${esc(a.value)}">
        <span class="lamp ${a.state}"></span><span class="tl">${esc(a.label)}</span><span class="tv" title="${esc(a.hint ?? '')}">${esc(a.value)}</span></div>`,
      )
      .join('');

    const rows = this._analytes
      .map((a) => {
        const pct = (n: number): number => Math.max(0, Math.min(100, (n / a.scaleMax) * 100));
        const bands = a.bands
          .map((b) => `<span class="bd ${b.tone}" style="left:${pct(b.from)}%;width:${pct(b.to) - pct(b.from)}%"></span>`)
          .join('');
        const t = a.flag === 'unknown' ? 'unknown' : a.flag;
        const word = a.flagWord || (a.flag === 'unknown' ? 'No data' : TONE_WORD[a.flag]);
        return `<tr><td><div class="m">${esc(a.label)}</div>${a.hint ? `<div class="mh">${esc(a.hint)}</div>` : ''}</td>
          <td><div class="r">${esc(a.display)}</div><span class="flag ${t}">${esc(word)}</span></td>
          <td><div class="rng" role="img" aria-label="${esc(a.label)} ${esc(a.display)}; reference ${esc(a.ref)}">${bands}<span class="mk" style="left:${pct(a.value)}%"></span></div><div class="refl">Reference: ${esc(a.ref)}</div></td>
          <td>${a.trend ? spark(a.trend, a.flag) : ''}${delta(a)}</td></tr>`;
      })
      .join('');

    const title = this._subject !== '' ? `${this._subject}: ${lv.word.toLowerCase()}` : lv.word;
    return `<div class="card" data-level="${this._level}">${this.head(this._heading, title, {
      sub: 'The verdict, the status lamps, then each measure against its reference range.',
    })}${plate}
      ${ann === '' ? '' : `<div class="ann" role="group" aria-label="Status panel">${ann}</div>`}
      ${rows === '' ? '' : `<div class="lab"><table><thead><tr><th>Measure</th><th>Result</th><th>Reference range</th><th>Last 8 scans</th></tr></thead><tbody>${rows}</tbody></table></div>`}
      ${this.foot()}</div>`;
  }
}

defineElement('docket-health-card', DocketHealthCard);
void KIT_STYLE;
