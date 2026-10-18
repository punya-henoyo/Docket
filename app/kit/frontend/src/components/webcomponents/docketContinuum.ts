// <docket-continuum>: every scan of every application on one time axis.
// One row per application; one mark per scan (full coverage, partial, or failed); a red
// diamond over a scan that proved an exploit; amber hatching wherever the policy cadence
// was broken. It answers "who has been looked at, how recently, and with what result"
// without opening a single record.

import { HenoyoElement, defineElement, esc, KIT_STYLE, legend, type KitStat } from './henoyoKit';
import { DOCKET_STYLE, LEVEL_WORD, type Level } from './docketKit';

export interface ContinuumEvent {
  id: string;
  at: string;
  coverage: 'full' | 'partial' | 'failed';
  proven: number;
  candidates?: number;
  /** 'pr' scans are pull-request gates and draw smaller than a full scan. */
  kind?: 'scan' | 'pr';
  label?: string;
}

export interface ContinuumRow {
  id: string;
  label: string;
  sub?: string;
  level: Level;
  events: ContinuumEvent[];
}

const DAY = 86_400_000;
const t = (iso: string): number => Date.parse(iso);

export class DocketContinuum extends HenoyoElement {
  private _heading = 'Scan continuum';
  private _rows: ContinuumRow[] = [];
  private _from = '';
  private _to = '';
  private _cadence = 7;

  set heading(v: string | undefined) {
    this._heading = v ?? 'Scan continuum';
    this.invalidate();
  }
  set rows(v: ContinuumRow[]) {
    this._rows = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  set from(v: string) {
    this._from = v;
    this.invalidate();
  }
  set to(v: string) {
    this._to = v;
    this.invalidate();
  }
  /** The policy's longest allowed gap between scans, in days. */
  set cadenceDays(v: number | undefined) {
    this._cadence = v ?? 7;
    this.invalidate();
  }

  protected styles(): string {
    return (
      DOCKET_STYLE +
      `
.cont { padding:0 var(--h-kit-pad, 22px) 8px; overflow-x:auto; }
.cr, .ca { display:grid; grid-template-columns:minmax(150px, 230px) minmax(420px, 1fr); column-gap:14px; align-items:center; }
.ca { font-size:11px; color:var(--k-text-3); padding:2px 0 6px; border-bottom:1px solid var(--k-hairline); }
.ca .ticks { position:relative; height:16px; } .ca .tick { position:absolute; top:0; transform:translateX(-50%); font-variant-numeric:tabular-nums; } .ca .tick:first-child { transform:none; }
.cr { width:100%; min-height:46px; border-bottom:1px solid var(--k-hairline); }
.cr .who { all:unset; box-sizing:border-box; display:flex; gap:10px; align-items:center; min-width:0; cursor:pointer; padding:6px 0; }
.cr .who:hover .nm, .cr .who:focus-visible .nm { text-decoration:underline; }
.cr .nm { font-size:13px; font-weight:600; line-height:1.25; } .cr .sb { font-size:11.5px; color:var(--k-text-3); }
.cr .lv { font-size:10.5px; font-weight:700; letter-spacing:.02em; }
.ctrack { position:relative; height:36px; }
.ctrack::before { content:''; position:absolute; left:0; right:0; top:50%; border-top:1px solid var(--k-hairline-2); }
.gl { position:absolute; top:0; bottom:0; border-left:1px solid var(--k-hairline); }
.gap { position:absolute; top:13px; height:10px; border-radius:3px; border:1px solid rgb(var(--h-sev-high, 217 122 26) / .6); }
.gaplbl { position:absolute; top:-1px; transform:translateX(-50%); font-size:10px; font-weight:700; color:rgb(var(--h-status-warning, 180 83 9)); white-space:nowrap; background:var(--k-surface); padding:0 4px; border-radius:3px; }
.mk { all:unset; box-sizing:border-box; position:absolute; top:9px; width:10px; height:18px; margin-left:-5px; border-radius:4px; cursor:pointer; z-index:1; }
.mk.full { background:rgb(var(--h-verdant-600, 59 96 71)); }
.mk.partial { background:var(--k-surface); border:2px solid rgb(var(--h-sev-high, 217 122 26)); }
.mk.failed { background:var(--k-bad-soft); border:2px solid var(--k-sev-critical); }
.mk.pr { top:13px; height:10px; width:8px; margin-left:-4px; border-radius:3px; }
.mk:focus-visible { outline:2px solid var(--k-brand); outline-offset:3px; }
.dia { position:absolute; top:-1px; left:50%; width:9px; height:9px; margin-left:-4.5px; background:var(--k-sev-critical); transform:rotate(45deg); border-radius:1px; box-shadow:0 0 0 1.5px var(--k-surface); }
.mk .tipbox { top:calc(100% + 6px); left:50%; transform:translateX(-30%); }
.mk:hover .tipbox, .mk:focus-visible .tipbox { display:block; }
.todayl { position:absolute; top:-4px; bottom:-4px; right:0; border-right:2px solid var(--k-text); opacity:.5; }
.never { position:absolute; left:0; right:0; top:11px; height:14px; border-radius:3px; border:1px dashed rgb(var(--h-sev-high, 217 122 26)); text-align:center; font-size:10.5px; font-weight:700; line-height:12px; color:rgb(var(--h-status-warning, 180 83 9)); }
@media (max-width:760px) { .cr, .ca { grid-template-columns:minmax(110px, 140px) minmax(360px, 1fr); } }
`
    );
  }

  protected view(): string {
    if (this._rows.length === 0 || this._from === '' || this._to === '')
      return this.emptyCard(this._heading, 'No scans in this window.');
    const from = t(this._from);
    const to = t(this._to);
    const span = to - from;
    const x = (ms: number): number => Math.max(0, Math.min(100, ((ms - from) / span) * 100));
    const cadence = this._cadence * DAY;

    // Weekly ticks, anchored to the window end so "today" is always a tick.
    const ticks: number[] = [];
    for (let ms = to; ms >= from; ms -= 7 * DAY) ticks.unshift(ms);
    const tickLabel = (ms: number): string =>
      ms === to ? 'Today' : new Date(ms).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });

    let stale = 0;
    let never = 0;
    let scans = 0;
    let proven = 0;
    const rows = this._rows
      .map((r) => {
        const ev = [...r.events].sort((a, b) => t(a.at) - t(b.at));
        scans += ev.length;
        proven += ev.reduce((n, e) => n + e.proven, 0);
        const last = ev.length ? t(ev[ev.length - 1]!.at) : null;
        if (last === null) never += 1;
        else if (to - last > cadence) stale += 1;

        // A gap is the time between one scan and the next (or today) that runs past the
        // cadence. It starts when the cadence expired, not when the scan finished. Time
        // before the first scan is not a gap: the application may not have been onboarded.
        const gaps: string[] = [];
        const marksAt = [...ev.map((e) => t(e.at)), to];
        for (let i = 0; i < marksAt.length - 1; i += 1) {
          const start = marksAt[i]!;
          const end = marksAt[i + 1]!;
          if (end - start <= cadence) continue;
          const gs = start + cadence;
          const w = x(end) - x(gs);
          gaps.push(
            `<span class="gap hatch" style="left:${x(gs)}%;width:${w}%"></span>${
              w > 9 ? `<span class="gaplbl" style="left:${x(gs) + w / 2}%">${Math.round((end - start) / DAY)} d without a scan</span>` : ''
            }`,
          );
        }

        const marks = ev
          .map((e) => {
            const word = e.coverage === 'full' ? 'All required scanners ran' : e.coverage === 'partial' ? 'Some required scanners did not run' : 'The scan failed';
            const tip = `<b>${esc(e.label ?? (e.kind === 'pr' ? 'Pull request scan' : 'Full scan'))}</b><br>${esc(
              new Date(t(e.at)).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }),
            )}<br>${word}<br>${e.proven > 0 ? `${e.proven} exploit${e.proven === 1 ? '' : 's'} proven` : 'No exploit proven'}${
              e.candidates ? ` · ${e.candidates} candidates` : ''
            }`;
            return `<button type="button" class="mk ${e.coverage} ${e.kind === 'pr' ? 'pr' : ''}" style="left:${x(t(e.at))}%" data-scan="${esc(e.id)}" data-app="${esc(r.id)}" aria-label="${esc(r.label)}: ${esc(word)}${e.proven > 0 ? `, ${e.proven} proven` : ''}">${
              e.proven > 0 ? '<span class="dia"></span>' : ''
            }<span class="tipbox" role="tooltip">${tip}</span></button>`;
          })
          .join('');

        const lv = LEVEL_WORD[r.level].word;
        const lamp = r.level === 'action' ? 'bad' : r.level === 'attention' ? 'warn' : r.level === 'clear' ? 'ok' : 'off';
        const track =
          ev.length === 0
            ? `<span class="never">Never scanned</span>`
            : `${ticks.map((tk) => `<span class="gl" style="left:${x(tk)}%"></span>`).join('')}${gaps.join('')}${marks}`;
        return `<div class="cr"><button type="button" class="who" data-app="${esc(r.id)}"><span class="lamp ${lamp}"></span><span><span class="nm">${esc(r.label)}</span><br><span class="sb">${esc(r.sub ?? '')}${r.sub ? ' · ' : ''}<span class="lv">${esc(lv)}</span></span></span></button>
          <div class="ctrack">${track}</div></div>`;
      })
      .join('');

    const days = Math.round(span / DAY);
    const title =
      never + stale === 0
        ? `Every application was scanned within ${this._cadence} days`
        : `${stale + never} of ${this._rows.length} applications are past the ${this._cadence}-day scan cadence`;
    const stats: KitStat[] = [
      { text: `${this._rows.length - stale - never} on cadence`, tone: 'ok', icon: 'check' },
      ...(stale > 0 ? [{ text: `${stale} stale`, tone: 'warn' as const, icon: 'clock' }] : []),
      ...(never > 0 ? [{ text: `${never} never scanned`, tone: 'bad' as const, icon: 'circle-x' }] : []),
    ];
    const axis = `<div class="ca"><div>Application</div><div class="ticks">${ticks
      .map((tk) => `<span class="tick" style="left:${x(tk)}%">${tickLabel(tk)}</span>`)
      .join('')}</div></div>`;

    return `<div class="card">${this.head(this._heading, title, {
      sub: `${scans} scans in ${days} days · ${proven} exploit${proven === 1 ? '' : 's'} proven · policy cadence ${this._cadence} days`,
      stats,
    })}<div class="cont" role="group" aria-label="${esc(this._heading)}">${axis}${rows}</div>
      <div class="body" style="padding-top:0">${legend([
        { label: 'Full scan, all required scanners', color: 'rgb(var(--h-verdant-600, 59 96 71))' },
        { label: 'Partial coverage', color: 'var(--k-surface)', swatchStyle: 'border:2px solid rgb(var(--h-sev-high, 217 122 26))' },
        { label: 'Failed', color: 'var(--k-bad-soft)', swatchStyle: 'border:2px solid var(--k-sev-critical)' },
        { label: 'Exploit proven', color: 'var(--k-sev-critical)', swatchStyle: 'transform:rotate(45deg);border-radius:1px' },
        { label: 'Past cadence', color: 'rgb(var(--h-sev-high, 217 122 26) / .55)' },
      ])}</div>${this.foot()}</div>`;
  }

  protected afterRender(): void {
    const fire = (type: string, detail: Record<string, string | undefined>): void => {
      this.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true }));
    };
    for (const b of this.root.querySelectorAll<HTMLElement>('.who'))
      b.addEventListener('click', () => fire('docket:open-app', { id: b.dataset['app'] }));
    for (const b of this.root.querySelectorAll<HTMLElement>('.mk'))
      b.addEventListener('click', () => fire('docket:open-scan', { id: b.dataset['scan'], app: b.dataset['app'] }));
  }
}

defineElement('docket-continuum', DocketContinuum);
void KIT_STYLE;
