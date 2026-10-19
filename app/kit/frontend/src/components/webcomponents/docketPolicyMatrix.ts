// <docket-policy-matrix>: policy against reality. Columns are the scanners the policy
// requires, in the order it requires them; rows are applications; each cell says whether
// that scanner ran inside its window. A missing or stale cell is a policy breach.

import { HenoyoElement, defineElement, esc, KIT_STYLE, legend, type KitStat } from './henoyoKit';
import { DOCKET_STYLE, dg, originChip, type Origin } from './docketKit';

export interface MatrixScanner {
  id: string;
  label: string;
  tool?: string;
  origin: Origin;
  icon?: string;
}

export type CellState = 'ok' | 'stale' | 'missing' | 'na';

export interface MatrixCell {
  state: CellState;
  /** "2 d ago", "never". */
  ago?: string;
}

export interface MatrixRow {
  id: string;
  label: string;
  /** Criticality tier that selects which policy rule applies. */
  tier?: string;
  cells: Record<string, MatrixCell>;
  /** What the cells add up to: blocks (a proven exploit), flags (a required scanner missing) or nothing. */
  consequence?: { effect: 'blocks' | 'flags' | 'advises'; text: string } | null;
}

const WORD: Record<CellState, string> = { ok: 'Ran', stale: 'Stale', missing: 'Never ran', na: 'Not required' };

export class DocketPolicyMatrix extends HenoyoElement {
  private _heading = 'Required checks against the policy';
  private _scanners: MatrixScanner[] = [];
  private _rows: MatrixRow[] = [];
  private _window = 7;

  set heading(v: string | undefined) {
    this._heading = v ?? 'Required checks against the policy';
    this.invalidate();
  }
  set scanners(v: MatrixScanner[]) {
    this._scanners = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  set rows(v: MatrixRow[]) {
    this._rows = Array.isArray(v) ? v : [];
    this.invalidate();
  }
  set windowDays(v: number | undefined) {
    this._window = v ?? 7;
    this.invalidate();
  }

  protected styles(): string {
    return (
      DOCKET_STYLE +
      `
.pm { padding:0 var(--h-kit-pad, 22px) 8px; overflow-x:auto; }
.pm table { border-collapse:separate; border-spacing:0 4px; width:100%; min-width:760px; }
.pm th { text-align:left; vertical-align:bottom; padding:4px 6px 8px; font-weight:600; font-size:12px; }
.pm th .seq { display:inline-grid; place-items:center; width:18px; height:18px; border-radius:999px; background:var(--k-text); color:var(--k-surface); font-size:10.5px; font-weight:700; margin-right:6px; }
.pm th .sn { display:flex; align-items:center; margin-bottom:5px; white-space:nowrap; }
.pm td.app { padding:6px 10px 6px 0; min-width:190px; }
.pm td.app button { all:unset; cursor:pointer; display:block; box-sizing:border-box; }
.pm td.app button:hover .nm { text-decoration:underline; }
.pm .nm { font-size:13px; font-weight:600; } .pm .tr { font-size:11.5px; color:var(--k-text-3); }
.pm td.c { padding:0 3px; width:1%; }
.cell { display:flex; align-items:center; gap:6px; height:38px; padding:0 9px; border-radius:8px; font-size:12px; font-weight:600; white-space:nowrap; }
.cell small { font-weight:500; opacity:.85; }
.cell.ok { background:var(--k-ok-soft); color:var(--k-ok); }
.cell.stale { background:rgb(var(--h-status-warning-soft, 255 251 235)); color:rgb(var(--h-status-warning, 180 83 9)); border:1px solid rgb(var(--h-sev-high, 217 122 26) / .55); }
.cell.missing { background:var(--k-bad-soft); color:var(--k-sev-critical); border:1.5px dashed var(--k-sev-critical); }
.cq { font-size:12.5px; min-width:170px; padding-left:10px; line-height:1.4; } .eff { display:inline-block; font-size:10.5px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; padding:1px 7px; border-radius:999px; margin-right:4px; }
.eff.blocks { background:var(--k-bad-soft); color:var(--k-sev-critical); border:1px solid var(--k-sev-critical); } .eff.flags { background:rgb(var(--h-status-warning-soft, 255 251 235)); color:rgb(var(--h-status-warning, 180 83 9)); border:1px solid rgb(var(--h-sev-high, 217 122 26) / .5); } .eff.advises { background:var(--k-neutral-soft); color:var(--k-neutral); }
.cell.na { background:transparent; color:var(--k-text-3); border:1px solid var(--k-hairline); font-weight:500; }
`
    );
  }

  protected view(): string {
    if (this._rows.length === 0 || this._scanners.length === 0)
      return this.emptyCard(this._heading, 'No policy is assigned to any application yet.');
    const meets = (r: MatrixRow): boolean =>
      this._scanners.every((s) => {
        const st = r.cells[s.id]?.state ?? 'na';
        return st === 'ok' || st === 'na';
      });
    const ok = this._rows.filter(meets).length;
    const breach = this._rows.length - ok;
    const title = `${ok} of ${this._rows.length} applications have every required check current`;
    const stats: KitStat[] = [
      { text: `${ok} current`, tone: 'ok', icon: 'check' },
      ...(breach > 0 ? [{ text: `${breach} lack a check`, tone: 'bad' as const, icon: 'triangle-alert' }] : []),
    ];
    const head = `<tr><th></th>${this._scanners
      .map(
        (s, i) =>
          `<th scope="col"><div class="sn"><span class="seq" aria-label="Step ${i + 1}">${i + 1}</span>${dg(s.icon ?? 'scan', 13)}&nbsp;${esc(s.label)}</div>${originChip(s.origin, s.tool)}</th>`,
      )
      .join('')}<th scope="col">Consequence</th></tr>`;
    const body = this._rows
      .map((r) => {
        const cells = this._scanners
          .map((s) => {
            const c = r.cells[s.id] ?? { state: 'na' as CellState };
            const icon = c.state === 'ok' ? 'check' : c.state === 'stale' ? 'clock' : c.state === 'missing' ? 'x' : 'minus';
            return `<td class="c"><div class="cell ${c.state}" aria-label="${esc(s.label)}: ${WORD[c.state]}${c.ago ? ', ' + esc(c.ago) : ''}">${dg(icon, 13)}${WORD[c.state]}${
              c.ago && c.state !== 'na' ? ` <small>${esc(c.ago)}</small>` : ''
            }</div></td>`;
          })
          .join('');
        const c = r.consequence && r.consequence.text !== '' ? r.consequence : null;
        const conseq = c
          ? `<td class="cq"><span class="eff ${c.effect}">${c.effect === 'blocks' ? 'Blocks' : c.effect === 'flags' ? 'Flags' : 'Advises'}</span> ${esc(c.text)}</td>`
          : `<td class="cq muted">None</td>`;
        return `<tr><td class="app"><button type="button" data-app="${esc(r.id)}"><span class="nm">${esc(r.label)}</span><br><span class="tr">${esc(r.tier ?? '')}</span></button></td>${cells}${conseq}</tr>`;
      })
      .join('');
    return `<div class="card">${this.head(this._heading, title, {
      sub: `A scanner counts as having run if it finished within ${this._window} days.`,
      stats,
    })}<div class="pm"><table><thead>${head}</thead><tbody>${body}</tbody></table></div>
      <div class="body" style="padding-top:6px">${legend([
        { label: 'Ran inside its window', color: 'var(--k-ok-soft)' },
        { label: 'Stale', color: 'rgb(var(--h-sev-high-soft, 255 251 235))', swatchStyle: 'border:1px solid rgb(var(--h-sev-high, 217 122 26))' },
        { label: 'Never ran', color: 'var(--k-bad-soft)', swatchStyle: 'border:1.5px dashed var(--k-sev-critical)' },
      ])}</div>${this.foot()}</div>`;
  }

  protected afterRender(): void {
    for (const b of this.root.querySelectorAll<HTMLElement>('[data-app]'))
      b.addEventListener('click', () =>
        this.dispatchEvent(new CustomEvent('docket:open-app', { detail: { id: b.dataset['app'] }, bubbles: true, composed: true })),
      );
  }
}

defineElement('docket-policy-matrix', DocketPolicyMatrix);
void KIT_STYLE;
