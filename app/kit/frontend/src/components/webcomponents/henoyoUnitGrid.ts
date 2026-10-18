// <henoyo-unit-grid>: one square per record, coloured by severity band.

import { kitLocale } from './colourScheme';
import { HenoyoElement, defineElement, emit, esc, legend, truncatedSpan } from './henoyoKit';
import { BANDS, bandWord, summarySentence, type SeverityBand } from './severityBands';

export interface UnitDetail {
  label: string;
  value: string;
}

export interface UnitSquare {
  id: string;
  recordId: string;
  objectApiName: string;
  label: string;
  band: SeverityBand;
  details: UnitDetail[];
}

const DEFAULT_SHARE: SeverityBand[] = ['critical', 'high'];

function bandColor(band: SeverityBand): string {
  return band === 'other' ? 'var(--k-hairline-2)' : `var(--k-sev-${band})`;
}

/** The finding: how many squares are critical and how many are high. */
export function unitGridFinding(squares: readonly { band: SeverityBand }[]): string {
  const count = (band: SeverityBand): number => squares.filter((s) => s.band === band).length;
  const critical = count('critical');
  const high = count('high');
  if (critical + high === 0) return 'None critical or high';
  return `${critical.toLocaleString(kitLocale())} critical · ${high.toLocaleString(kitLocale())} high`;
}

function isBand(value: unknown): value is SeverityBand {
  return typeof value === 'string' && (BANDS as readonly string[]).includes(value);
}

export class HenoyoUnitGrid extends HenoyoElement {
  private _heading: string | undefined;
  private _squares: UnitSquare[] = [];
  private _share: SeverityBand[] = DEFAULT_SHARE;
  private _shareLabel = 'critical or high';
  private _truncated = false;
  private _selected: string | undefined;

  constructor() {
    super();
    this.root.addEventListener('click', (event) => {
      const target = (event.target as Element | null)?.closest<HTMLElement>('[data-act]');
      const act = target?.dataset.act;
      if (act === 'square') {
        const id = target?.dataset.id ?? '';
        this._selected = this._selected === id ? undefined : id;
        this.invalidate();
        return;
      }
      if (act === 'close') {
        this._selected = undefined;
        this.invalidate();
        return;
      }
      if (act === 'goto') {
        const square = this._squares.find((item) => item.id === this._selected);
        if (square === undefined || square.recordId === '') return;
        emit(this, 'henoyo:open-record', {
          objectApiName: square.objectApiName,
          recordId: square.recordId,
        });
      }
    });
  }

  get heading(): string | undefined {
    return this._heading;
  }
  set heading(value: string | undefined) {
    this._heading = value;
    this.invalidate();
  }

  get squares(): UnitSquare[] {
    return this._squares;
  }
  set squares(value: UnitSquare[]) {
    this._squares = Array.isArray(value)
      ? value.filter((item) => item != null && isBand(item.band))
      : [];
    if (this._selected !== undefined && !this._squares.some((item) => item.id === this._selected)) {
      this._selected = undefined;
    }
    this.invalidate();
  }

  get shareBands(): SeverityBand[] {
    return this._share;
  }
  set shareBands(value: SeverityBand[] | undefined) {
    this._share =
      value === undefined ? DEFAULT_SHARE : Array.isArray(value) ? value.filter(isBand) : [];
    this.invalidate();
  }

  get shareLabel(): string {
    return this._shareLabel;
  }
  set shareLabel(value: string | undefined) {
    this._shareLabel = value === undefined ? 'critical or high' : value;
    this.invalidate();
  }

  get truncated(): boolean {
    return this._truncated;
  }
  set truncated(value: boolean | undefined) {
    this._truncated = value === true;
    this.invalidate();
  }

  protected styles(): string {
    return `
.stage { display:flex; gap:18px; align-items:flex-start; }
.gridwrap { flex:1; min-width:0; }
.cells { list-style:none; display:flex; flex-wrap:wrap; gap:3px; margin:0; padding:0; }
.sq { width:14px; height:14px; padding:0; border:0; border-radius:3px; cursor:pointer; background:var(--sq); }
.sq[aria-pressed="true"] { outline:2px solid var(--k-brand); outline-offset:1px; }
.panel { width:240px; flex:none; border-left:1px solid var(--k-hairline); padding-left:16px; }
.panel h4 { margin:0; font-size:14px; font-weight:600; }
.word { display:flex; align-items:center; gap:6px; margin:6px 0 10px; font-size:12px; color:var(--k-text-2); }
dl { margin:0; }
.rowline { display:grid; gap:2px; margin:0 0 8px; }
dt { font-size:11px; color:var(--k-text-3); }
dd { margin:0; font-size:13px; }
.panel-actions { display:flex; gap:10px; align-items:center; margin-top:12px; }
@media (max-width: 720px) {
  .stage { flex-direction:column; }
  .panel { width:auto; border-left:0; border-top:1px solid var(--k-hairline); padding:12px 0 0; }
}
`;
  }

  protected view(): string {
    const squares = this._squares;
    const eyebrow = this._heading ?? 'Severity';
    if (squares.length === 0) return this.emptyCard(eyebrow, 'No records to grade');
    const notable = squares.filter((square) => this._share.includes(square.band)).length;
    const cells = squares
      .map((square) => {
        const word = bandWord(square.band);
        const pressed = square.id === this._selected ? 'true' : 'false';
        const summary = `${square.label} — ${word}`;
        return `<li><button type="button" class="sq ${square.band}" style="--sq:${bandColor(square.band)}" data-act="square" data-id="${esc(square.id)}" aria-pressed="${pressed}" aria-label="${esc(summary)}" title="${esc(summary)}"><span class="sr">${esc(word)}</span></button></li>`;
      })
      .join('');
    const items = BANDS.filter((band) => squares.some((square) => square.band === band)).map(
      (band) => ({
        label: bandWord(band),
        color: bandColor(band),
        count: squares.filter((square) => square.band === band).length.toLocaleString(kitLocale()),
      }),
    );
    const selected = squares.find((square) => square.id === this._selected);
    const panel =
      selected === undefined
        ? ''
        : `<aside class="panel" aria-label="Record detail">
            <h4>${esc(selected.label)}</h4>
            <p class="word"><span class="sw" style="background:${bandColor(selected.band)}"></span>${esc(bandWord(selected.band))}</p>
            ${
              selected.details.length === 0
                ? ''
                : `<dl>${selected.details
                    .map(
                      (detail) =>
                        `<div class="rowline"><dt>${esc(detail.label)}</dt><dd>${esc(detail.value)}</dd></div>`,
                    )
                    .join('')}</dl>`
            }
            <div class="panel-actions">
              ${
                selected.recordId === ''
                  ? ''
                  : '<button type="button" class="btn primary" data-act="goto">Open record</button>'
              }
              <button type="button" class="linkbtn" data-act="close">Close</button>
            </div>
          </aside>`;
    return `<div class="card">${this.head(eyebrow, unitGridFinding(squares), {
      sub: summarySentence(squares.length, notable, this._shareLabel),
    })}
      <div class="body">
        <div class="stage">
          <div class="gridwrap">
            <ul class="cells">${cells}</ul>
            ${legend(items)}
          </div>
          ${panel}
        </div>
      </div>
      ${this.foot(truncatedSpan(this._truncated))}
    </div>`;
  }
}

defineElement('henoyo-unit-grid', HenoyoUnitGrid);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-unit-grid': HenoyoUnitGrid;
  }
}
