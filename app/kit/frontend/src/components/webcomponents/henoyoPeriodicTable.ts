// <henoyo-periodic-table>: an authored grid of tiles, one report measure per tile.

import { kitLocale } from './colourScheme';
import { HenoyoElement, defineElement, emit, esc, legend } from './henoyoKit';

import type { PeriodicModel, PeriodicTile } from './periodicTable.model';

const HEX = /^#[0-9A-Fa-f]{6}$/;

function isTile(value: unknown): value is PeriodicTile {
  if (value === null || typeof value !== 'object') return false;
  const tile = value as PeriodicTile;
  return (
    typeof tile.key === 'string' && typeof tile.row === 'string' && typeof tile.column === 'string'
  );
}

/** The finding: how many applicable categories have a value above zero. */
export function periodicFinding(tiles: readonly PeriodicTile[]): string {
  const applicable = tiles.filter((tile) => !tile.notApplicable);
  const work = applicable.filter((tile) => (tile.value ?? 0) > 0).length;
  if (applicable.length === 0) return 'No categories to show';
  return `${work} of ${applicable.length} categories have open findings`;
}

export class HenoyoPeriodicTable extends HenoyoElement {
  constructor() {
    super();
    this.root.addEventListener('click', (event) => {
      this.onClick(event);
    });
  }

  private _heading: string | undefined;
  private _model: PeriodicModel | null = null;
  private _framed = true;
  private _selectedKey = '';

  get heading(): string | undefined {
    return this._heading;
  }
  set heading(value: string | undefined) {
    this._heading = typeof value === 'string' && value !== '' ? value : undefined;
    this.invalidate();
  }

  get model(): PeriodicModel | null {
    return this._model;
  }
  set model(value: PeriodicModel | null | undefined) {
    if (value == null || !Array.isArray(value.rows) || !Array.isArray(value.columns)) {
      this._model = null;
    } else {
      this._model = {
        ...value,
        tiles: Array.isArray(value.tiles) ? value.tiles.filter(isTile) : [],
        measures: Array.isArray(value.measures) ? value.measures : [],
      };
    }
    this.invalidate();
  }

  get framed(): boolean {
    return this._framed;
  }
  set framed(value: boolean | undefined) {
    this._framed = value !== false;
    this.invalidate();
  }

  get selectedKey(): string {
    return this._selectedKey;
  }
  set selectedKey(value: string | undefined) {
    this._selectedKey = typeof value === 'string' ? value : '';
    this.invalidate();
  }

  protected styles(): string {
    return `
.wrap { display:flex; flex-direction:column; gap:12px; }
.scroll { overflow-x:auto; }
.grid { width:100%; min-width:calc(var(--cols, 1) * 104px + 96px); border-collapse:separate; border-spacing:6px; table-layout:fixed; }
.ax { font-size:11px; color:var(--k-text-3); font-weight:600; }
.ax.row { text-align:right; vertical-align:middle; }
.hint { display:block; font-weight:400; }
.tile { position:relative; display:flex; flex-direction:column; justify-content:space-between; gap:6px; width:100%; min-height:76px; min-width:0; padding:8px 8px 8px 14px; text-align:left; background:var(--k-surface); border:1px solid var(--k-hairline); border-radius:6px; color:inherit; }
.tile::before { content:""; position:absolute; left:0; top:0; bottom:0; width:4px; border-radius:6px 0 0 6px; background:var(--rail, transparent); }
.tile[aria-pressed="true"] { outline:2px solid var(--k-brand); outline-offset:1px; }
.tile:disabled { color:var(--k-text-3); border-style:dashed; cursor:default; }
.top { display:flex; align-items:baseline; justify-content:space-between; gap:8px; }
.sym { white-space:nowrap; font-variant-numeric:tabular-nums; font-size:13px; font-weight:600; }
.lab { display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; overflow:hidden; overflow-wrap:break-word; hyphens:none; font-size:12px; line-height:1.3; color:var(--k-text-2); }
.num { white-space:nowrap; font-variant-numeric:tabular-nums; font-size:14px; font-weight:600; }
.toggle { display:flex; justify-content:center; }
.toggle div { display:flex; border:1px solid var(--k-hairline-2); border-radius:999px; overflow:hidden; }
.toggle button { padding:4px 12px; background:transparent; color:var(--k-text-2); font-size:12px; }
.toggle button[aria-pressed="true"] { background:var(--k-text); color:var(--k-surface); }
.note { margin:0; text-align:center; }
`;
  }

  protected view(): string {
    const eyebrow = this._heading ?? 'Coverage';
    const model = this._model;
    if (!this._framed) {
      const body =
        model === null
          ? `<div class="empty">Nothing to show yet.</div>`
          : model.emptyLayout
            ? `<div class="empty">This report has no tile layout. Add one on the report's chart.</div>`
            : this.grid(model);
      return `<div class="wrap">${body}</div>`;
    }
    if (model === null) return this.emptyCard(eyebrow, 'Nothing to show yet');
    if (model.emptyLayout)
      return this.emptyCard(
        eyebrow,
        'No tile layout yet',
        "This report has no tile layout. Add one on the report's chart.",
      );
    return `<div class="card">${this.head(eyebrow, periodicFinding(model.tiles))}<div class="body"><div class="wrap">${this.grid(model)}</div></div>${this.foot()}</div>`;
  }

  private onClick(event: Event): void {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const measure = target.closest('[data-act="measure"]');
    if (measure instanceof HTMLElement) {
      const id = measure.dataset['id'] ?? '';
      if (id !== '') emit(this, 'henoyo:measure', { id });
      return;
    }
    const tile = target.closest('[data-act="tile"]');
    if (!(tile instanceof HTMLElement) || tile.dataset['selectable'] !== 'true') return;
    emit(this, 'henoyo:tile-selected', {
      key: tile.dataset['key'] ?? '',
      label: tile.dataset['label'] ?? '',
    });
  }

  private grid(model: PeriodicModel): string {
    const heads = model.columns
      .map(
        (column) =>
          `<th scope="col" class="ax" data-capture-text="${esc(column.label)}">${esc(column.label)}${this.hint(column.hint)}</th>`,
      )
      .join('');
    const body = model.rows
      .map((row) => {
        const cells = model.columns
          .map((column) => {
            const tile = model.tiles.find(
              (item) => item.row === row.key && item.column === column.key,
            );
            if (tile === undefined) return `<td data-capture-text=""></td>`;
            return `<td data-capture-text="${esc(this.capture(tile))}">${this.button(tile)}</td>`;
          })
          .join('');
        return `<tr><th scope="row" class="ax row" data-capture-text="${esc(row.label)}">${esc(row.label)}${this.hint(row.hint)}</th>${cells}</tr>`;
      })
      .join('');
    const toggle =
      model.measures.length < 2
        ? ''
        : `<div class="toggle"><div role="group" aria-label="Tile measure">${model.measures
            .map(
              (measure) =>
                `<button type="button" data-act="measure" data-id="${esc(measure.id)}" aria-pressed="${measure.id === model.activeId}">${esc(measure.label)}</button>`,
            )
            .join('')}</div></div>`;
    const notes: string[] = [];
    if (model.truncated) {
      notes.push(
        `Showing the first ${model.shownGroups.toLocaleString(kitLocale())} groups — some tiles may be short.`,
      );
    }
    if (model.multiselect) {
      notes.push(
        'One record can sit on more than one tile, so the tiles do not add up to the total.',
      );
    }
    if (model.unmapped > 0) {
      notes.push(
        `${model.unmapped.toLocaleString(kitLocale())} ${model.unmapped === 1 ? 'value has' : 'values have'} no tile on this grid.`,
      );
    }
    const note = notes.length === 0 ? '' : `<p class="note">${esc(notes.join(' '))}</p>`;
    return `<div class="scroll"><table class="grid" style="--cols:${model.columns.length}"><thead><tr><th></th>${heads}</tr></thead><tbody>${body}</tbody></table></div>${toggle}${note}${this.key(model)}`;
  }

  private key(model: PeriodicModel): string {
    if (!model.tiles.some((tile) => tile.notApplicable)) return '';
    return legend([
      {
        label: 'Not applicable: this category does not apply here, so it is not counted',
        color: 'transparent',
        swatchStyle: 'border:1px dashed var(--k-text-3)',
      },
    ]);
  }

  private hint(text: string): string {
    return text === '' ? '' : `<span class="hint">${esc(text)}</span>`;
  }

  private capture(tile: PeriodicTile): string {
    if (tile.notApplicable) return 'n/a';
    const name = tile.label === '' ? tile.symbol : `${tile.symbol} ${tile.label}`;
    return `${name}: ${tile.valueText}`;
  }

  private button(tile: PeriodicTile): string {
    const color = tile.color !== null && HEX.test(tile.color) ? tile.color : '';
    const rail = color === '' ? '' : ` style="--rail:${color}"`;
    const pressed = this._selectedKey !== '' && this._selectedKey === tile.key;
    const name = tile.label === '' ? tile.symbol : tile.label;
    const title = tile.notApplicable ? `${name} — Not applicable` : `${name}: ${tile.valueText}`;
    return `<button type="button" class="tile" data-act="tile" data-key="${esc(tile.key)}" data-label="${esc(name)}" data-selectable="${tile.selectable}" aria-pressed="${pressed}"${tile.notApplicable ? ' disabled' : ''}${rail} title="${esc(title)}" aria-label="${esc(title)}"><span class="top"><span class="sym">${tile.notApplicable ? '' : esc(tile.symbol)}</span><span class="num">${esc(tile.valueText)}</span></span><span class="lab">${esc(tile.label)}</span></button>`;
  }
}

defineElement('henoyo-periodic-table', HenoyoPeriodicTable);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-periodic-table': HenoyoPeriodicTable;
  }
}
