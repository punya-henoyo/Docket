// <henoyo-exposure-tree>: lazily loaded hierarchy with risk rolled up at every level.

import {
  HenoyoElement,
  SEVERITY_ORDER,
  chip,
  defineElement,
  downloadCsv,
  emit,
  esc,
  truncatedSpan,
  humanize,
  isMaterial,
  severityVar,
  type Material,
} from './henoyoKit';

export interface ExposureColumn {
  key: string;
  label: string;
  format?: 'count' | 'severity';
}

export type ExposureMetrics = Record<string, number | string | undefined>;

export interface ExposureNode {
  id: string;
  objectApiName: string;
  /** The record Open navigates to, when the node id is not the record id. */
  recordId?: string;
  /** False when the record's object is unknown, so there is nothing to open. */
  openable?: boolean;
  label: string;
  sublabel?: string;
  material: Material;
  glyphName: string;
  edgeLabel?: string;
  metrics?: ExposureMetrics;
  childCount: number;
  truncated?: boolean;
  sharedCount?: number;
  children?: ExposureNode[];
}

interface Row {
  node: ExposureNode;
  level: number;
  path: string[];
  cycle?: boolean;
}

const COL_W = 120;

function metricsOf(n: ExposureNode): ExposureMetrics {
  return n.metrics && typeof n.metrics === 'object' ? n.metrics : {};
}

function kidsOf(n: ExposureNode): ExposureNode[] {
  return Array.isArray(n.children)
    ? n.children.filter((c) => c && typeof c === 'object' && typeof c.id === 'string')
    : [];
}

function hasKidsOf(n: ExposureNode): boolean {
  return Number(n.childCount) > 0;
}

function sevRank(s: unknown): number {
  const i = SEVERITY_ORDER.indexOf(String(s ?? '').toLowerCase());
  return i < 0 ? SEVERITY_ORDER.length : i;
}

function numOf(v: unknown): number {
  return typeof v === 'number' ? v : 0;
}

function countCell(v: unknown): string {
  return numOf(v) > 0 ? String(v) : '<span class="muted" aria-label="none">–</span>';
}

export class HenoyoExposureTree extends HenoyoElement {
  private _heading: string | undefined;
  private _truncated = false;
  private _columns: ExposureColumn[] = [];
  private _root: ExposureNode | undefined;
  private _pageSize = 25;
  private _exportEnabled: boolean | undefined;
  private expanded = new Set<string>();
  private loading = new Set<string>();
  private pages = new Map<string, number>();
  private focusId: string | undefined;
  private refocus = false;
  private gen = 0;

  constructor() {
    super();
    this.root.addEventListener('click', (e) => this.onClick(e));
    this.root.addEventListener('keydown', (e) => this.onKey(e as KeyboardEvent));
    this.root.addEventListener('focusin', (e) => {
      const id = (e.target as Element).closest<HTMLElement>('[data-row]')?.dataset.row;
      if (id !== undefined) this.focusId = id;
    });
  }

  protected invalidate(): void {
    if (this.root.activeElement) this.refocus = true;
    super.invalidate();
  }

  get truncated(): boolean {
    return this._truncated;
  }
  set truncated(v: boolean | undefined) {
    this._truncated = v === true;
    this.invalidate();
  }
  get heading(): string | undefined {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v;
    this.invalidate();
  }

  get columns(): ExposureColumn[] {
    return this._columns;
  }
  set columns(v: ExposureColumn[] | undefined) {
    this._columns = Array.isArray(v)
      ? v.filter((c) => c && typeof c === 'object' && typeof c.key === 'string')
      : [];
    this.invalidate();
  }

  private sevKey(): string | undefined {
    return this._columns.find((c) => c.format === 'severity')?.key;
  }

  private countKey(): string | undefined {
    return this._columns.find((c) => c.format !== 'severity')?.key;
  }

  private sortChildren(list: ExposureNode[]): ExposureNode[] {
    const sk = this.sevKey();
    const ck = this.countKey();
    return [...list].sort(
      (a, b) =>
        (sk ? sevRank(metricsOf(a)[sk]) - sevRank(metricsOf(b)[sk]) : 0) ||
        (ck ? numOf(metricsOf(b)[ck]) - numOf(metricsOf(a)[ck]) : 0),
    );
  }

  get pageSize(): number {
    return this._pageSize;
  }
  set pageSize(v: number | undefined) {
    this._pageSize = v && v > 0 ? Math.floor(v) : 25;
    this.invalidate();
  }

  get exportEnabled(): boolean | undefined {
    return this._exportEnabled;
  }
  set exportEnabled(v: boolean | undefined) {
    this._exportEnabled = v;
    this.invalidate();
  }

  get rootNode(): ExposureNode | undefined {
    return this._root;
  }
  set rootNode(v: ExposureNode | undefined) {
    this.setRoot(v);
  }

  setRoot(v: ExposureNode | undefined): void {
    const gen = ++this.gen;
    this._root = v && typeof v === 'object' && typeof v.id === 'string' ? v : undefined;
    this.expanded.clear();
    this.loading.clear();
    this.pages.clear();
    const r = this._root;
    this.focusId = r?.id;
    if (r) {
      this.expanded.add(r.id);
      if (hasKidsOf(r) && !Array.isArray(r.children)) {
        this.loading.add(r.id);
        queueMicrotask(() => {
          if (gen === this.gen)
            emit(this, 'henoyo:expand', { id: r.id, objectApiName: r.objectApiName });
        });
      }
    }
    this.invalidate();
  }

  setChildren(id: string, children: ExposureNode[], truncated?: boolean): void {
    if (!Array.isArray(children)) return;
    const node = this.find(id);
    if (!node) return;
    node.children = children;
    node.truncated = truncated ?? false;
    this.loading.delete(id);
    this.expanded.add(id);
    this.invalidate();
  }

  private find(id: string): ExposureNode | undefined {
    const seen = new Set<ExposureNode>();
    const walk = (n: ExposureNode): ExposureNode | undefined => {
      if (n.id === id) return n;
      if (seen.has(n)) return undefined;
      seen.add(n);
      for (const c of kidsOf(n)) {
        const hit = walk(c);
        if (hit) return hit;
      }
      return undefined;
    };
    return this._root ? walk(this._root) : undefined;
  }

  private visibleRows(): Row[] {
    const out: Row[] = [];
    const walk = (n: ExposureNode, level: number, path: string[], anc: Set<string>): void => {
      const here = [...path, n.label];
      if (anc.has(n.id)) {
        out.push({ node: n, level, path: here, cycle: true });
        return;
      }
      out.push({ node: n, level, path: here });
      if (!this.expanded.has(n.id) || !Array.isArray(n.children)) return;
      const next = new Set(anc).add(n.id);
      const shown = (this.pages.get(n.id) ?? 1) * this._pageSize;
      for (const c of this.sortChildren(kidsOf(n)).slice(0, shown)) walk(c, level + 1, here, next);
    };
    if (this._root) walk(this._root, 1, [], new Set());
    return out;
  }

  private expand(id: string): void {
    const n = this.find(id);
    if (!n || !hasKidsOf(n) || this.expanded.has(id)) return;
    this.expanded.add(id);
    if (!Array.isArray(n.children)) {
      this.loading.add(id);
      emit(this, 'henoyo:expand', { id, objectApiName: n.objectApiName });
    }
    this.invalidate();
  }

  private collapse(id: string): void {
    if (this.expanded.delete(id)) this.invalidate();
  }

  private toggle(id: string): void {
    this.focusId = id;
    this.refocus = true;
    if (this.expanded.has(id)) this.collapse(id);
    else this.expand(id);
  }

  private onClick(e: Event): void {
    const t = (e.target as Element).closest<HTMLElement>('[data-act]');
    if (!t) return;
    const arg = t.dataset.arg ?? '';
    if (t.dataset.act === 'toggle') this.toggle(arg);
    else if (t.dataset.act === 'open') {
      const n = this.find(arg);
      if (n)
        emit(this, 'henoyo:open-record', {
          objectApiName: n.objectApiName,
          recordId: n.recordId ?? arg,
        });
    } else if (t.dataset.act === 'more') {
      this.focusId = arg;
      this.refocus = true;
      this.pages.set(arg, (this.pages.get(arg) ?? 1) + 1);
      this.invalidate();
    } else if (t.dataset.act === 'export') this.exportCsv();
  }

  private focusRow(id: string): void {
    this.focusId = id;
    this.root
      .querySelectorAll<HTMLElement>('[data-row]')
      .forEach((el) => el.setAttribute('tabindex', el.dataset.row === id ? '0' : '-1'));
    this.root.querySelector<HTMLElement>(`[data-row="${CSS.escape(id)}"]`)?.focus();
  }

  private onKey(e: KeyboardEvent): void {
    const target = e.target as Element;
    const rowEl = target.closest<HTMLElement>('[data-row]');
    if (!rowEl || target !== rowEl) return;
    const id = rowEl.dataset.row ?? '';
    const rows = this.visibleRows();
    const i = rows.findIndex((r) => r.node.id === id);
    const row = rows[i];
    if (!row) return;
    const goto = (to: number): void => {
      const r = rows[Math.max(0, Math.min(rows.length - 1, to))];
      if (r) this.focusRow(r.node.id);
    };
    const kids = hasKidsOf(row.node) && !row.cycle;
    const open = this.expanded.has(id);
    if (e.key === 'ArrowDown') goto(i + 1);
    else if (e.key === 'ArrowUp') goto(i - 1);
    else if (e.key === 'ArrowRight') {
      if (!kids) return;
      if (!open) this.toggle(id);
      else if ((rows[i + 1]?.level ?? 0) > row.level) goto(i + 1);
    } else if (e.key === 'ArrowLeft') {
      if (kids && open) this.toggle(id);
      else
        for (let j = i - 1; j >= 0; j--) {
          if ((rows[j]?.level ?? 99) < row.level) {
            goto(j);
            break;
          }
        }
    } else if (e.key === 'Enter' || e.key === ' ') {
      if (kids) this.toggle(id);
    } else return;
    e.preventDefault();
  }

  private exportCsv(): void {
    downloadCsv(
      this,
      'exposure',
      ['Level', 'Path', 'Label', ...this._columns.map((c) => c.label)],
      this.visibleRows().map((r) => [
        r.level,
        r.path.join(' > '),
        r.node.label,
        ...this._columns.map((c) => metricsOf(r.node)[c.key]),
      ]),
    );
  }

  protected afterRender(): void {
    if (!this.refocus) return;
    this.refocus = false;
    if (this.focusId) this.focusRow(this.focusId);
  }

  private template(): string {
    return `minmax(0,1fr) repeat(${this._columns.length}, ${COL_W}px)`;
  }

  protected styles(): string {
    return `
.wrap { overflow-x:auto; padding:0 0 8px; }
.row { display:grid; align-items:center; gap:8px; padding:4px 22px; min-height:36px; border-top:1px solid var(--k-hairline); }
.row.hd { font-size:11px; letter-spacing:.08em; text-transform:uppercase; color:var(--k-text-3); font-weight:600; border-top:0; }
.row[data-row]:hover { background:var(--k-surface-2); }
.row[data-row]:focus-visible { outline-offset:-2px; }
.name { display:flex; align-items:center; gap:8px; min-width:0; }
.caret { width:24px; height:24px; flex:none; display:inline-grid; place-items:center; background:none; border:0; cursor:pointer; border-radius:6px; color:var(--k-text-2); }
.caret.none { visibility:hidden; pointer-events:none; }
.caret svg { transition:transform .15s; }
.caret[aria-expanded="true"] svg { transform:rotate(90deg); }
.lbl { min-width:7rem; flex:1 1 auto; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:13px; }
.lbl small { color:var(--k-text-3); margin-left:6px; font-size:11.5px; }
.tag { flex:none; font-size:11px; color:var(--k-text-3); border:1px solid var(--k-hairline); border-radius:999px; padding:1px 8px; white-space:nowrap; }
.openbtn { flex:none; margin-left:auto; min-height:24px; min-width:24px; padding:0 8px; border-radius:6px; }
.n { text-align:right; font-variant-numeric:tabular-nums; font-size:13px; }
.c { text-align:center; justify-self:center; }
.pill { border:1px solid currentColor; background:var(--k-surface); }
.load,.more { padding:6px 22px; font-size:12px; color:var(--k-text-3); border-top:1px solid var(--k-hairline); }
.more .linkbtn { min-height:28px; padding:0 8px; }
`;
  }

  protected view(): string {
    const root = this._root;
    if (!root) return this.emptyCard('Exposure', this._heading ?? 'Exposure');
    const cols = this._columns;
    const rm = metricsOf(root);
    const sev = cols.find((c) => c.format === 'severity');
    const counts = cols.filter((c) => c.format !== 'severity').slice(0, 2);
    const out = this.visibleRows()
      .map((r) => this.rowHtml(r))
      .join('');
    const tpl = this.template();
    const minW = 340 + cols.length * (COL_W + 8);
    const hd = cols
      .map(
        (c) =>
          `<span role="columnheader" class="${c.format === 'severity' ? 'c' : 'n'}">${esc(c.label)}</span>`,
      )
      .join('');
    return `<section class="card" aria-label="${esc(this._heading ?? 'Exposure')}">
      ${this.head(this._heading ?? 'Exposure', root.label, {
        actions: `${
          sev
            ? `<span class="stat">${esc(sev.label)} <span class="pill" style="color:${severityVar(String(rm[sev.key] ?? ''))}">${esc(humanize(String(rm[sev.key] ?? 'none')))}</span></span>`
            : ''
        }${counts.map((c) => `<span class="stat">${esc(c.label)} <b>${numOf(rm[c.key])}</b></span>`).join('')}${
          this._exportEnabled === false
            ? ''
            : '<button class="btn" data-act="export" type="button">Export CSV</button>'
        }`,
      })}
      <div class="wrap"><div class="grid" style="min-width:${minW}px" role="treegrid" aria-label="${esc(root.label)} exposure">
        <div class="row hd" role="row" style="grid-template-columns:${tpl}"><span role="columnheader">Name</span>${hd}</div>
        ${out}
      </div></div>${this.foot(truncatedSpan(this._truncated))}</section>`;
  }

  private cell(c: ExposureColumn, n: ExposureNode): string {
    const v = metricsOf(n)[c.key];
    if (c.format === 'severity')
      return `<div role="gridcell" class="c">${v ? `<span class="pill" style="color:${severityVar(String(v))}">${esc(humanize(String(v)))}</span>` : '<span class="muted">–</span>'}</div>`;
    return `<div role="gridcell" class="n">${typeof v === 'number' ? countCell(v) : esc(v ?? '')}</div>`;
  }

  private rowHtml(r: Row): string {
    const n = r.node;
    const open = this.expanded.has(n.id) && !r.cycle;
    const hasKids = hasKidsOf(n) && !r.cycle;
    const tab = n.id === (this.focusId ?? this._root?.id) ? 0 : -1;
    const material: Material = isMaterial(n.material) ? n.material : 'stone';
    const tags = [
      r.cycle ? '<span class="tag">cycle</span>' : '',
      n.edgeLabel ? `<span class="tag">${esc(n.edgeLabel)}</span>` : '',
      n.sharedCount ? `<span class="tag">also used by ${esc(n.sharedCount)}</span>` : '',
    ].join('');
    const caret = hasKids
      ? `<button class="caret" type="button" data-act="toggle" data-arg="${esc(n.id)}" aria-label="${open ? 'Collapse' : 'Expand'} ${esc(n.label)}" aria-expanded="${open}" tabindex="-1"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg></button>`
      : '<span class="caret none"></span>';
    const openBtn = `<button class="linkbtn openbtn" type="button" data-act="open" data-arg="${esc(n.id)}" aria-label="Open ${esc(n.label)}">Open ↗</button>`;
    let html = `<div class="row" role="row" data-row="${esc(n.id)}" tabindex="${tab}" aria-level="${r.level}"${hasKids ? ` aria-expanded="${open}"` : ''} style="grid-template-columns:${this.template()}">
      <div class="name" role="gridcell" style="padding-left:${Math.min(r.level - 1, 4) * 16}px">${caret}${chip(material, n.glyphName)}<span class="lbl" title="${esc(n.label)}">${esc(n.label)}${n.sublabel ? `<small>${esc(n.sublabel)}</small>` : ''}</span>${tags}${n.openable === false ? '' : openBtn}</div>
      ${this._columns.map((c) => this.cell(c, n)).join('')}</div>`;
    if (open && this.loading.has(n.id))
      html += `<div class="load" role="row" style="padding-left:${22 + r.level * 20}px"><span role="gridcell">Loading…</span></div>`;
    if (open && Array.isArray(n.children)) {
      const total = kidsOf(n).length;
      const shown = (this.pages.get(n.id) ?? 1) * this._pageSize;
      if (total > shown) {
        const more = Math.min(this._pageSize, total - shown);
        html += `<div class="more" role="row" style="padding-left:${22 + r.level * 20}px"><span role="gridcell"><button class="linkbtn" type="button" data-act="more" data-arg="${esc(n.id)}">Show ${more} more</button></span></div>`;
      } else if (n.truncated)
        html += `<div class="more" role="row" style="padding-left:${22 + r.level * 20}px"><span role="gridcell">More items exist than are shown here.</span></div>`;
    }
    return html;
  }
}

defineElement('henoyo-exposure-tree', HenoyoExposureTree);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-exposure-tree': HenoyoExposureTree;
  }
}
