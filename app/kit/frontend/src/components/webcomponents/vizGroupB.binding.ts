// viz library: group B — report mappers for the rank gauge, the one-shot narrative,
// and the severity × age heatmap. No object name is special-cased.

import { kitLocale } from './colourScheme';
import type { ResolvedInput } from './bindingTypes';
import type { ReportCell, ReportDataResponse } from '../../lib/reports';

const NONE_KEY = '';
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const AGE_CORE = ['0-30', '31-90', '91-180', '181+'] as const;
const AGE_EXTRA = ['unknown', 'future'] as const;
const SEVERITY_WORD: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};
const AGE_WORD: Record<string, string> = {
  '0-30': '0–30 days',
  '31-90': '31–90 days',
  '91-180': '91–180 days',
  '181+': '181+ days',
  unknown: 'Unknown',
  future: 'Future',
};
const KNOWN_AGE = new Set<string>([...AGE_CORE, ...AGE_EXTRA]);
const KNOWN_SEVERITY = new Set<string>(SEVERITIES);

export interface RankGaugeRow {
  id: string;
  label: string;
  value: number;
}

export interface NarrativeItem {
  id: string;
  label: string;
  value: number;
  share: number;
}

export interface SeverityAgeAxis {
  id: string;
  label: string;
  tone: string;
}

export interface SeverityAgeCell {
  row: string;
  col: string;
  value: number;
}

interface GroupMeasure {
  field: string;
  label: string;
  measureId: string;
  measureLabel: string;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

export function formatCount(value: number): string {
  const rounded = Math.round(value * 10) / 10;
  if (Number.isInteger(rounded)) return rounded.toLocaleString(kitLocale());
  return rounded.toLocaleString(kitLocale(), {
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  });
}

function keyOf(cell: ReportCell, field: string): string {
  const value = cell.keys[field];
  return value === null || value === undefined ? NONE_KEY : String(value);
}

function measureOf(cell: ReportCell, id: string): number {
  const value = cell.measures[id];
  const n = typeof value === 'string' ? Number(value) : value;
  return typeof n === 'number' && Number.isFinite(n) ? n : 0;
}

function labeller(
  input: ResolvedInput,
  report: ReportDataResponse,
  field: string,
): (key: string) => string {
  const picklist = input.describes[report.object]?.fields.find(
    (f) => f.api_name === field,
  )?.picklist_values;
  const labels = new Map((picklist ?? []).map((entry) => [entry.value, entry.label]));
  return (key) => (key === NONE_KEY ? 'None' : (labels.get(key) ?? key));
}

function inPicklistOrder(
  input: ResolvedInput,
  report: ReportDataResponse,
  field: string,
  keys: readonly string[],
): string[] {
  const picklist = input.describes[report.object]?.fields.find(
    (f) => f.api_name === field,
  )?.picklist_values;
  if (picklist === undefined || picklist === null || picklist.length === 0) return [...keys];
  const index = new Map<string, number>();
  keys.forEach((key, i) => index.set(key, i));
  const rank = new Map(picklist.map((entry, i) => [entry.value, i]));
  return [...keys].sort((a, b) => {
    const ra = rank.get(a);
    const rb = rank.get(b);
    if (ra === undefined && rb === undefined) return (index.get(a) ?? 0) - (index.get(b) ?? 0);
    if (ra === undefined) return 1;
    if (rb === undefined) return -1;
    return ra - rb;
  });
}

function shape(
  report: ReportDataResponse | undefined,
  groupings: number,
): { report: ReportDataResponse; groups: GroupMeasure[] } | undefined {
  if (report === undefined || report.groups.length !== groupings || report.measures.length !== 1) {
    return undefined;
  }
  const measure = report.measures[0];
  if (measure === undefined) return undefined;
  const groups: GroupMeasure[] = [];
  for (const group of report.groups) {
    groups.push({
      field: group.field,
      label: group.label,
      measureId: measure.id,
      measureLabel: measure.label,
    });
  }
  return groups.length === groupings ? { report, groups } : undefined;
}

function headingOf(props: Record<string, unknown>): string | undefined {
  return str(props['title']);
}

function limitOf(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 10;
  return Math.min(24, Math.max(1, Math.trunc(value)));
}

function oneAxis(
  input: ResolvedInput,
  report: ReportDataResponse,
  group: GroupMeasure,
): RankGaugeRow[] {
  const totals = new Map<string, number>();
  const seen: string[] = [];
  for (const cell of report.cells) {
    const key = keyOf(cell, group.field);
    if (!totals.has(key)) seen.push(key);
    totals.set(key, (totals.get(key) ?? 0) + measureOf(cell, group.measureId));
  }
  const name = labeller(input, report, group.field);
  return seen
    .map((id) => ({ id, label: name(id), value: totals.get(id) ?? 0 }))
    .sort((a, b) => b.value - a.value || (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
}

export function rankGaugeProps(input: ResolvedInput): Record<string, unknown> | null {
  const shaped = shape(input.reports?.['report'], 1);
  const group = shaped?.groups[0];
  if (shaped === undefined || group === undefined) return null;
  const props: Record<string, unknown> = {
    groupLabel: group.label,
    measureLabel: group.measureLabel,
    limit: limitOf(input.props['limit']),
    truncated: shaped.report.cells_truncated === true,
    rows: oneAxis(input, shaped.report, group),
  };
  const heading = headingOf(input.props);
  if (heading !== undefined) props['heading'] = heading;
  return props;
}

/** Shortest prefix of a highest-first list that holds 60% of the total. */
export function concentrationCount(
  values: readonly number[],
  total: number,
): { count: number; share: number } {
  if (total <= 0 || values.length === 0) return { count: 0, share: 0 };
  let sum = 0;
  let count = 0;
  for (const value of values) {
    sum += value;
    count += 1;
    if (sum / total >= 0.6) break;
  }
  return { count, share: Math.round((sum / total) * 100) };
}

export function narrativeSentence(
  rows: readonly RankGaugeRow[],
  groupLabel: string,
  measureLabel: string,
): string {
  const total = rows.reduce((sum, row) => sum + row.value, 0);
  const top = rows[0];
  if (rows.length === 0 || top === undefined || total <= 0) return `No ${measureLabel} to report.`;
  if (rows.length === 1) return `${formatCount(total)} ${measureLabel}, all in ${top.label}.`;
  const topPct = Math.round((top.value / total) * 100);
  const band = concentrationCount(
    rows.map((row) => row.value),
    total,
  );
  const hold = band.count === 1 ? 'holds' : 'hold';
  return (
    `${formatCount(total)} ${measureLabel}. Grouped by ${groupLabel}. ` +
    `${top.label} leads with ${formatCount(top.value)} (${topPct}%). ` +
    `${band.count} of ${rows.length} ${hold} ${band.share}%.`
  );
}

export function narrativeProps(input: ResolvedInput): Record<string, unknown> | null {
  const shaped = shape(input.reports?.['report'], 1);
  const group = shaped?.groups[0];
  if (shaped === undefined || group === undefined) return null;
  const rows = oneAxis(input, shaped.report, group);
  const total = rows.reduce((sum, row) => sum + row.value, 0);
  const items: NarrativeItem[] = rows.slice(0, 6).map((row) => ({
    id: row.id,
    label: row.label,
    value: row.value,
    share: total > 0 ? Math.round((row.value / total) * 100) : 0,
  }));
  const props: Record<string, unknown> = {
    groupLabel: group.label,
    measureLabel: group.measureLabel,
    total,
    sentence: narrativeSentence(rows, group.label, group.measureLabel),
    count: rows.length,
    items,
    truncated: shaped.report.cells_truncated === true,
  };
  const heading = headingOf(input.props);
  if (heading !== undefined) props['heading'] = heading;
  return props;
}

export function normKey(value: string): string {
  const compact = value.trim().toLowerCase().replace(/[–—]/g, '-').replace(/\s+/g, '');
  if (compact === 'informational') return 'info';
  if (compact.endsWith('days')) return compact.slice(0, -4);
  if (compact.endsWith('day')) return compact.slice(0, -3);
  return compact;
}

function axisId(raw: string, known: ReadonlySet<string>): string {
  const norm = normKey(raw);
  return known.has(norm) ? norm : raw;
}

function axisLabel(
  id: string,
  raw: string,
  name: (key: string) => string,
  words: Record<string, string>,
): string {
  const picked = name(raw);
  if (picked !== raw) return picked;
  const byId = name(id);
  if (byId !== id) return byId;
  return words[id] ?? picked;
}

function isOverdue(id: string): boolean {
  if (id === '91-180' || id === '181+') return true;
  const plus = /^(\d+)\+$/.exec(id);
  if (plus?.[1] !== undefined) return Number(plus[1]) >= 91;
  const range = /^(\d+)-(\d+)$/.exec(id);
  const lower = range?.[1];
  return lower !== undefined && Number(lower) >= 91;
}

function cellKey(row: string, col: string): string {
  return `${row}\u0000${col}`;
}

export function severityAgeProps(input: ResolvedInput): Record<string, unknown> | null {
  const shaped = shape(input.reports?.['report'], 2);
  const rowGroup = shaped?.groups[0];
  const colGroup = shaped?.groups[1];
  if (shaped === undefined || rowGroup === undefined || colGroup === undefined) return null;

  const rowName = labeller(input, shaped.report, rowGroup.field);
  const colName = labeller(input, shaped.report, colGroup.field);
  const grid = new Map<string, number>();
  const rowRaw = new Map<string, string>();
  const colRaw = new Map<string, string>();
  const rowSeen: string[] = [];
  const colSeen: string[] = [];

  for (const cell of shaped.report.cells) {
    const rawRow = keyOf(cell, rowGroup.field);
    const rawCol = keyOf(cell, colGroup.field);
    const row = axisId(rawRow, KNOWN_SEVERITY);
    const col = axisId(rawCol, KNOWN_AGE);
    if (!rowRaw.has(row)) {
      rowRaw.set(row, rawRow);
      rowSeen.push(row);
    }
    if (!colRaw.has(col)) {
      colRaw.set(col, rawCol);
      colSeen.push(col);
    }
    const key = cellKey(row, col);
    grid.set(key, (grid.get(key) ?? 0) + measureOf(cell, rowGroup.measureId));
  }

  const severityMode = rowSeen.some((id) => KNOWN_SEVERITY.has(id));
  const ageMode = colSeen.some((id) => KNOWN_AGE.has(id));
  const rowIds = severityMode
    ? [
        ...SEVERITIES,
        ...inPicklistOrder(
          input,
          shaped.report,
          rowGroup.field,
          rowSeen.filter((id) => !KNOWN_SEVERITY.has(id)),
        ),
      ]
    : inPicklistOrder(input, shaped.report, rowGroup.field, rowSeen);
  const colIds = ageMode
    ? [
        ...AGE_CORE,
        ...AGE_EXTRA.filter((id) => colSeen.includes(id)),
        ...inPicklistOrder(
          input,
          shaped.report,
          colGroup.field,
          colSeen.filter((id) => !KNOWN_AGE.has(id)),
        ),
      ]
    : inPicklistOrder(input, shaped.report, colGroup.field, colSeen);

  const rows: SeverityAgeAxis[] = rowIds.map((id) => ({
    id,
    label: axisLabel(id, rowRaw.get(id) ?? id, rowName, SEVERITY_WORD),
    tone: KNOWN_SEVERITY.has(id) ? id : '',
  }));
  const columns: SeverityAgeAxis[] = colIds.map((id) => ({
    id,
    label: axisLabel(id, colRaw.get(id) ?? id, colName, AGE_WORD),
    tone: '',
  }));
  const cells: SeverityAgeCell[] = [];
  let total = 0;
  let overdue = 0;
  let oldCritical = 0;
  for (const row of rowIds) {
    for (const col of colIds) {
      const value = grid.get(cellKey(row, col)) ?? 0;
      cells.push({ row, col, value });
      total += value;
      if (ageMode && (row === 'critical' || row === 'high') && isOverdue(col)) overdue += value;
      if (ageMode && row === 'critical' && isOverdue(col)) oldCritical += value;
    }
  }

  const props: Record<string, unknown> = {
    rowLabel: rowGroup.label,
    colLabel: colGroup.label,
    sentence: ageSentence(
      total,
      overdue,
      ageMode,
      rows.length,
      columns.length,
      rowGroup.label,
      colGroup.label,
    ),
    rows,
    columns,
    cells,
    oldCritical: ageMode && severityMode ? oldCritical : null,
    oldAge: '90 days',
    truncated: shaped.report.cells_truncated === true,
  };
  const heading = headingOf(input.props);
  if (heading !== undefined) props['heading'] = heading;
  return props;
}

function ageSentence(
  total: number,
  overdue: number,
  ageMode: boolean,
  rowCount: number,
  colCount: number,
  rowLabel: string,
  colLabel: string,
): string {
  const tracked = formatCount(total);
  if (!ageMode) return `${tracked} across ${rowCount} ${rowLabel} and ${colCount} ${colLabel}.`;
  if (overdue <= 0) return `${tracked} tracked — no critical or high are older than 90 days.`;
  const pct = total > 0 ? Math.round((overdue / total) * 100) : 0;
  return `${tracked} tracked — ${formatCount(overdue)} (${pct}%) critical or high are older than 90 days.`;
}
