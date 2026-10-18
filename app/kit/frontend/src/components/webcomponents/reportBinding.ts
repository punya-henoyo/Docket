import { humanize } from './henoyoKit';
import { isObject, str, type ResolvedInput } from './bindingTypes';

import { countScaleProps } from './heatmapScale';
import type { HenoyoMatrixCell } from './henoyoMatrix';
import type { HenoyoRingPart, HenoyoRingTone } from './henoyoRing';
import type { ReportCell, ReportDataResponse } from '../../lib/reports';

const NONE_KEY = '';
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function reportOf(input: ResolvedInput): ReportDataResponse | undefined {
  return input.reports?.['report'];
}

function keyOf(cell: ReportCell, field: string): string {
  const value = cell.keys[field];
  return value === null || value === undefined ? NONE_KEY : String(value);
}

function measureOf(cell: ReportCell, id: string): number | undefined {
  const value = cell.measures[id];
  const n = typeof value === 'string' ? Number(value) : value;
  return typeof n === 'number' && Number.isFinite(n) ? n : undefined;
}

function labeller(
  input: ResolvedInput,
  report: ReportDataResponse,
  field: string,
): (key: string) => string {
  const picklist = input.describes[report.object]?.fields.find(
    (f) => f.api_name === field,
  )?.picklist_values;
  return (key) =>
    key === NONE_KEY ? 'None' : (picklist?.find((p) => p.value === key)?.label ?? humanize(key));
}

function byRawValue(a: string, b: string): number {
  if (a === NONE_KEY || b === NONE_KEY) return Number(a === NONE_KEY) - Number(b === NONE_KEY);
  const na = Number(a);
  const nb = Number(b);
  if (a.trim() !== '' && b.trim() !== '' && Number.isFinite(na) && Number.isFinite(nb)) {
    return na - nb;
  }
  return a < b ? -1 : a > b ? 1 : 0; // code-point order: packs pad formula values to set their order
}

/**
 * A picklist grouping reads in the picklist's own order; values it does not list follow in report
 * order. Other groupings keep report order, except a secondary grouping (`sortRaw`), whose values
 * the cells don't order, which reads ascending by value.
 */
function inPicklistOrder(
  input: ResolvedInput,
  report: ReportDataResponse,
  field: string,
  keys: readonly string[],
  sortRaw = false,
): string[] {
  const picklist = input.describes[report.object]?.fields.find(
    (f) => f.api_name === field,
  )?.picklist_values;
  if (picklist === undefined || picklist === null) {
    return sortRaw ? [...keys].sort(byRawValue) : [...keys];
  }
  const at = (key: string): number => {
    const i = picklist.findIndex((p) => p.value === key);
    return i === -1 ? picklist.length : i;
  };
  return keys
    .map((key, i) => ({ key, i }))
    .sort((a, b) => at(a.key) - at(b.key) || a.i - b.i)
    .map(({ key }) => key);
}

function withHeading(out: Record<string, unknown>, props: Record<string, unknown>): void {
  const title = str(props['title']);
  if (title !== undefined) out['heading'] = title;
}

/** Rows are the first grouping and columns the second, each in the report's own order; the cell is its one measure. */
export function reportHeatmapProps(input: ResolvedInput): Record<string, unknown> | null {
  const report = reportOf(input);
  if (report === undefined || report.groups.length !== 2 || report.measures.length !== 1) {
    return null;
  }
  const [rowGroup, colGroup] = report.groups;
  const measure = report.measures[0];
  if (rowGroup === undefined || colGroup === undefined || measure === undefined) return null;

  const rowKeys: string[] = [];
  const colKeys: string[] = [];
  const values = new Map<string, number>();
  for (const cell of report.cells) {
    const row = keyOf(cell, rowGroup.field);
    const col = keyOf(cell, colGroup.field);
    if (!rowKeys.includes(row)) rowKeys.push(row);
    if (!colKeys.includes(col)) colKeys.push(col);
    values.set(`${row}\u0000${col}`, measureOf(cell, measure.id) ?? 0);
  }
  const severityRows = input.props['severity_rows'] === true;
  const rank = (key: string): number => {
    const at = SEVERITY_ORDER.indexOf(key.toLowerCase());
    return at === -1 ? SEVERITY_ORDER.length : at;
  };
  const listedRows = inPicklistOrder(input, report, rowGroup.field, rowKeys);
  const orderedRows = severityRows
    ? listedRows
        .map((key, i) => ({ key, i }))
        .sort((a, b) => rank(a.key) - rank(b.key) || a.i - b.i)
        .map(({ key }) => key)
    : listedRows;

  const rowLabel = labeller(input, report, rowGroup.field);
  const colLabel = labeller(input, report, colGroup.field);
  const orderedCols = inPicklistOrder(input, report, colGroup.field, colKeys, true);
  const cells: HenoyoMatrixCell[] = orderedRows.flatMap((row) =>
    orderedCols.map((col) => ({ row, col, value: values.get(`${row}\u0000${col}`) ?? 0 })),
  );
  const out: Record<string, unknown> = {
    mode: 'heatmap',
    rows: orderedRows.map((key) => ({
      id: key,
      label: rowLabel(key),
      ...(severityRows ? { severity: key } : {}),
    })),
    columns: orderedCols.map((key) => ({ id: key, label: colLabel(key) })),
    cells,
    truncated: report.cells_truncated === true,
  };
  withHeading(out, input.props);
  return { ...out, ...countScaleProps(input.props) };
}

/** One segment per value of the one grouping, in the report's order; tones come from the `tones` map, never from its key order. */
export function reportRingProps(input: ResolvedInput): Record<string, unknown> | null {
  const report = reportOf(input);
  if (report === undefined || report.groups.length !== 1 || report.measures.length !== 1) {
    return null;
  }
  const group = report.groups[0];
  const measure = report.measures[0];
  if (group === undefined || measure === undefined) return null;

  const tones = isObject(input.props['tones']) ? input.props['tones'] : {};
  const name = labeller(input, report, group.field);
  const byKey = new Map(report.cells.map((cell) => [keyOf(cell, group.field), cell]));
  const keys = inPicklistOrder(input, report, group.field, [...byKey.keys()]);
  const all: HenoyoRingPart[] = keys.map((key) => {
    const cell = byKey.get(key) as ReportCell;
    const tone = tones[key];
    return {
      label: name(key),
      count: measureOf(cell, measure.id) ?? 0,
      ...(typeof tone === 'string' ? { tone: tone as HenoyoRingTone } : {}),
    };
  });
  const total = all.reduce((sum, part) => sum + part.count, 0);
  const out: Record<string, unknown> = {
    parts: total === 0 ? all : all.filter((part) => part.count > 0),
    truncated: report.cells_truncated === true,
  };
  withHeading(out, input.props);
  const center = str(input.props['center_label']);
  if (center !== undefined) out['centerLabel'] = center;
  return out;
}
