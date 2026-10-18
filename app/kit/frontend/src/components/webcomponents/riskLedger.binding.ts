import { humanize } from './henoyoKit';
import { str, type ResolvedInput } from './bindingTypes';

import type { LedgerRow } from './henoyoRiskLedger';
import type { ReportCell, ReportDataResponse } from '../../lib/reports';

function measureOf(cell: ReportCell, id: string): number {
  const value = cell.measures[id];
  const n = typeof value === 'string' ? Number(value) : value;
  return typeof n === 'number' && Number.isFinite(n) ? n : 0;
}

function labelOf(
  input: ResolvedInput,
  report: ReportDataResponse,
  cell: ReportCell,
  field: string,
): string {
  const written = cell.label.trim();
  if (written !== '') return written;
  const raw = cell.keys[field];
  const key = raw === null || raw === undefined ? '' : String(raw);
  if (key === '') return 'None';
  const picklist = input.describes[report.object]?.fields.find(
    (item) => item.api_name === field,
  )?.picklist_values;
  return picklist?.find((item) => item.value === key)?.label ?? humanize(key);
}

function limitOf(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 10;
  return Math.min(50, Math.max(1, Math.floor(value)));
}

/** Highest values of a one-grouping, one-measure report, ranked for the rows shown. */
export function riskLedgerProps(input: ResolvedInput): Record<string, unknown> | null {
  const report = input.reports?.['report'];
  if (report === undefined || report.groups.length !== 1 || report.measures.length !== 1)
    return null;
  const group = report.groups[0];
  const measure = report.measures[0];
  if (group === undefined || measure === undefined) return null;
  const limit = limitOf(input.props['limit']);
  const scored = report.cells.map((cell) => ({
    label: labelOf(input, report, cell, group.field),
    value: measureOf(cell, measure.id),
  }));
  scored.sort((a, b) => b.value - a.value || a.label.localeCompare(b.label));
  const shown = scored.slice(0, limit);
  const max = shown.reduce((peak, row) => Math.max(peak, row.value), 0);
  const rows: LedgerRow[] = shown.map((row, index) => ({
    rank: index + 1,
    label: row.label,
    value: row.value,
    share: max <= 0 ? 0 : row.value / max,
  }));
  const heading = str(input.props['title']);
  return {
    rows,
    valueLabel: measure.label,
    total: scored.length,
    sum: scored.reduce((acc, row) => acc + row.value, 0),
    truncated: report.cells_truncated === true,
    ...(heading !== undefined ? { heading } : {}),
  };
}
