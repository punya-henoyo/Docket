// One model for the periodic-table chart and the Visual Kit kind.
// Author hexes win. Otherwise the rail walks paper to oxblood, one solid per band.

import { kitLocale } from './colourScheme';
import { rampColor, scheme } from './henoyoKit';
import { formatMoney } from './lossCurve';

import type { ReportDataResponse } from '../../lib/reports';

const HEX = /^#[0-9A-Fa-f]{6}$/;

export function editorialBandColor(index: number, count: number, s = scheme()): string {
  return rampColor(s, count <= 1 ? 0 : index / (count - 1));
}

/** Left-rail colour for one tile. A value we cannot read, or a tile that does not apply, stays uncoloured. */
export function tileColor(
  value: number | null,
  segments: readonly number[] | undefined,
  colors: readonly string[] | undefined,
  s = scheme(),
): string | null {
  if (value === null) return null;
  const thresholds = (segments ?? []).filter((n) => Number.isFinite(n)).sort((a, b) => a - b);
  const crossed = thresholds.filter((n) => value >= n).length;
  const authored = colors?.[crossed];
  if (typeof authored === 'string' && HEX.test(authored)) return authored;
  return editorialBandColor(crossed, thresholds.length + 1, s);
}

export interface PeriodicAxis {
  key: string;
  label: string;
  hint: string;
}

export interface PeriodicTile {
  key: string;
  row: string;
  column: string;
  symbol: string;
  label: string;
  valueText: string;
  value: number | null;
  color: string | null;
  notApplicable: boolean;
  selectable: boolean;
}

export interface PeriodicMeasure {
  id: string;
  label: string;
}

export interface PeriodicModel {
  emptyLayout: boolean;
  rows: PeriodicAxis[];
  columns: PeriodicAxis[];
  tiles: PeriodicTile[];
  measures: PeriodicMeasure[];
  activeId: string;
  unmapped: number;
  multiselect: boolean;
  truncated: boolean;
  shownGroups: number;
}

function toNumber(value: unknown): number | null {
  if (value === null || value === undefined || typeof value === 'boolean') return null;
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) ? n : null;
}

function formatTileValue(value: unknown, dataType: string | undefined): string {
  if (value === null || value === undefined) return '—';
  const n = toNumber(value);
  if (n === null) return typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value);
  if (dataType === 'Currency') {
    return formatMoney(n, '', 2);
  }
  return n.toLocaleString(kitLocale(), { maximumFractionDigits: 2 });
}

export function measureChoice(data: ReportDataResponse): { primary: string; alt: string | null } {
  const primary = data.chart?.series?.[0] ?? data.measures[0]?.id ?? '';
  const alt = data.chart?.alt_series ?? null;
  return { primary, alt: alt !== null && alt !== primary ? alt : null };
}

function measureLabel(data: ReportDataResponse, id: string): string {
  return data.measures.find((measure) => measure.id === id)?.label ?? id;
}

/** Tiles for one measure. A missing layout is an empty model, not a blank grid. */
export function periodicModel(
  data: ReportDataResponse,
  measureId?: string,
  colours = scheme(),
): PeriodicModel {
  const chart = data.chart;
  const choice = measureChoice(data);
  const activeId =
    measureId !== undefined && (measureId === choice.primary || measureId === choice.alt)
      ? measureId
      : choice.primary;
  const measures: PeriodicMeasure[] = [
    { id: choice.primary, label: measureLabel(data, choice.primary) },
  ];
  if (choice.alt !== null) {
    const written = chart?.alt_label?.trim() ?? '';
    measures.push({
      id: choice.alt,
      label: written !== '' ? written : measureLabel(data, choice.alt),
    });
  }
  const rows = (chart?.grid_rows ?? []).map((row) => ({
    key: row.key,
    label: row.label,
    hint: row.hint ?? '',
  }));
  const columns = (chart?.grid_columns ?? []).map((column) => ({
    key: column.key,
    label: column.label,
    hint: column.hint ?? '',
  }));
  const xField = chart?.x ?? '';
  const byKey = new Map<string, (typeof data.cells)[number]>();
  for (const cell of data.cells) byKey.set(String(cell.keys[xField] ?? ''), cell);
  const placed = new Set((chart?.grid_cells ?? []).map((cell) => cell.key));
  const unmapped = data.cells.filter(
    (cell) => !placed.has(String(cell.keys[xField] ?? '')) && cell.keys[xField] != null,
  ).length;
  const dataType = data.measures.find((measure) => measure.id === activeId)?.data_type;
  const tiles: PeriodicTile[] = (chart?.grid_cells ?? []).map((cell) => {
    const datum = byKey.get(cell.key);
    const raw = datum?.measures[activeId] ?? null;
    const notApplicable = cell.not_applicable === true;
    const label = cell.label ?? '';
    return {
      key: cell.key,
      row: cell.row,
      column: cell.column,
      symbol: cell.symbol,
      label,
      valueText: notApplicable ? 'Not applicable' : formatTileValue(raw, dataType),
      value: notApplicable ? null : toNumber(raw),
      color: notApplicable
        ? null
        : tileColor(toNumber(raw), chart?.grid_segments, chart?.grid_segment_colors, colours),
      notApplicable,
      selectable: !notApplicable && datum !== undefined,
    };
  });
  return {
    emptyLayout: rows.length === 0 || columns.length === 0,
    rows,
    columns,
    tiles,
    measures,
    activeId,
    unmapped,
    multiselect:
      data.groups.find((group) => group.field === xField)?.data_type === 'Multiselect Picklist',
    truncated: data.cells_truncated === true,
    shownGroups: data.cell_count,
  };
}
