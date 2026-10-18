// Mappers for the Visual Kit charts in group C. Aggregate kinds read a saved
// report; per-record kinds read related lists. No object name is special-cased.

import { isRelatedListRef, str, type RecordInput, type ResolvedInput } from './bindingTypes';
import { humanize, inkOn, PAPER, rampColor, scheme, type ColourScheme } from './henoyoKit';
import { text } from './rowValues';
import { chainGraph, chainPlan, type VizGraph } from './vizGraph';
import {
  foldBands,
  monthKey,
  monthStamp,
  OTHER_KEY,
  paintFor,
  paints,
  periodLabel,
  severityOf,
  severityWord,
  stackBands,
  type Band,
} from './vizPalette';

import type { Plan } from '../../data/pageComponents/plan';
import type { TrendPeriod, TrendSeries } from './henoyoDiscoveryTrend';
import type { ReportCell, ReportDataResponse } from '../../lib/reports';

const MAX_SPAN = 36;
function neutral(s: ColourScheme): TrendSeries {
  return { key: '', label: '', ...s.other, stroke: s.severity.info.stroke, values: [] };
}

function schemeOf(input: ResolvedInput): ColourScheme {
  return scheme(str(input.props['colour_scheme']));
}

function reportOf(input: ResolvedInput): ReportDataResponse | undefined {
  return input.reports?.['report'];
}

function cellKey(cell: ReportCell, field: string): string {
  const raw = cell.keys[field];
  if (raw === null || raw === undefined || raw === '') return '';
  return String(raw);
}

function measureOf(cell: ReportCell, id: string | undefined): number {
  if (id === undefined) return 0;
  const raw = cell.measures[id];
  const n = typeof raw === 'number' ? raw : typeof raw === 'string' ? Number(raw) : Number.NaN;
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function fieldLabel(input: ResolvedInput, object: string, field: string, key: string): string {
  if (key === '') return 'None';
  const dated = periodLabel(key);
  if (dated !== undefined) return dated;
  const word = severityWord(key);
  if (word !== undefined) return word;
  const options = input.describes[object]?.fields.find(
    (f) => f.api_name === field,
  )?.picklist_values;
  return options?.find((option) => option.value === key)?.label ?? humanize(key);
}

/** Month keys are ordered and empty months between them are filled. Other keys stay as reported. */
function orderedPeriods(keys: readonly string[]): string[] {
  if (keys.length === 0 || keys.some((key) => monthStamp(key) === undefined)) return [...keys];
  const sorted = [...keys].sort();
  const monthOnly = keys.every((key) => /^\d{4}-\d{2}$/.test(key));
  const firstOfMonth = keys.every((key) => /^\d{4}-\d{2}-01$/.test(key));
  if (!monthOnly && !firstOfMonth) return sorted;
  const stamps = keys.map((key) => monthStamp(key) ?? 0);
  const min = Math.min(...stamps);
  const max = Math.max(...stamps);
  if (max - min > MAX_SPAN) return sorted;
  const filled: string[] = [];
  for (let stamp = min; stamp <= max; stamp += 1) filled.push(monthKey(stamp, firstOfMonth));
  return filled;
}

/** Two groupings (time, then band) and one measure. Null when the report is a different shape. */
export function discoveryTrendProps(input: ResolvedInput): Record<string, unknown> | null {
  const report = reportOf(input);
  const measure = report?.measures[0];
  const rowField = report?.groups[0];
  const colField = report?.groups[1];
  if (
    report === undefined ||
    measure === undefined ||
    rowField === undefined ||
    colField === undefined ||
    report.groups.length !== 2 ||
    report.measures.length !== 1
  ) {
    return null;
  }

  const grid = new Map<string, Map<string, number>>();
  const seriesSeen: Band[] = [];
  const seriesIndex = new Map<string, Band>();
  const periodSeen: string[] = [];
  for (const cell of report.cells) {
    const period = cellKey(cell, rowField.field);
    const seriesKey = cellKey(cell, colField.field);
    const value = measureOf(cell, measure.id);
    if (!grid.has(period)) {
      grid.set(period, new Map());
      periodSeen.push(period);
    }
    const row = grid.get(period);
    if (row !== undefined) row.set(seriesKey, (row.get(seriesKey) ?? 0) + value);
    const band = seriesIndex.get(seriesKey);
    if (band === undefined) {
      const next: Band = {
        key: seriesKey,
        label: fieldLabel(input, report.object, colField.field, seriesKey),
        total: value,
      };
      seriesIndex.set(seriesKey, next);
      seriesSeen.push(next);
    } else {
      band.total += value;
    }
  }

  const keys = orderedPeriods(periodSeen);
  const periods: TrendPeriod[] = keys.map((key) => ({
    key,
    label: fieldLabel(input, report.object, rowField.field, key),
  }));
  const stacked = stackBands(seriesSeen.filter((band) => band.total > 0));
  const sch = schemeOf(input);
  const colours = paints(stacked, sch);
  const kept = new Set(stacked.map((band) => band.key));
  const series: TrendSeries[] = stacked.map((band, i) => {
    const paint = colours[i] ?? neutral(sch);
    return {
      key: band.key,
      label: band.label,
      fill: paint.fill,
      stroke: paint.stroke,
      outline: paint.outline,
      values: keys.map((key) => {
        const row = grid.get(key);
        if (row === undefined) return 0;
        if (band.key !== '__other__') return row.get(band.key) ?? 0;
        let sum = 0;
        for (const [seriesKey, value] of row) {
          if (!kept.has(seriesKey)) sum += value;
        }
        return sum;
      }),
    };
  });

  const title = str(input.props['title']);
  return {
    ...(title === undefined ? {} : { heading: title }),
    periods,
    series,
    truncated: report.cells_truncated === true,
  };
}

const MAX_ZONES = 6;
const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function titled(input: ResolvedInput, body: Record<string, unknown>): Record<string, unknown> {
  const title = str(input.props['title']);
  return { ...(title === undefined ? {} : { heading: title }), ...body };
}

/** One grouping and one measure, ranked, with at most six bars. */
export function kpiBarProps(input: ResolvedInput): Record<string, unknown> | null {
  const report = reportOf(input);
  const measure = report?.measures[0];
  const group = report?.groups[0];
  if (
    report === undefined ||
    measure === undefined ||
    group === undefined ||
    report.groups.length !== 1 ||
    report.measures.length !== 1
  ) {
    return null;
  }
  const totals = new Map<string, number>();
  const seen: string[] = [];
  for (const cell of report.cells) {
    const key = cellKey(cell, group.field);
    if (!totals.has(key)) seen.push(key);
    totals.set(key, (totals.get(key) ?? 0) + measureOf(cell, measure.id));
  }
  const folded = foldBands(
    seen
      .map((key) => ({
        key,
        label: fieldLabel(input, report.object, group.field, key),
        total: totals.get(key) ?? 0,
      }))
      .filter((band) => band.total > 0),
  );
  const rows = folded.map((band) => ({ key: band.key, label: band.label, value: band.total }));
  return titled(input, { rows, truncated: report.cells_truncated === true });
}

function axisOrder(input: ResolvedInput, object: string, field: string, seen: string[]): string[] {
  const options = input.describes[object]?.fields.find(
    (item) => item.api_name === field,
  )?.picklist_values;
  if (options == null || options.length === 0) return seen;
  const have = new Set(seen);
  const ordered = options.map((option) => option.value).filter((value) => have.has(value));
  return [...ordered, ...seen.filter((key) => !ordered.includes(key))];
}

/** Two groupings as the axes of a zone matrix. The cell is the measure. */
export function zoneExposureProps(input: ResolvedInput): Record<string, unknown> | null {
  const report = reportOf(input);
  const measure = report?.measures[0];
  const rowField = report?.groups[0];
  const colField = report?.groups[1];
  if (
    report === undefined ||
    measure === undefined ||
    rowField === undefined ||
    colField === undefined ||
    report.groups.length !== 2 ||
    report.measures.length !== 1
  ) {
    return null;
  }
  const grid = new Map<string, number>();
  const rowSeen: string[] = [];
  const colSeen: string[] = [];
  for (const cell of report.cells) {
    const row = cellKey(cell, rowField.field);
    const col = cellKey(cell, colField.field);
    if (!rowSeen.includes(row)) rowSeen.push(row);
    if (!colSeen.includes(col)) colSeen.push(col);
    const id = `${row}\0${col}`;
    grid.set(id, (grid.get(id) ?? 0) + measureOf(cell, measure.id));
  }
  const union = axisOrder(input, report.object, rowField.field, rowSeen);
  for (const key of axisOrder(input, report.object, colField.field, colSeen)) {
    if (!union.includes(key)) union.push(key);
  }
  const folded = union.length > MAX_ZONES ? new Set(union.slice(MAX_ZONES - 1)) : new Set<string>();
  const zoneKeys = folded.size === 0 ? union : [...union.slice(0, MAX_ZONES - 1), OTHER_KEY];
  const bucket = (key: string): string => (folded.has(key) ? OTHER_KEY : key);
  const totals = new Map<string, number>();
  let max = 0;
  for (const row of zoneKeys) {
    for (const col of zoneKeys) {
      let value = 0;
      for (const [id, count] of grid) {
        const [rawRow, rawCol] = id.split('\0');
        if (bucket(rawRow ?? '') === row && bucket(rawCol ?? '') === col) value += count;
      }
      totals.set(`${row}\0${col}`, value);
      if (value > max) max = value;
    }
  }
  const sch = schemeOf(input);
  const index = new Map(zoneKeys.map((key, i) => [key, i]));
  const labelOf = (key: string, field: string): string =>
    key === OTHER_KEY ? 'Other' : fieldLabel(input, report.object, field, key);
  const zones = zoneKeys.map((key) => ({
    key,
    label: labelOf(key, rowField.field),
  }));
  const cells = zoneKeys.flatMap((row) =>
    zoneKeys.map((col) => {
      const value = totals.get(`${row}\0${col}`) ?? 0;
      const fill = value <= 0 || max <= 0 ? PAPER : rampColor(sch, 0.12 + 0.88 * (value / max));
      const rowIndex = index.get(row) ?? 0;
      const colIndex = index.get(col) ?? 0;
      return {
        row,
        col,
        value,
        fill,
        ink: inkOn(fill),
        diagonal: row === col,
        crosses: row !== OTHER_KEY && col !== OTHER_KEY && Math.abs(rowIndex - colIndex) > 1,
      };
    }),
  );
  return titled(input, {
    zones,
    cells,
    truncated: report.cells_truncated === true || folded.size > 0,
  });
}

export function fanoutPlan(props: Record<string, unknown>): Plan {
  return chainPlan(props);
}

export function fanoutProps(input: RecordInput): Record<string, unknown> {
  const graph: VizGraph = chainGraph(input);
  return titled(input, { nodes: graph.nodes, edges: graph.edges, truncated: graph.truncated });
}

export function blastPlan(props: Record<string, unknown>): Plan {
  return chainPlan(props);
}

export function blastProps(input: RecordInput): Record<string, unknown> {
  const graph: VizGraph = chainGraph(input);
  return titled(input, { nodes: graph.nodes, truncated: graph.truncated });
}

export function zoneEnclosurePlan(props: Record<string, unknown>): Plan {
  const source = props['source'];
  if (!isRelatedListRef(source)) return [];
  return [{ path: 'source', child_object: source.child_object, relationship: source.relationship }];
}

export function zoneEnclosureProps(input: RecordInput): Record<string, unknown> {
  const source = input.props['source'];
  const child = isRelatedListRef(source) ? source.child_object : '';
  const labelField = str(input.props['label_field']) ?? '';
  const zoneField = str(input.props['zone_field']) ?? '';
  const severityField = str(input.props['severity_field']);
  const linkField = str(input.props['link_to']);
  const describe = child === '' ? undefined : input.describes[child];
  const options =
    describe?.fields.find((item) => item.api_name === zoneField)?.picklist_values ?? [];
  const rows = (input.rows['source'] ?? []).flatMap((row) => {
    const id = text(row, 'id');
    if (id === undefined) return [];
    const zone = text(row, zoneField) ?? '';
    const severity = severityField === undefined ? '' : (text(row, severityField) ?? '');
    return [
      {
        id,
        zone,
        severity,
        label: text(row, labelField) ?? id,
        link: linkField === undefined ? undefined : text(row, linkField),
      },
    ];
  });
  const known = new Set(options.map((option) => option.value));
  const zoneOrder = [
    ...options
      .map((option) => option.value)
      .filter((value) => rows.some((row) => row.zone === value)),
    ...[...new Set(rows.map((row) => row.zone))].filter((zone) => zone !== '' && !known.has(zone)),
  ];
  if (rows.some((row) => row.zone === '')) zoneOrder.push('');
  const sch = schemeOf(input);
  const rank = (severity: string): number => SEVERITY_RANK[severityOf(severity) ?? ''] ?? 9;
  const bands = zoneOrder.map((zone, zoneIndex) => {
    const zonePaint = paintFor(`zone-${zoneIndex}`, zoneIndex, sch);
    const label =
      zone === ''
        ? 'Unknown'
        : (options.find((option) => option.value === zone)?.label ?? humanize(zone));
    const members = rows
      .filter((row) => row.zone === zone)
      .sort((a, b) => rank(a.severity) - rank(b.severity) || (a.label < b.label ? -1 : 1));
    return {
      key: zone === '' ? '__unknown__' : zone,
      label,
      nodes: members.map((row) => {
        const colour = row.severity === '' ? zonePaint : paintFor(row.severity, zoneIndex, sch);
        const word = severityWord(row.severity);
        return {
          id: row.id,
          label: row.label,
          fill: colour.fill,
          stroke: colour.stroke,
          outline: colour.outline,
          objectApiName: child,
          recordId: row.id,
          openable: /^[a-z][a-z0-9_]*$/.test(child),
          tip: word === undefined ? `${row.label} — ${label}` : `${row.label} — ${label} — ${word}`,
        };
      }),
    };
  });
  const ids = new Set(rows.map((row) => row.id));
  const links = rows.flatMap((row) =>
    row.link !== undefined && row.link !== row.id && ids.has(row.link)
      ? [{ from: row.id, to: row.link }]
      : [],
  );
  return titled(input, { bands, links, truncated: input.truncated === true });
}
