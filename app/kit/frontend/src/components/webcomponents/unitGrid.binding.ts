import { kitLocale } from './colourScheme';
import { isObject, isRelatedListRef, str, strings, type ResolvedInput } from './bindingTypes';
import { text } from './rowValues';
import { BANDS, bandWord, foldBand, joinOr, type SeverityBand } from './severityBands';

import type { UnitDetail, UnitSquare } from './henoyoUnitGrid';
import type { RecordRow } from '../../lib/dataApi';

function foldMap(value: unknown): Record<string, string> {
  if (!isObject(value)) return {};
  const out: Record<string, string> = {};
  for (const [key, folded] of Object.entries(value)) {
    if (typeof folded === 'string' && folded !== '') out[key] = folded;
  }
  return out;
}

function shown(row: RecordRow, key: string): string | undefined {
  const display = text(row, `${key}__display`);
  if (display !== undefined) return display;
  const value = row[key];
  if (typeof value === 'number' && Number.isFinite(value)) return value.toLocaleString(kitLocale());
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return text(row, key);
}

function shareOf(
  configured: readonly string[],
  folds: Record<string, string>,
): { bands: SeverityBand[]; label: string } {
  if (configured.length === 0) return { bands: ['critical', 'high'], label: 'critical or high' };
  const bands = BANDS.filter(
    (band) => band !== 'other' && configured.some((value) => foldBand(value, folds) === band),
  );
  if (bands.length === 0) return { bands: [], label: '' };
  return { bands, label: joinOr(bands.map((band) => bandWord(band).toLowerCase())) };
}

/** One square per related record. Severity folds once, then colours the square. */
export function unitGridProps(input: ResolvedInput): Record<string, unknown> | null {
  const source = input.props['source'];
  const severityField = str(input.props['severity_field']);
  const labelField = str(input.props['label_field']);
  if (!isRelatedListRef(source) || severityField === undefined || labelField === undefined) {
    return null;
  }
  const folds = foldMap(input.props['folds']);
  const share = shareOf(strings(input.props['summary_values']), folds);
  const fields = input.describes[source.child_object]?.fields;
  const detailFields = strings(input.props['detail_fields']).slice(0, 6);
  const squares: UnitSquare[] = (input.rows['source'] ?? []).map((row, index) => {
    const raw = text(row, severityField);
    const band = foldBand(raw, folds);
    const id = typeof row['id'] === 'string' && row['id'] !== '' ? row['id'] : `row-${index}`;
    const details: UnitDetail[] = [];
    for (const field of detailFields) {
      const value = shown(row, field);
      if (value === undefined) continue;
      const meta = fields?.find((item) => item.api_name === field);
      details.push({ label: meta?.label ?? field, value });
    }
    return {
      id,
      recordId: typeof row['id'] === 'string' ? row['id'] : '',
      objectApiName: source.child_object,
      label: shown(row, labelField) ?? 'Record',
      band,
      details,
    };
  });
  squares.sort(
    (a, b) => BANDS.indexOf(a.band) - BANDS.indexOf(b.band) || a.label.localeCompare(b.label),
  );
  const heading = str(input.props['title']);
  return {
    squares,
    shareBands: share.bands,
    shareLabel: share.label,
    truncated: input.truncated === true,
    ...(heading !== undefined ? { heading } : {}),
  };
}
