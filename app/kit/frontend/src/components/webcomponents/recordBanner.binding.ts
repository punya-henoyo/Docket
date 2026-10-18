// Props for <henoyo-record-banner>: the authored rows. A row with a `when` rule is kept only
// when the rule holds for the open record; a row without one always shows.

import type { RecordRow } from '../../lib/dataApi';
import type { HenoyoBannerRow } from './henoyoRecordBanner';
import { isObject, objects, str, strings, type ResolvedInput } from './bindingTypes';

const LEVELS = ['info', 'warning', 'danger', 'success'];
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}[T ]/;

const isEmpty = (v: unknown): boolean =>
  v === undefined ||
  v === null ||
  (typeof v === 'string' && v.trim() === '') ||
  (Array.isArray(v) && v.length === 0);

const localDay = (d: Date): string =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;

/** Compares two values for lt/gt: numbers as numbers, dates as dates, anything else is false. */
function order(actual: unknown, expected: unknown): number | undefined {
  if (typeof actual === 'number' && typeof expected === 'number') return actual - expected;
  if (typeof actual === 'string' && typeof expected === 'string') {
    if (DATE_ONLY.test(actual) && DATE_ONLY.test(expected))
      return actual < expected ? -1 : actual > expected ? 1 : 0;
    if (DATE_TIME.test(actual) || DATE_TIME.test(expected)) {
      const a = Date.parse(actual);
      const b = Date.parse(expected);
      if (!Number.isNaN(a) && !Number.isNaN(b)) return a - b;
    }
  }
  return undefined;
}

/** True when the rule holds for the record. A malformed rule never holds. */
export function ruleHolds(
  rule: Record<string, unknown>,
  record: RecordRow,
  now: Date = new Date(),
): boolean {
  const field = str(rule['field']);
  const op = str(rule['op']);
  if (field === undefined || op === undefined) return false;
  const actual: unknown = record[field];
  if (op === 'empty') return isEmpty(actual);
  if (op === 'notempty') return !isEmpty(actual);
  if (op === 'in') return !isEmpty(actual) && strings(rule['values']).includes(String(actual));
  if (op !== 'eq' && op !== 'ne' && op !== 'lt' && op !== 'gt') return false;

  const relative = str(rule['relative']);
  let expected: unknown = rule['value'];
  let seen: unknown = actual;
  if (relative === 'today') {
    // Date-only comparison, in the viewer's day.
    expected = localDay(now);
    seen =
      typeof actual === 'string' && DATE_TIME.test(actual) ? localDay(new Date(actual)) : actual;
  } else if (relative === 'now') {
    expected = now.toISOString();
  } else if (expected === undefined || expected === null) {
    return false;
  }
  if (op === 'eq' || op === 'ne') {
    const same = !isEmpty(seen) && String(seen) === String(expected);
    return op === 'eq' ? same : !same;
  }
  if (isEmpty(seen)) return false;
  const cmp = order(seen, expected);
  if (cmp === undefined || cmp === 0) return false;
  return op === 'lt' ? cmp < 0 : cmp > 0;
}

export function recordBannerProps(
  input: ResolvedInput,
  now: Date = new Date(),
): Record<string, unknown> {
  const rows: HenoyoBannerRow[] = [];
  for (const raw of objects(input.props['rows'])) {
    const id = str(raw['id']);
    const message = str(raw['message']);
    const level = str(raw['level']);
    if (id === undefined || message === undefined || level === undefined) continue;
    if (!LEVELS.includes(level)) continue;
    const when = raw['when'];
    if (when !== undefined && when !== null) {
      if (!isObject(when) || input.record === undefined || !ruleHolds(when, input.record, now))
        continue;
    }
    const row = { id, level: level as HenoyoBannerRow['level'], message } as HenoyoBannerRow;
    const reason = str(raw['reason']);
    const actionLabel = str(raw['action_label']);
    const href = str(raw['href']);
    if (href !== undefined) row.href = href;
    if (reason !== undefined) row.reason = reason;
    if (actionLabel !== undefined) row.actionLabel = actionLabel;
    rows.push(row);
  }
  return { rows };
}
