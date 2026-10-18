import { isObject, isRelatedListRef, str, strings, type ResolvedInput } from './bindingTypes';
import { humanize } from './henoyoKit';
import { label, text } from './rowValues';

import type { HenoyoRingPart, HenoyoRingTone } from './henoyoRing';
import type { Plan } from '../../data/pageComponents/plan';

/** Server-side `only` filter, so the page cap applies to the rows that count. */
export function ringPlan(props: Record<string, unknown>): Plan {
  const source = props['source'];
  if (!isRelatedListRef(source)) return [];
  const only = props['only'];
  const field = isObject(only) ? str(only['field']) : undefined;
  const values = isObject(only) ? strings(only['values']) : [];
  return [
    {
      path: 'source',
      child_object: source.child_object,
      relationship: source.relationship,
      ...(field !== undefined && values.length > 0 ? { in: { [field]: values } } : {}),
    },
  ];
}

export function ringProps({
  props,
  rows,
  describes,
  truncated,
}: ResolvedInput): Record<string, unknown> | null {
  const groupBy = str(props['group_by']);
  const source = props['source'];
  if (groupBy === undefined || !isRelatedListRef(source) || !isObject(props['segments'])) {
    return null;
  }
  const segments = props['segments'];
  const items = rows['source'] ?? [];
  const picklist = describes[source.child_object]?.fields.find(
    (f) => f.api_name === groupBy,
  )?.picklist_values;

  const counts = new Map<string, { count: number; shown: string | undefined }>();
  for (const item of items) {
    const key = text(item, groupBy);
    if (key === undefined || !(key in segments)) continue;
    const entry = counts.get(key) ?? { count: 0, shown: label(item, groupBy) };
    entry.count += 1;
    counts.set(key, entry);
  }
  // Stored JSON does not keep key order, so segments follow the picklist, not the map.
  const listed = picklist?.map((p) => p.value) ?? [];
  const order = [
    ...listed.filter((key) => key in segments),
    ...Object.keys(segments).filter((key) => !listed.includes(key)),
  ];
  const all = order.flatMap((key) => {
    const tone = segments[key];
    if (typeof tone !== 'string') return [];
    const entry = counts.get(key);
    return [
      {
        label: picklist?.find((p) => p.value === key)?.label ?? entry?.shown ?? humanize(key),
        count: entry?.count ?? 0,
        tone: tone as HenoyoRingTone,
      },
    ];
  });
  const total = all.reduce((sum, part) => sum + part.count, 0);
  const parts: HenoyoRingPart[] = total === 0 ? all : all.filter((part) => part.count > 0);
  const out: Record<string, unknown> = { parts, truncated: truncated === true };
  const title = str(props['title']);
  if (title !== undefined) out['heading'] = title;
  const center = str(props['center_label']);
  if (center !== undefined) out['centerLabel'] = center;
  return out;
}
