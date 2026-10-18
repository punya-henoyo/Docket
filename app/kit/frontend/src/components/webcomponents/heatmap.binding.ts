import { humanize } from './henoyoKit';
import { isRelatedListRef, str, strings, type ResolvedInput } from './bindingTypes';
import { text } from './rowValues';

import { countScaleProps } from './heatmapScale';
import type { HenoyoMatrixCell } from './henoyoMatrix';

function ordered(chosen: readonly string[], picklist: readonly string[], seen: readonly string[]) {
  if (chosen.length > 0) return [...chosen];
  const extra = [...new Set(seen)].filter((value) => !picklist.includes(value)).sort();
  return [...picklist, ...extra];
}

/** Counts related records per cell of two picklists; without a chosen order, every picklist value is shown in the picklist's order. */
export function heatmapProps({
  props,
  rows,
  describes,
  truncated,
}: ResolvedInput): Record<string, unknown> | null {
  const items = rows['source'] ?? [];
  const rowField = str(props['row_field']);
  const columnField = str(props['column_field']);
  if (rowField === undefined || columnField === undefined) return null;
  const source = props['source'];
  const fields = isRelatedListRef(source) ? describes[source.child_object]?.fields : undefined;
  const picklist = (api: string | undefined): { value: string; label: string }[] =>
    fields?.find((f) => f.api_name === api)?.picklist_values ?? [];

  const counts = new Map<string, number>();
  const rowSeen: string[] = [];
  const colSeen: string[] = [];
  for (const item of items) {
    const row = text(item, rowField);
    const col = text(item, columnField);
    if (row === undefined || col === undefined) continue;
    rowSeen.push(row);
    colSeen.push(col);
    counts.set(`${row}\u0000${col}`, (counts.get(`${row}\u0000${col}`) ?? 0) + 1);
  }
  const rowPick = picklist(rowField);
  const colPick = picklist(columnField);
  const rowKeys = ordered(
    strings(props['row_order']),
    rowPick.map((p) => p.value),
    rowSeen,
  );
  const colKeys = ordered(
    strings(props['column_order']),
    colPick.map((p) => p.value),
    colSeen,
  );
  const nameOf = (pick: { value: string; label: string }[], key: string): string =>
    pick.find((p) => p.value === key)?.label ?? humanize(key);

  const cells: HenoyoMatrixCell[] = rowKeys.flatMap((row) =>
    colKeys.map((col) => ({ row, col, value: counts.get(`${row}\u0000${col}`) ?? 0 })),
  );
  const out: Record<string, unknown> = {
    mode: 'heatmap',
    rows: rowKeys.map((key) => ({
      id: key,
      label: nameOf(rowPick, key),
      ...(props['severity_rows'] === true ? { severity: key } : {}),
    })),
    columns: colKeys.map((key) => ({ id: key, label: nameOf(colPick, key) })),
    cells,
    truncated: truncated === true,
  };
  const title = str(props['title']);
  if (title !== undefined) out['heading'] = title;
  return { ...out, ...countScaleProps(props) };
}
