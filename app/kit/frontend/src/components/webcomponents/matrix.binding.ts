import { objects, str, isObject, type ResolvedInput } from './bindingTypes';
import { text } from './rowValues';

import type { HenoyoMatrixCell, MatrixValue } from './henoyoMatrix';

const VALUES: readonly string[] = ['met', 'missing', 'unknown', 'na', 'partial'];

function lookup(map: Record<string, unknown>, raw: string): unknown {
  if (raw in map) return map[raw];
  const lower = raw.toLowerCase();
  const key = Object.keys(map).find((k) => k.toLowerCase() === lower);
  return key === undefined ? undefined : map[key];
}

export function matrixProps({ props, rows }: ResolvedInput): Record<string, unknown> | null {
  const items = rows['source'] ?? [];
  if (items.length === 0) return null;
  const labelField = str(props['label_field']);
  const sublabelField = str(props['sublabel_field']);
  const columns = objects(props['columns']).flatMap((column) => {
    const id = str(column['id']);
    return id === undefined
      ? []
      : [
          {
            id,
            label: str(column['label']) ?? id,
            field: str(column['field']),
            map: column['map'],
          },
        ];
  });

  const matrixRows: Record<string, unknown>[] = [];
  const cells: HenoyoMatrixCell[] = [];
  items.forEach((item, index) => {
    const id = text(item, 'id') ?? `row:${index}`;
    const row: Record<string, unknown> = { id, label: text(item, labelField) ?? 'Unnamed' };
    const sublabel = text(item, sublabelField);
    if (sublabel !== undefined) row['sublabel'] = sublabel;
    matrixRows.push(row);
    for (const column of columns) {
      const raw = text(item, column.field) ?? '';
      const mapped = isObject(column.map) ? lookup(column.map, raw) : undefined;
      cells.push({
        row: id,
        col: column.id,
        value: (typeof mapped === 'string' && VALUES.includes(mapped)
          ? mapped
          : 'unknown') as MatrixValue,
      });
    }
  });

  const out: Record<string, unknown> = {
    mode: 'coverage',
    rows: matrixRows,
    columns: columns.map(({ id, label }) => ({ id, label })),
    cells,
  };
  const title = str(props['title']);
  if (title !== undefined) out['heading'] = title;
  return out;
}
