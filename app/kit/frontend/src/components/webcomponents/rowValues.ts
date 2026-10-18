import { humanize } from './henoyoKit';

import type { RecordRow } from '../../lib/dataApi';

export function text(row: RecordRow, key: string | undefined): string | undefined {
  if (key === undefined) return undefined;
  const value = row[key];
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

export function firstText(row: RecordRow, keys: readonly string[] | undefined): string | undefined {
  for (const key of keys ?? []) {
    const value = text(row, key);
    if (value !== undefined) return value;
  }
  return undefined;
}

export function label(row: RecordRow, key: string | undefined): string | undefined {
  if (key === undefined) return undefined;
  const shown = text(row, `${key}__display`);
  if (shown !== undefined) return shown;
  const raw = text(row, key);
  return raw === undefined ? undefined : humanize(raw);
}
