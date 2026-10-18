// Props for <henoyo-evidence-ledger>: one row per related evidence record when a `source` is
// set, otherwise the authored sample items, passed through as they are.

import type { HenoyoEvidenceItem } from './henoyoEvidenceLedger';
import { isObject, isRelatedListRef, objects, str, type ResolvedInput } from './bindingTypes';
import { label, text } from './rowValues';

const VERDICTS = ['accepted', 'rejected', 'awaiting'];

function sourcedItems(input: ResolvedInput): HenoyoEvidenceItem[] {
  const fields = isObject(input.props['fields']) ? input.props['fields'] : {};
  const verdictMap = isObject(input.props['verdict_map']) ? input.props['verdict_map'] : {};
  const verdictField = str(fields['verdict']);
  const out: HenoyoEvidenceItem[] = [];
  (input.rows['source'] ?? []).forEach((row, index) => {
    const mapped = verdictMap[text(row, verdictField) ?? ''];
    const item: HenoyoEvidenceItem = {
      id: text(row, 'id') ?? `row:${index}`,
      name: label(row, str(fields['name'])) ?? 'Untitled',
      kind: label(row, str(fields['kind'])) ?? '',
      collectedAt: text(row, str(fields['collected_at'])) ?? '',
      // A value the mapping does not name has not been judged yet.
      verdict:
        typeof mapped === 'string' && VERDICTS.includes(mapped)
          ? (mapped as HenoyoEvidenceItem['verdict'])
          : 'awaiting',
    };
    const expiresAt = text(row, str(fields['expires_at']));
    const reviewer = label(row, str(fields['reviewer']));
    if (expiresAt !== undefined) item.expiresAt = expiresAt;
    if (reviewer !== undefined) item.reviewer = reviewer;
    out.push(item);
  });
  return out;
}

export function evidenceLedgerProps(input: ResolvedInput): Record<string, unknown> {
  if (isRelatedListRef(input.props['source'])) {
    return { items: sourcedItems(input), editable: input.props['editable'] === true };
  }
  const items: HenoyoEvidenceItem[] = [];
  for (const raw of objects(input.props['items'])) {
    const id = str(raw['id']);
    const name = str(raw['name']);
    const kind = str(raw['kind']);
    const collectedAt = str(raw['collected_at']);
    const verdict = str(raw['verdict']);
    if (id === undefined || name === undefined || kind === undefined) continue;
    if (collectedAt === undefined || verdict === undefined || !VERDICTS.includes(verdict)) continue;
    const item = {
      id,
      name,
      kind,
      collectedAt,
      verdict: verdict as HenoyoEvidenceItem['verdict'],
    } as HenoyoEvidenceItem;
    const expiresAt = str(raw['expires_at']);
    const reviewer = str(raw['reviewer']);
    if (expiresAt !== undefined) item.expiresAt = expiresAt;
    if (reviewer !== undefined) item.reviewer = reviewer;
    items.push(item);
  }
  return { items, editable: input.props['editable'] === true };
}
