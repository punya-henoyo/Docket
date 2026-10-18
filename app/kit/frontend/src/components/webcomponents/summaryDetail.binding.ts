// Props for <henoyo-summary-detail>: the authored items, passed through as they are.

import type { HenoyoSummaryItem, SummaryTone } from './henoyoSummaryDetail';
import { isObject, objects, str, type ResolvedInput } from './bindingTypes';

const TONES: readonly SummaryTone[] = ['neutral', 'info', 'success', 'warning', 'danger'];

const isTone = (v: string): v is SummaryTone => TONES.some((tone) => tone === v);

export function summaryDetailProps(input: ResolvedInput): Record<string, unknown> {
  const items: HenoyoSummaryItem[] = [];
  for (const raw of objects(input.props['items'])) {
    const id = str(raw['id']);
    const title = str(raw['title']);
    if (id === undefined || title === undefined) continue;
    const item: HenoyoSummaryItem = { id, title, details: [] };
    const subtitle = str(raw['subtitle']);
    if (subtitle !== undefined) item.subtitle = subtitle;
    if (isObject(raw['status'])) {
      const label = str(raw['status']['label']);
      const tone = str(raw['status']['tone']);
      if (label !== undefined)
        item.status = { label, tone: tone !== undefined && isTone(tone) ? tone : 'neutral' };
    }
    for (const pair of objects(raw['details'])) {
      const label = str(pair['label']);
      const value = str(pair['value']);
      if (label === undefined || value === undefined) continue;
      item.details.push({ label, value });
    }
    const actionLabel = str(raw['action_label']);
    if (actionLabel !== undefined) item.actionLabel = actionLabel;
    items.push(item);
  }
  const out: Record<string, unknown> = { items };
  const selected = str(input.props['selected']);
  const emptyText = str(input.props['empty_text']);
  if (selected !== undefined) out['selected'] = selected;
  if (emptyText !== undefined) out['emptyText'] = emptyText;
  return out;
}
