import { objects, str, type RecordInput } from './bindingTypes';
import { text } from './rowValues';

import type { HenoyoDeadline } from './henoyoDeadlineClock';

export function deadlineClockProps(
  { record, props }: RecordInput,
  now: Date = new Date(),
): Record<string, unknown> | null {
  const deadlines: HenoyoDeadline[] = [];
  for (const spec of objects(props['deadlines'])) {
    const due = text(record, str(spec['due']));
    const id = str(spec['id']);
    if (due === undefined || id === undefined) continue;
    const deadline: HenoyoDeadline = { id, label: str(spec['label']) ?? id, due };
    const metAt = text(record, str(spec['met']));
    const basis = str(spec['basis']);
    if (metAt !== undefined) deadline.metAt = metAt;
    if (basis !== undefined) deadline.basis = basis;
    deadlines.push(deadline);
  }
  if (deadlines.length === 0) return null;
  const anchorSpec = objects([props['anchor']])[0] ?? {};
  const anchorAt = text(record, str(anchorSpec['field']));
  const out: Record<string, unknown> = {
    anchor:
      anchorAt !== undefined
        ? { label: str(anchorSpec['label']) ?? 'Start', at: anchorAt }
        : { label: 'Today', at: now.toISOString() },
    deadlines,
  };
  const title = str(props['title']);
  if (title !== undefined) out['heading'] = title;
  return out;
}
