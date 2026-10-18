// Props for <henoyo-board>: columns from the picklist's own order, one card per related-list row.

import { isObject, isRelatedListRef, str, strings, type RecordInput } from './bindingTypes';
import { label, text } from './rowValues';

import type { BoardRole, HenoyoBoardCard, HenoyoBoardColumn } from './henoyoBoard';

const ROLES: readonly string[] = [
  'stage',
  'outcome_positive',
  'outcome_negative',
  'outcome_neutral',
  'hold',
];

export function boardProps({
  props,
  rows,
  describes,
}: RecordInput): Record<string, unknown> | null {
  const source = props['source'];
  const fields = isObject(props['fields']) ? props['fields'] : {};
  const columnField = str(fields['column']);
  if (!isRelatedListRef(source) || columnField === undefined) return null;
  const field = describes[source.child_object]?.fields.find((f) => f.api_name === columnField);
  if (!field?.picklist_values) return null;
  const roles = isObject(props['roles']) ? props['roles'] : {};
  const columns = field.picklist_values.map<HenoyoBoardColumn>((p) => {
    const role = roles[p.value];
    return {
      value: p.value,
      label: p.label,
      role: (typeof role === 'string' && ROLES.includes(role) ? role : 'stage') as BoardRole,
    };
  });
  const titleField = str(fields['title']);
  const ownerField = str(fields['owner']);
  const severityField = str(fields['severity']);
  const cards: HenoyoBoardCard[] = [];
  (rows['source'] ?? []).forEach((row, index) => {
    const column = text(row, columnField);
    if (column === undefined) return;
    const card: HenoyoBoardCard = {
      id: text(row, 'id') ?? `row:${index}`,
      title: label(row, titleField) ?? 'Untitled',
      column,
    };
    const owner = ownerField === undefined ? undefined : label(row, ownerField);
    const severity = text(row, severityField);
    const due = text(row, str(fields['due']));
    const since = text(row, str(fields['since']));
    if (owner !== undefined) card.owner = owner;
    if (severity !== undefined) card.severity = severity;
    if (due !== undefined) card.due = due;
    if (since !== undefined) card.since = since;
    cards.push(card);
  });
  const out: Record<string, unknown> = {
    columns,
    cards,
    editable: props['editable'] === true && !field.read_only,
    decisionControlled: strings(props['decision_controlled']),
  };
  if (typeof props['max_per_column'] === 'number') out['maxPerColumn'] = props['max_per_column'];
  const title = str(props['title']);
  if (title !== undefined) out['heading'] = title;
  return out;
}
