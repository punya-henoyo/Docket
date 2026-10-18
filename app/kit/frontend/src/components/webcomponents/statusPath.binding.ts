import { isObject, objects, str, strings, type RecordInput } from './bindingTypes';
import { resolvePicklistSource } from './picklistSource';
import { label, text } from './rowValues';

import type { HenoyoStatusValue, StatusRole } from './henoyoStatusPath';

const ROLES: readonly string[] = [
  'stage',
  'outcome_positive',
  'outcome_negative',
  'outcome_neutral',
  'hold',
];

export function statusPathProps({
  record,
  describe,
  props,
}: RecordInput): Record<string, unknown> | null {
  const source = resolvePicklistSource({ props, describe }, 'values');
  if (source === null) return null;
  const picklist = source.mode === 'picklist';
  const roles = isObject(props['roles']) ? props['roles'] : {};
  // Manual values carry their own role; picklist values take it from the `roles` map.
  const authoredRole = new Map(
    objects(props['values']).map((v) => [str(v['value']), v['role']] as const),
  );
  const values = source.items.map<HenoyoStatusValue>((p) => {
    const role = picklist ? roles[p.value] : authoredRole.get(p.value);
    const value: HenoyoStatusValue = {
      value: p.value,
      label: p.label,
      role: (typeof role === 'string' && ROLES.includes(role) ? role : 'stage') as StatusRole,
    };
    if (p.description !== undefined) value.description = p.description;
    return value;
  });
  const out: Record<string, unknown> = {
    values,
    // On a record page the path is editable unless the layout says false; the host then
    // applies the user's permissions.
    editable: picklist && props['editable'] !== false && !source.readOnly,
    decisionControlled: picklist ? strings(props['decision_controlled']) : [],
    // A record page gets the slim bar unless the layout asks for the card.
    variant: props['variant'] === 'card' ? 'card' : 'bar',
  };
  const current = source.field !== undefined ? text(record, source.field) : str(props['current']);
  if (current !== undefined) out['current'] = current;
  const title = str(props['title']);
  if (title !== undefined) out['heading'] = title;
  const since = text(record, str(props['since']));
  if (since !== undefined) out['since'] = since;
  const ownerField = str(props['owner']);
  if (ownerField !== undefined) out['owner'] = label(record, ownerField) ?? 'Unassigned';
  const ownerLabel = str(props['owner_label']);
  if (ownerLabel !== undefined) out['ownerLabel'] = ownerLabel;
  return out;
}
