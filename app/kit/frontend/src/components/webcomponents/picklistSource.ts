// One model for every control that lists a picklist's values (visual picker, stepper, status path).
//
// PICKLIST MODE: `field` names a record picklist; the values, order, labels and per-value
//   explanations (help_text) come from the field metadata.
// MANUAL MODE: an authored list (`options` / `steps` / `values`) is used as typed.
// MIXED: in picklist mode, `labels` and `descriptions` maps ({value: text}) override or fill the metadata.
// Exactly one of `field` / the authored list is required; anything else resolves to null.

import { isObject, objects, str, type ResolvedInput } from './bindingTypes';

import type { DescribeResponse } from '../../lib/describe';

export interface PicklistItem {
  value: string;
  label: string;
  description?: string;
}

export interface PicklistSource {
  mode: 'picklist' | 'manual';
  /** The bound field in picklist mode. */
  field?: string;
  readOnly: boolean;
  items: PicklistItem[];
}

function textMap(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!isObject(raw)) return out;
  for (const [k, v] of Object.entries(raw)) {
    const s = str(v);
    if (s !== undefined) out[k] = s;
  }
  return out;
}

/**
 * @param listKey the prop that holds the authored list; `valueKey` is the key an authored entry
 *   uses for its value (`value` for options and values, `id` for stepper steps).
 */
export function resolvePicklistSource(
  input: Pick<ResolvedInput, 'props'> & { describe?: DescribeResponse },
  listKey: string,
  valueKey: 'value' | 'id' = 'value',
): PicklistSource | null {
  const { props, describe } = input;
  const fieldName = str(props['field']);
  const authored = Array.isArray(props[listKey]) && (props[listKey] as unknown[]).length > 0;
  if ((fieldName === undefined) === !authored) return null;

  if (fieldName !== undefined) {
    const field = describe?.fields.find((f) => f.api_name === fieldName);
    if (!field?.picklist_values) return null;
    const labels = textMap(props['labels']);
    const descriptions = textMap(props['descriptions']);
    const items = field.picklist_values.map<PicklistItem>((p) => {
      const item: PicklistItem = { value: p.value, label: labels[p.value] ?? p.label };
      const description = descriptions[p.value] ?? str(p.help_text);
      if (description !== undefined) item.description = description;
      return item;
    });
    return { mode: 'picklist', field: fieldName, readOnly: field.read_only === true, items };
  }

  const items: PicklistItem[] = [];
  for (const raw of objects(props[listKey])) {
    const value = str(raw[valueKey]);
    const label = str(raw['label']);
    if (value === undefined || label === undefined) continue;
    const item: PicklistItem = { value, label };
    const description = str(raw['description']);
    if (description !== undefined) item.description = description;
    items.push(item);
  }
  return { mode: 'manual', readOnly: true, items };
}
