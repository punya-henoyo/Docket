// Props for <henoyo-visual-picker>: a picklist field (labels and descriptions from its metadata,
// optionally overridden by `labels` / `descriptions`) or an authored `options` list.

import { strings, str, type RecordInput } from './bindingTypes';
import { resolvePicklistSource } from './picklistSource';
import { text } from './rowValues';

import type { HenoyoPickerOption } from './henoyoVisualPicker';

export function visualPickerProps({
  record,
  describe,
  props,
}: RecordInput): Record<string, unknown> | null {
  const source = resolvePicklistSource({ props, describe }, 'options');
  if (source === null) return null;
  const options = source.items.map<HenoyoPickerOption>((i) => ({ ...i }));
  const picklist = source.mode === 'picklist';
  const out: Record<string, unknown> = {
    options,
    editable: picklist && props['editable'] === true && !source.readOnly,
    confirm: props['confirm'] === true,
    decisionControlled: picklist ? strings(props['decision_controlled']) : [],
  };
  const selected = source.field !== undefined ? text(record, source.field) : str(props['selected']);
  if (selected !== undefined) out['selected'] = selected;
  const title = str(props['title']);
  if (title !== undefined) out['heading'] = title;
  return out;
}
