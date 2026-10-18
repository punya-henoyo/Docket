// Props for <henoyo-stepper>: authored steps passed through as they are, or the values of a record
// picklist field (labels and explanations from the metadata, optionally overridden by `labels` /
// `descriptions`). In picklist mode the record's value is the current step and the steps before it
// are complete.

import { objects, str, strings, type ResolvedInput } from './bindingTypes';
import { resolvePicklistSource } from './picklistSource';
import { text } from './rowValues';

import type { HenoyoStep } from './henoyoStepper';

export function stepperProps(input: ResolvedInput): Record<string, unknown> {
  const { props } = input;
  const source = resolvePicklistSource(input, 'steps', 'id');
  const out: Record<string, unknown> = { steps: [] };
  const saved = str(props['draft_saved_at']);
  if (saved !== undefined) out['draftSavedAt'] = saved;

  if (source?.mode === 'picklist') {
    const field = source.field as string;
    const current = input.record !== undefined ? text(input.record, field) : undefined;
    const at = source.items.findIndex((i) => i.value === current);
    out['steps'] = source.items.map<HenoyoStep>((item, k) => {
      const step: HenoyoStep = { id: item.value, label: item.label };
      if (item.description !== undefined) step.description = item.description;
      if (at >= 0 && k < at) step.complete = true;
      return step;
    });
    if (current !== undefined) out['current'] = current;
    out['editable'] = props['editable'] === true && !source.readOnly;
    out['decisionControlled'] = strings(props['decision_controlled']);
    return out;
  }

  if (source === null) return out;
  const steps: HenoyoStep[] = [];
  for (const raw of objects(props['steps'])) {
    const id = str(raw['id']);
    const label = str(raw['label']);
    if (id === undefined || label === undefined) continue;
    const step: HenoyoStep = { id, label };
    if (raw['complete'] === true) step.complete = true;
    if (raw['error'] === true) step.error = true;
    const summary = str(raw['summary']);
    if (summary !== undefined) step.summary = summary;
    const description = str(raw['description']);
    if (description !== undefined) step.description = description;
    steps.push(step);
  }
  out['steps'] = steps;
  const current = str(props['current']);
  if (current !== undefined) out['current'] = current;
  return out;
}
