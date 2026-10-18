import { firstText, text } from './rowValues';
import { objects, str, strings, type RecordInput } from './bindingTypes';

import type {
  HenoyoTimelineEvent,
  HenoyoTimelineGap,
  HenoyoTimelineLane,
  HenoyoTimelineMeta,
} from './henoyoRecordTimeline';

function lower(value: string | undefined): string {
  return (value ?? '').trim().toLowerCase();
}

function evaluateGaps(
  props: Record<string, unknown>,
  events: HenoyoTimelineEvent[],
): HenoyoTimelineGap[] | null {
  const rules = objects(props['gap_rules']);
  const causeKinds = strings(props['require_cause_kinds']);
  if (rules.length === 0 && causeKinds.length === 0) return null;

  const gaps: HenoyoTimelineGap[] = [];
  const hasTo = (kind: string, toIn: string[]): boolean => {
    const wanted = new Set(toIn.map(lower));
    return events.some((e) => e.kind === kind && (wanted.size === 0 || wanted.has(lower(e.to))));
  };
  rules.forEach((rule, i) => {
    const when = objects([rule['when']])[0];
    const requires = objects([rule['requires']])[0];
    const whenKind = str(when?.['kind']);
    const requiresKind = str(requires?.['kind']);
    if (whenKind === undefined || requiresKind === undefined) return;
    if (!hasTo(whenKind, strings(when?.['to_in']))) return;
    if (hasTo(requiresKind, strings(requires?.['to_in']))) return;
    gaps.push({ id: str(rule['id']) ?? `gap-${i}`, label: str(rule['label']) ?? 'Gap' });
  });
  const causeSet = new Set(causeKinds);
  for (const e of events) {
    if (causeSet.has(e.kind) && (e.cause ?? '') === '') {
      gaps.push({ id: `cause:${e.id}`, label: `No cause recorded: ${e.title}` });
    }
  }
  return gaps;
}

/** Picklist labels by stored value, e.g. { pending_validation: 'Pending validation' }. */
function labelMap(raw: unknown): Record<string, string> | undefined {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return undefined;
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) if (typeof value === 'string') out[key] = value;
  return Object.keys(out).length > 0 ? out : undefined;
}

export function recordTimelineProps({
  record,
  describe,
  props,
  rows,
}: RecordInput): Record<string, unknown> | null {
  const sources = objects(props['sources']);
  const lanes: HenoyoTimelineLane[] = [];
  const events: HenoyoTimelineEvent[] = [];
  const seen = new Set<string>();
  // Phases are the record's status values, never event titles. Rows whose `to` is not one of them
  // (evidence or control rows logged in the same child object) stay in the feed but are no phase.
  const phaseField = str(props['phase_field']) ?? 'status';
  const picklist = (describe.fields ?? []).find((f) => f.api_name === phaseField)?.picklist_values;
  const phaseNames = new Set<string>();
  const picklistLabels: Record<string, string> = {};
  (picklist ?? []).forEach((p) => {
    phaseNames.add(lower(p.value));
    phaseNames.add(lower(p.label));
    picklistLabels[p.value] = p.label;
  });

  sources.forEach((source, s) => {
    const kind = str(source['kind']) ?? `source-${s}`;
    const lane: HenoyoTimelineLane = { kind, label: str(source['label']) ?? kind };
    const role = str(source['role']);
    if (role !== undefined) lane.role = role;
    lanes.push(lane);

    const ref = objects([source['source']])[0];
    const objectName = str(ref?.['child_object']) ?? kind;
    const requireAt = source['require_at'] === true;
    (rows[`sources.${s}.source`] ?? []).forEach((row, index) => {
      const at = firstText(row, strings(source['at']));
      if (at === undefined && requireAt) return;
      const rowId = text(row, 'id');
      const event: HenoyoTimelineEvent = {
        id: rowId !== undefined ? `${objectName}:${rowId}` : `${objectName}:row:${index}`,
        kind,
        at: at ?? '',
        title: text(row, str(source['title']) ?? 'name') ?? '',
      };
      const actor = firstText(row, strings(source['actor']));
      const from = text(row, str(source['from']));
      const to = text(row, str(source['to']));
      const cause = strings(source['cause'])
        .map((key) => text(row, key))
        .filter((part): part is string => part !== undefined)
        .join(' ');
      const fieldKey = str(source['field']);
      if (fieldKey !== undefined) {
        // `field` names a column on the event row holding the changed field's api name; when the
        // row has none, the placement's constant is used. The object's field label wins if known.
        const apiName = text(row, fieldKey) ?? fieldKey;
        const label = (describe.fields ?? []).find((f) => f.api_name === apiName)?.label;
        event.field = label !== undefined && label !== '' ? label : apiName;
      }
      if (actor !== undefined) event.actor = actor;
      if (from !== undefined) event.from = from;
      if (to !== undefined) event.to = to;
      if (to !== undefined && phaseNames.size > 0 && !phaseNames.has(lower(to)))
        event.phase = false;
      if (cause !== '') event.cause = cause;
      if (seen.has(event.id)) return;
      seen.add(event.id);
      events.push(event);
    });
  });

  const meta: HenoyoTimelineMeta = { lanes };
  const phaseValues = (picklist ?? []).flatMap((p) => [p.value, p.label]);
  if (phaseValues.length > 0) meta.phaseValues = phaseValues;
  const currentStatus = text(record, phaseField);
  if (currentStatus !== undefined) meta.currentStatus = currentStatus;
  const valueLabels =
    labelMap(props['value_labels']) ??
    (Object.keys(picklistLabels).length > 0 ? picklistLabels : undefined);
  if (valueLabels !== undefined) meta.valueLabels = valueLabels;
  const subject = text(record, describe.display_field?.api_name);
  const openedAt = text(record, str(props['opened_field']));
  const dueAt = text(record, str(props['due_field']));
  const closedAt = text(record, str(props['closed_field']));
  if (subject !== undefined) meta.subject = subject;
  if (openedAt !== undefined) meta.openedAt = openedAt;
  if (dueAt !== undefined) meta.dueAt = dueAt;
  if (closedAt !== undefined) meta.closedAt = closedAt;
  if (events.length === 0 && openedAt === undefined) return null;
  return { events, gaps: evaluateGaps(props, events), meta };
}
