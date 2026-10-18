// Approval chain binding: one slot per function (role), showing its LATEST decision.
//
// Several source rows may share a role (a decline followed by a re-sign-off). Rows are grouped by
// the raw role value; the group's slot is its latest row, so the summary is computed from latest
// decisions only (all roles signed => Approved). Slot order is the order_by order of each group's
// first row. Earlier decided rows that differ from the winner surface as `previous` (history).
//
// "Latest" is decided by a recency key, compared in this order:
//   1. decided_at (signed_at) when present, else created_at, else updated_at. A pending row with a
//      null signed_at therefore ranks by when it was created: it never outranks a signed row for
//      the same role unless it was created later (a pending reset after the decision).
//   2. created_at, then 3. updated_at (later wins).
//   4. the raw ISO strings of those keys, compared lexicographically (keeps microsecond precision
//      when two timestamps are equal once truncated to milliseconds).
//   5. source position (later row wins) when everything else ties.
// A row with no usable date at all ranks below any dated row. Dates that do not parse count as
// missing. Fields `created_at` and `updated_at` are read from `fields.created_at` /
// `fields.updated_at`, defaulting to those column names.
import { isMaterial } from './henoyoKit';
import { isObject, str, type RecordInput } from './bindingTypes';
import { label, text } from './rowValues';

import type { RecordRow } from '../../lib/dataApi';
import type {
  ApprovalStatus,
  HenoyoApprovalRequester,
  HenoyoApprovalSlot,
} from './henoyoApprovalChain';

const STATUSES: readonly string[] = ['pending', 'approved', 'rejected', 'skipped', 'not_required'];

function fieldOf(fields: Record<string, unknown>, key: string): string | undefined {
  return str(fields[key]);
}

function compareValues(a: unknown, b: unknown): number {
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  const sa = String(a);
  const sb = String(b);
  const ta = Date.parse(sa);
  const tb = Date.parse(sb);
  if (typeof a === 'string' && typeof b === 'string' && !Number.isNaN(ta) && !Number.isNaN(tb))
    return ta - tb;
  return sa.localeCompare(sb);
}

function sortRows(items: RecordRow[], field: string | undefined): RecordRow[] {
  if (field === undefined) return items;
  const missing = (v: unknown): boolean => v === null || v === undefined || v === '';
  return [...items].sort((x, y) => {
    const a = x[field];
    const b = y[field];
    if (missing(a) || missing(b)) return missing(a) === missing(b) ? 0 : missing(a) ? 1 : -1;
    return compareValues(a, b);
  });
}

function time(v: string | undefined): number {
  if (v === undefined) return Number.NEGATIVE_INFINITY;
  const t = Date.parse(v);
  return Number.isNaN(t) ? Number.NEGATIVE_INFINITY : t;
}

interface Candidate {
  slot: HenoyoApprovalSlot;
  primary: number;
  created: number;
  updated: number;
  /** Raw ISO strings (decided, created, updated); '' when missing. */
  raw: [string, string, string];
  index: number;
  /** Best available decision date: decided_at, else created_at, else updated_at. */
  when?: string;
}

function newer(a: Candidate, b: Candidate): boolean {
  if (a.primary !== b.primary) return a.primary > b.primary;
  if (a.created !== b.created) return a.created > b.created;
  if (a.updated !== b.updated) return a.updated > b.updated;
  for (let i = 0; i < 3; i++) {
    const x = a.raw[i]!;
    const y = b.raw[i]!;
    if (x !== y) return x > y;
  }
  return a.index > b.index;
}

export function approvalChainProps({
  record,
  props,
  rows,
}: RecordInput): Record<string, unknown> | null {
  const source = rows['source'] ?? [];
  if (source.length === 0) return null;
  const items = sortRows(source, str(props['order_by']));
  const fields = isObject(props['fields']) ? props['fields'] : {};
  const statusMap = isObject(props['status_map']) ? props['status_map'] : {};
  const roleField = fieldOf(fields, 'role');
  const statusField = fieldOf(fields, 'status');
  const actorField = fieldOf(fields, 'actor');
  const decidedField = fieldOf(fields, 'decided_at');
  const noteField = fieldOf(fields, 'note');

  const createdField = fieldOf(fields, 'created_at') ?? 'created_at';
  const updatedField = fieldOf(fields, 'updated_at') ?? 'updated_at';

  const candidates = items.map<{ key: string; c: Candidate }>((row, index) => {
    const raw = text(row, statusField) ?? '';
    const mapped = statusMap[raw];
    const slot: HenoyoApprovalSlot = {
      id: text(row, 'id') ?? `row:${index}`,
      role: label(row, roleField) ?? '',
      status: (typeof mapped === 'string' && STATUSES.includes(mapped)
        ? mapped
        : 'unknown') as ApprovalStatus,
    };
    const actor = text(row, actorField);
    const decidedAt = text(row, decidedField);
    const note = text(row, noteField);
    const name = actorField === undefined ? undefined : text(row, `${actorField}__display`);
    if (actor !== undefined) slot.actor = actor;
    if (name !== undefined) slot.actorName = name;
    if (decidedAt !== undefined) slot.decidedAt = decidedAt;
    if (note !== undefined) slot.note = note;
    const createdRaw = text(row, createdField);
    const updatedRaw = text(row, updatedField);
    const created = time(createdRaw);
    const updated = time(updatedRaw);
    const primary =
      [time(decidedAt), created, updated].find((t) => t > Number.NEGATIVE_INFINITY) ??
      Number.NEGATIVE_INFINITY;
    const key = text(row, roleField) ?? slot.role;
    const when = decidedAt ?? text(row, createdField) ?? text(row, updatedField);
    return {
      key,
      c: {
        slot,
        primary,
        created,
        updated,
        raw: [decidedAt ?? '', createdRaw ?? '', updatedRaw ?? ''],
        index,
        ...(when !== undefined ? { when } : {}),
      },
    };
  });

  const groups = new Map<string, Candidate[]>();
  for (const { key, c } of candidates) {
    const g = groups.get(key);
    if (g === undefined) groups.set(key, [c]);
    else g.push(c);
  }
  const slots = [...groups.values()].map((g) => {
    const sorted = [...g].sort((a, b) => (newer(a, b) ? -1 : 1));
    const slot = sorted[0]!.slot;
    const prev = sorted
      .slice(1)
      .find(
        (c) =>
          c.slot.status !== slot.status &&
          c.slot.status !== 'pending' &&
          c.slot.status !== 'unknown',
      );
    if (prev !== undefined)
      slot.previous =
        prev.when !== undefined
          ? { status: prev.slot.status, decidedAt: prev.when }
          : { status: prev.slot.status };
    return slot;
  });

  const out: Record<string, unknown> = {
    mode: props['mode'] === 'parallel' ? 'parallel' : 'sequential',
    material: isMaterial(props['material']) ? props['material'] : 'brass',
    slots,
  };
  const title = str(props['title']);
  if (title !== undefined) out['heading'] = title;
  const glyph = str(props['glyph']);
  if (glyph !== undefined) out['glyphName'] = glyph;
  const requester = requesterOf(props['requester'], record);
  if (requester !== undefined) out['requester'] = requester;
  return out;
}

function requesterOf(
  config: unknown,
  record: RecordInput['record'],
): HenoyoApprovalRequester | undefined {
  if (!isObject(config)) return undefined;
  const actor = text(record, str(config['actor']));
  if (actor === undefined) return undefined;
  const requester: HenoyoApprovalRequester = { actor };
  const name = text(record, `${str(config['actor'])}__display`);
  if (name !== undefined) requester.actorName = name;
  const at = text(record, str(config['at']));
  if (at !== undefined) requester.at = at;
  const lbl = str(config['label']);
  if (lbl !== undefined) requester.label = lbl;
  return requester;
}
