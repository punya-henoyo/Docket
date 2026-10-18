// A record and the related records that lead away from it, one hop per step.
// Shared by the relationship fan and the blast-radius rings.

import type { Plan } from '../../data/pageComponents/plan';
import type { RecordInput } from './bindingTypes';

import { isRelatedListRef, objects, str } from './bindingTypes';
import { emit, esc, humanize, type SeverityKey } from './henoyoKit';
import { text } from './rowValues';
import { OTHER_KEY, severityOf, severityWord } from './vizPalette';

const MAX_PER_RING = 24;
const API_NAME = /^[a-z][a-z0-9_]*$/;

export interface VizNode {
  id: string;
  label: string;
  ring: number;
  objectApiName: string;
  /** What kind of record this is, as a person names it. */
  typeLabel: string;
  recordId: string;
  openable: boolean;
  tip: string;
  severity?: SeverityKey;
}

export interface VizEdge {
  from: string;
  to: string;
}

export interface VizGraph {
  nodes: VizNode[];
  edges: VizEdge[];
  truncated: boolean;
}

interface Draft {
  id: string;
  label: string;
  ring: number;
  objectApiName: string;
  typeLabel: string;
  recordId: string;
  openable: boolean;
  groupKey: string;
}

export function chainPlan(props: Record<string, unknown>): Plan {
  const hops = objects(props['steps']);
  return hops.flatMap((hop, index) => {
    const source = hop['source'];
    if (!isRelatedListRef(source)) return [];
    const previous = hops[index - 1];
    const column = previous === undefined ? '' : (str(previous['to']) ?? '');
    return [
      {
        path: `steps.${index}`,
        child_object: source.child_object,
        relationship: source.relationship,
        ...(index > 0 ? { from: { path: `steps.${index - 1}`, column } } : {}),
      },
    ];
  });
}

export function chainGraph(input: RecordInput): VizGraph {
  const recordId = text(input.record, 'id') ?? '';
  const rootId = `${input.describe.api_name}:${recordId}`;
  const drafts: Draft[] = [
    {
      id: rootId,
      label: text(input.record, input.describe.display_field?.api_name) ?? input.describe.label,
      ring: 0,
      objectApiName: input.describe.api_name,
      typeLabel: input.describe.label,
      recordId,
      openable: API_NAME.test(input.describe.api_name),
      groupKey: '',
    },
  ];
  const edges: VizEdge[] = [];
  const edgeKeys = new Set<string>();
  let parents = [{ id: rootId, recordId }];
  let truncated = input.truncated === true;
  const hops = objects(input.props['steps']);

  hops.forEach((hop, index) => {
    const source = hop['source'];
    if (!isRelatedListRef(source)) return;
    const to = str(hop['to']) ?? '';
    const groupField = str(hop['group_field']);
    const rel = input.describes[source.child_object]?.parent_relationships.find(
      (item) => item.api_name === to,
    );
    const parentIds = new Set(parents.map((parent) => parent.recordId));
    const next: { id: string; recordId: string }[] = [];
    let kept = 0;
    for (const row of input.rows[`steps.${index}`] ?? []) {
      const via = text(row, source.relationship) ?? '';
      if (index > 0 && !parentIds.has(via)) continue;
      const farId = text(row, to);
      const objectApiName = text(row, `${to}__object`) ?? rel?.parent_object_api_name;
      if (farId === undefined || objectApiName === undefined) continue;
      const id = `${objectApiName}:${farId}`;
      const parent = index === 0 ? parents[0] : parents.find((item) => item.recordId === via);
      if (parent === undefined) continue;
      const groupKey = groupField === undefined ? '' : (text(row, groupField) ?? '');
      const existing = drafts.find((node) => node.id === id);
      if (existing !== undefined) {
        if (worse(groupKey, existing.groupKey)) existing.groupKey = groupKey;
      } else if (kept >= MAX_PER_RING) {
        truncated = true;
        continue;
      } else {
        kept += 1;
        drafts.push({
          id,
          label: text(row, `${to}__display`) ?? farId,
          ring: index + 1,
          objectApiName,
          typeLabel: input.describes[objectApiName]?.label ?? humanize(objectApiName),
          recordId: farId,
          openable: API_NAME.test(objectApiName),
          groupKey,
        });
        next.push({ id, recordId: farId });
      }
      const edge = `${parent.id}->${id}`;
      if (!edgeKeys.has(edge)) {
        edgeKeys.add(edge);
        edges.push({ from: parent.id, to: id });
      }
    }
    parents = next;
  });

  return { nodes: describe(drafts, input), edges, truncated };
}

function worse(next: string, current: string): boolean {
  const rank = (key: string): number => {
    const word = severityWord(key);
    if (word === 'Critical') return 0;
    if (word === 'High') return 1;
    if (word === 'Medium') return 2;
    if (word === 'Low') return 3;
    if (word === 'Informational') return 4;
    return 9;
  };
  return next !== '' && rank(next) < rank(current);
}

function describe(drafts: Draft[], input: RecordInput): VizNode[] {
  return drafts.map((node) => {
    const word = severityWord(node.groupKey);
    const tip =
      word !== undefined
        ? `${node.label} — ${word}`
        : node.groupKey === ''
          ? node.label
          : `${node.label} — ${groupLabel(input, node.groupKey)}`;
    const severity = severityOf(node.groupKey);
    return {
      id: node.id,
      label: node.label,
      ring: node.ring,
      objectApiName: node.objectApiName,
      typeLabel: node.typeLabel,
      recordId: node.recordId,
      openable: node.openable,
      tip,
      ...(severity === undefined ? {} : { severity }),
    };
  });
}

function groupLabel(input: RecordInput, key: string): string {
  const word = severityWord(key);
  if (word !== undefined) return word;
  if (key === OTHER_KEY) return 'Other';
  for (const hop of objects(input.props['steps'])) {
    const source = hop['source'];
    const field = str(hop['group_field']);
    if (!isRelatedListRef(source) || field === undefined) continue;
    const option = input.describes[source.child_object]?.fields
      .find((item) => item.api_name === field)
      ?.picklist_values?.find((item) => item.value === key);
    if (option !== undefined) return option.label;
  }
  return humanize(key);
}

export function wireRecordOpen(root: EventTarget, host: HTMLElement): void {
  const go = (event: Event): void => {
    const raw = event.target;
    if (!(raw instanceof Element)) return;
    const target = raw.closest('[data-act="open"]');
    if (target === null) return;
    const objectApiName = target.getAttribute('data-object') ?? '';
    const recordId = target.getAttribute('data-id') ?? '';
    if (objectApiName === '' || recordId === '') return;
    emit(host, 'henoyo:open-record', { objectApiName, recordId });
  };
  root.addEventListener('click', go);
  root.addEventListener('keydown', (event) => {
    if (!(event instanceof KeyboardEvent) || (event.key !== 'Enter' && event.key !== ' ')) return;
    go(event);
  });
}

export function openAttrs(node: Pick<VizNode, 'openable' | 'objectApiName' | 'recordId'>): string {
  if (!node.openable) return '';
  return ` data-act="open" data-object="${esc(node.objectApiName)}" data-id="${esc(node.recordId)}" role="button" tabindex="0"`;
}
