import {
  isObject,
  isRelatedListRef,
  objects,
  str,
  strings,
  type RecordInput,
} from './bindingTypes';
import { SEVERITY_ORDER, isMaterial, type Material } from './henoyoKit';
import { label, text } from './rowValues';

import type { ExposureColumn, ExposureMetrics, ExposureNode } from './henoyoExposureTree';
import type { Plan } from '../../data/pageComponents/plan';
import type { RecordRow } from '../../lib/dataApi';

const OPEN = 'open';

/** Step 0 follows the record; each later stage follows the ids found one stage earlier. */
export function exposureTreePlan(props: Record<string, unknown>): Plan {
  const steps = objects(props['steps']);
  const plan: Plan = [];
  steps.forEach((step, i) => {
    const source = step['source'];
    if (!isRelatedListRef(source)) return;
    const previous = steps[i - 1];
    plan.push({
      path: `steps.${i}`,
      child_object: source.child_object,
      relationship: source.relationship,
      ...(i > 0 && previous !== undefined
        ? { from: { path: `steps.${i - 1}`, column: str(previous['to']) ?? '' } }
        : {}),
    });
  });
  const leaf = props['leaf'];
  const last = steps[steps.length - 1];
  if (isObject(leaf) && isRelatedListRef(leaf['source']) && last !== undefined) {
    plan.push({
      path: 'leaf',
      child_object: leaf['source'].child_object,
      relationship: leaf['source'].relationship,
      from: { path: `steps.${steps.length - 1}`, column: str(last['to']) ?? '' },
    });
  }
  return plan;
}

function rank(severity: string | undefined): number {
  const i = SEVERITY_ORDER.indexOf((severity ?? '').toLowerCase());
  return i < 0 ? SEVERITY_ORDER.length : i;
}

function material(value: unknown, fallback: Material): Material {
  return isMaterial(value) ? value : fallback;
}

interface Leaf {
  id: string;
  node: ExposureNode;
  open: boolean;
  severity: string | undefined;
}

function rollup(leaves: readonly Leaf[]): ExposureMetrics {
  const open = leaves.filter((leaf) => leaf.open);
  const worst = open.reduce<string | undefined>(
    (best, leaf) => (rank(leaf.severity) < rank(best) ? leaf.severity : best),
    undefined,
  );
  return { worst, [OPEN]: open.length, total: leaves.length };
}

function byColumn(rows: readonly RecordRow[], column: string): Map<string, RecordRow[]> {
  const out = new Map<string, RecordRow[]>();
  for (const row of rows) {
    const key = text(row, column);
    if (key === undefined) continue;
    out.set(key, [...(out.get(key) ?? []), row]);
  }
  return out;
}

export function exposureTreeProps({
  record,
  describe,
  props,
  rows,
  describes,
  truncated,
}: RecordInput): Record<string, unknown> | null {
  const steps = objects(props['steps']);
  const leafProps = isObject(props['leaf']) ? props['leaf'] : {};
  const leafSource = isRelatedListRef(leafProps['source']) ? leafProps['source'] : undefined;
  if (steps.length === 0 || leafSource === undefined) return null;

  const severityField = str(leafProps['severity_field']);
  const statusField = str(leafProps['status_field']);
  const openStatuses = new Set(strings(leafProps['open_statuses']));
  const countsOpen = statusField !== undefined && openStatuses.size > 0;
  const leafRows = byColumn(rows['leaf'] ?? [], leafSource.relationship);

  const leavesOf = (parentId: string, parentPath: string): Leaf[] => {
    const seen = new Set<string>();
    const out: Leaf[] = [];
    for (const row of leafRows.get(parentId) ?? []) {
      const id = text(row, 'id');
      if (id === undefined || seen.has(id)) continue;
      seen.add(id);
      const severity = text(row, severityField);
      const isOpen = !countsOpen || openStatuses.has(text(row, statusField) ?? '');
      const node: ExposureNode = {
        id: `${parentPath}/${leafSource.child_object}:${id}`,
        objectApiName: leafSource.child_object,
        recordId: id,
        label: text(row, str(leafProps['label_field'])) ?? 'Unnamed',
        material: material(leafProps['material'], 'clay'),
        glyphName: str(leafProps['glyph']) ?? 'file-text',
        metrics: { worst: isOpen ? severity : undefined, [OPEN]: isOpen ? 1 : 0, total: 1 },
        childCount: 0,
      };
      const status = label(row, statusField);
      if (status !== undefined) node.sublabel = status;
      out.push({ id, node, open: isOpen, severity });
    }
    return out.sort(
      (a, b) => Number(b.open) - Number(a.open) || rank(a.severity) - rank(b.severity),
    );
  };

  interface Built {
    nodes: ExposureNode[];
    leaves: Leaf[];
  }
  const build = (level: number, parentId: string, parentPath: string): Built => {
    const step = steps[level];
    if (step === undefined) {
      const leaves = leavesOf(parentId, parentPath);
      return { nodes: leaves.map((leaf) => leaf.node), leaves };
    }
    const source = isRelatedListRef(step['source']) ? step['source'] : undefined;
    const to = str(step['to']);
    if (source === undefined || to === undefined) return { nodes: [], leaves: [] };
    const junctions = rows[`steps.${level}`] ?? [];
    const own =
      level === 0 ? junctions : (byColumn(junctions, source.relationship).get(parentId) ?? []);
    const target = describes[source.child_object]?.parent_relationships.find(
      (r) => r.api_name === to,
    )?.parent_object_api_name;
    const nodes: ExposureNode[] = [];
    const leaves = new Map<string, Leaf>();
    const seen = new Set<string>();
    for (const row of own) {
      const toId = text(row, to);
      if (toId === undefined || seen.has(toId)) continue;
      seen.add(toId);
      const known = text(row, `${to}__object`) ?? target;
      const objectApiName = known ?? to;
      const nodeId = `${parentPath}/${objectApiName}:${toId}`;
      const below = build(level + 1, toId, nodeId);
      below.leaves.forEach((leaf) => leaves.set(leaf.id, leaf));
      const node: ExposureNode = {
        id: nodeId,
        objectApiName,
        recordId: toId,
        ...(known === undefined ? { openable: false } : {}),
        label: text(row, `${to}__display`) ?? 'Unnamed',
        material: material(step['material'], 'sea'),
        glyphName: str(step['glyph']) ?? 'file-text',
        metrics: rollup(below.leaves),
        childCount: below.nodes.length,
        children: below.nodes,
      };
      const edge = label(row, str(step['edge_label_field']));
      if (edge !== undefined) node.edgeLabel = edge;
      nodes.push(node);
    }
    return { nodes, leaves: [...leaves.values()] };
  };

  const rootId = typeof record['id'] === 'string' ? record['id'] : '';
  const rootKey = `${describe.api_name}:${rootId}`;
  const top = build(0, '', rootKey);
  const title = str(props['title']);
  const heading = title === undefined ? {} : { heading: title };
  if (top.nodes.length === 0) return { columns: [], truncated: truncated === true, ...heading };
  const root: ExposureNode = {
    id: rootKey,
    objectApiName: describe.api_name,
    recordId: rootId,
    label: text(record, describe.display_field?.api_name) ?? describe.label,
    material: material(props['root_material'], 'dusk'),
    glyphName: str(props['root_glyph']) ?? 'file-text',
    metrics: rollup(top.leaves),
    childCount: top.nodes.length,
    children: top.nodes,
  };
  const columns: ExposureColumn[] = [
    ...(severityField !== undefined
      ? [{ key: 'worst', label: 'Worst open', format: 'severity' as const }]
      : []),
    ...(countsOpen ? [{ key: OPEN, label: 'Open', format: 'count' as const }] : []),
    { key: 'total', label: 'Total', format: 'count' },
  ];
  return { columns, rootNode: root, truncated: truncated === true, ...heading };
}
