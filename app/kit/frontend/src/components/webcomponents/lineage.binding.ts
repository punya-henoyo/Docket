import { isObject, objects, str, type RecordInput } from './bindingTypes';
import { isMaterial } from './henoyoKit';
import { label, text } from './rowValues';

import type { LineageEdge, LineageNode } from './henoyoLineageGraph';
import type { Material } from './henoyoKit';
import type { RecordRow } from '../../lib/dataApi';

const TONES = ['warn', 'bad', 'info'];

function material(value: unknown, fallback: Material): Material {
  return isMaterial(value) ? value : fallback;
}

function flagFor(flags: unknown, raw: string | undefined): LineageEdge['flag'] {
  if (raw === undefined || !isObject(flags) || !isObject(flags[raw])) return undefined;
  const flag = flags[raw];
  const flagLabel = str(flag['label']);
  const tone = str(flag['tone']);
  return flagLabel !== undefined && tone !== undefined && TONES.includes(tone)
    ? { label: flagLabel, tone: tone as 'warn' | 'bad' | 'info' }
    : undefined;
}

export function lineageProps({
  record,
  describe,
  props,
  rows,
  describes,
  truncated,
}: RecordInput): Record<string, unknown> | null {
  const centerId = `${describe.api_name}:${typeof record['id'] === 'string' ? record['id'] : ''}`;
  const nodes = new Map<string, LineageNode>([
    [
      centerId,
      {
        id: centerId,
        label: text(record, describe.display_field?.api_name) ?? describe.label,
        material: material(props['center_material'], 'dusk'),
        glyphName: str(props['center_glyph']) ?? 'network',
      },
    ],
  ]);
  const edges: LineageEdge[] = [];
  objects(props['legs']).forEach((leg, i) => {
    const other = str(leg['other']);
    const source = isObject(leg['source']) ? str(leg['source']['child_object']) : undefined;
    if (other === undefined) return;
    const target = describes[source ?? '']?.parent_relationships.find(
      (r) => r.api_name === other,
    )?.parent_object_api_name;
    const inbound = leg['direction'] !== 'outbound';
    const edgeField = str(leg['edge_label_field']);
    const rowsOfLeg: readonly RecordRow[] = rows[`legs.${i}.source`] ?? [];
    for (const row of rowsOfLeg) {
      const otherId = text(row, other);
      if (otherId === undefined) continue;
      const object = text(row, `${other}__object`) ?? target;
      const nodeId = `${object ?? other}:${otherId}`;
      if (!nodes.has(nodeId)) {
        const node: LineageNode = {
          id: nodeId,
          label: text(row, `${other}__display`) ?? 'Unnamed',
          material: material(leg['material'], 'sand'),
          glyphName: str(leg['glyph']) ?? 'file-text',
          ...(object !== undefined ? { objectApiName: object, recordId: otherId } : {}),
        };
        const group = str(leg['group_label']);
        if (group !== undefined) node.group = group;
        nodes.set(nodeId, node);
      }
      const edge: LineageEdge = inbound
        ? { from: nodeId, to: centerId }
        : { from: centerId, to: nodeId };
      const edgeLabel = label(row, edgeField);
      if (edgeLabel !== undefined) edge.label = edgeLabel;
      const flag = flagFor(leg['flags'], text(row, edgeField));
      if (flag !== undefined) {
        edge.flag = flag;
        delete edge.label;
      }
      edges.push(edge);
    }
  });
  const out: Record<string, unknown> = {
    nodes: edges.length === 0 ? [] : [...nodes.values()],
    edges,
    truncated: truncated === true,
  };
  const title = str(props['title']);
  if (title !== undefined) out['heading'] = title;
  return out;
}
