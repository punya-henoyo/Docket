import { str, type RecordInput } from './bindingTypes';
import { text } from './rowValues';

/** The person is a field of the open record; a lookup shows its display name. An empty field still draws the empty chip. */
export function personChipProps({ record, props }: RecordInput): Record<string, unknown> {
  const field = str(props['name']);
  const out: Record<string, unknown> = {};
  const name =
    field === undefined ? undefined : (text(record, `${field}__display`) ?? text(record, field));
  if (name !== undefined) out['name'] = name;
  const role = str(props['role']);
  if (role !== undefined) out['personRole'] = role;
  const email = text(record, str(props['email']));
  if (email !== undefined) out['email'] = email;
  const emptyText = str(props['empty_text']);
  if (emptyText !== undefined) out['emptyText'] = emptyText;
  const size = str(props['size']);
  if (size !== undefined) out['size'] = size;
  return out;
}
