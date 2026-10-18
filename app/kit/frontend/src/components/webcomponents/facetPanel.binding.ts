// Props for <henoyo-facet-panel>: authored facet groups, checked and passed through.

import { str, type ResolvedInput } from './bindingTypes';
import { normalizeFacets } from './henoyoFacetPanel';

export function facetPanelProps(input: ResolvedInput): Record<string, unknown> {
  const out: Record<string, unknown> = {
    facets: normalizeFacets(input.props['facets']),
    editable: input.props['editable'] === true,
  };
  const sentence = str(input.props['sentence']);
  if (sentence !== undefined) out['sentence'] = sentence;
  return out;
}
