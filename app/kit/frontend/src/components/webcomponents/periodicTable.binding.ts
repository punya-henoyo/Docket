import { str, type ResolvedInput } from './bindingTypes';
import { scheme } from './henoyoKit';
import { periodicModel } from './periodicTable.model';

/** A saved report with one grouping, one measure, and the chart's tile layout. */
export function periodicTableProps(input: ResolvedInput): Record<string, unknown> | null {
  const report = input.reports?.['report'];
  if (report === undefined || report.groups.length !== 1 || report.measures.length !== 1)
    return null;
  const heading = str(input.props['title']);
  return {
    model: periodicModel(report, undefined, scheme(str(input.props['colour_scheme']))),
    framed: true,
    ...(heading !== undefined ? { heading } : {}),
  };
}
