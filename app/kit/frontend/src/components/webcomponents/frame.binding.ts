import { collectSources } from '../../data/pageComponents/plan';
import { reportDetailPath } from '../../shell/systemTabs';
import { humanize, type KitSource } from './henoyoKit';
import { str, type ResolvedInput } from './bindingTypes';

import { KIT_HELP } from './kitHelp';

/** The report or list a kind draws from, as the footer's "From …" link. */
export function sourceOf(input: ResolvedInput): KitSource | undefined {
  const report = input.reports?.['report'];
  if (report !== undefined) {
    const label = str(report.title) ?? str(report.label) ?? humanize(report.report);
    return { label, href: reportDetailPath(report.object, report.report) };
  }
  const children = [...new Set(collectSources(input.props).map((s) => s.child_object))];
  const names = children.map((c) => input.describes[c]?.label_plural ?? humanize(c));
  const first = children[0];
  if (first === undefined) return undefined;
  if (children.length === 1) return { label: names[0]!, href: `/r/${encodeURIComponent(first)}` };
  const more = children.length - 2;
  return {
    label: more > 0 ? `${names[0]}, ${names[1]} and ${more} more` : `${names[0]} and ${names[1]}`,
  };
}

/** What every kind gets besides its own props: the help behind the i, the source footer and the as-of time. */
export function frameProps(
  tag: string,
  input: ResolvedInput,
  asOf: string,
): Record<string, unknown> {
  const out: Record<string, unknown> = { asOf };
  const help = str(input.props['help_text']) ?? KIT_HELP[tag];
  if (help !== undefined) out['helpText'] = help;
  const source = sourceOf(input);
  if (source !== undefined) out['source'] = source;
  return out;
}
