// Pure text helpers for <henoyo-record-timeline>: turn raw enum values into labels.

export type ValueLabels = Record<string, string>;

const RAW = /^[a-z0-9_]+$/;

/** "pending_validation" reads as "Pending validation"; anything already readable is kept. */
export function humanize(value: string, labels?: ValueLabels): string {
  const known = labels?.[value];
  if (known !== undefined && known !== '') return known;
  if (!RAW.test(value)) return value;
  const text = value.replace(/_/g, ' ');
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/**
 * An event title as people read it. Raw audit titles such as "status pending_validation"
 * become "Status: Pending validation", or "Status: Open → In remediation" when the
 * old and new values are known. Titles that are already prose are left alone.
 */
export function eventTitle(
  title: string,
  from?: string,
  to?: string,
  labels?: ValueLabels,
): string {
  const t = title.trim();
  if (RAW.test(t)) return humanize(t, labels);
  const m = /^([a-z][a-z0-9_]*) ([a-z0-9_]+)$/.exec(t);
  if (m === null) return title;
  const field = humanize(m[1] ?? '');
  const hasTo = to !== undefined && to !== '';
  const hasFrom = from !== undefined && from !== '';
  const next = humanize(hasTo ? to : (m[2] ?? ''), labels);
  return hasFrom && hasTo ? `${field}: ${humanize(from, labels)} → ${next}` : `${field}: ${next}`;
}

/** An empty old value, including the placeholders a row may carry ("—", "-", "null", "none"). */
export function isBlank(value: string | undefined): boolean {
  if (value === undefined) return true;
  const v = value.trim().toLowerCase();
  return v === '' || v === '—' || v === '–' || v === '-' || v === 'null' || v === 'none';
}

export interface EventTitleParts {
  title: string;
  /** The original sentence when a field and old/new values replaced it; shown as the subtitle. */
  detail?: string;
}

/**
 * Like eventTitle, but when the event names a field and has an old and/or new value the title is
 * always "Field: old → new", even if the stored title is a sentence. The sentence moves to
 * `detail` so its cause is not lost. Without field or value data the title is left as it is.
 */
export function eventTitleParts(
  title: string,
  from?: string,
  to?: string,
  labels?: ValueLabels,
  field?: string,
  phaseValues?: string[],
): EventTitleParts {
  const hasTo = !isBlank(to);
  const hasFrom = !isBlank(from);
  const f = field?.trim() ?? '';
  if (f === '' || (!hasTo && !hasFrom)) return { title: eventTitle(title, from, to, labels) };
  // No old value and a new value that is not one of the field's status values (an evidence title
  // logged in the same child object) is not a transition: show the stored title as it is.
  if (!hasFrom && hasTo && phaseValues !== undefined && phaseValues.length > 0) {
    const known = new Set(phaseValues.map((v) => v.trim().toLowerCase()));
    if (!known.has((to ?? '').trim().toLowerCase())) return { title: eventTitle(title) };
  }
  const name = humanize(f);
  const old = hasFrom ? humanize(from ?? '', labels) : '';
  const next = hasTo ? humanize(to ?? '', labels) : '';
  const built =
    hasFrom && hasTo
      ? `${name}: ${old} → ${next}`
      : hasTo
        ? `${name}: ${next}`
        : `${name}: ${old} →`;
  const t = title.trim();
  const generic = t === '' || RAW.test(t) || /^[a-z][a-z0-9_]* [a-z0-9_]+$/.test(t);
  return generic ? { title: built } : { title: built, detail: title };
}
