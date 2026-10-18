/** Class helper for the Henoyo chrome: hx("chip crit") -> "hx-chip hx-crit". Keeps the
 *  prefix in one place so the stylesheet and the components cannot drift. */
export const hx = (names: string): string =>
  names.split(/\s+/).filter(Boolean).map((n) => `hx-${n}`).join(" ");
