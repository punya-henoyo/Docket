import { createElement, useEffect, useRef, type CSSProperties } from "react";

/** Mounts a Henoyo Visual Kit element (or one of Docket's own: docket-pipeline,
 *  docket-health-card, docket-continuum, docket-policy-matrix) and hands it data.
 *
 *  Kit elements take data through PROPERTIES, not attributes, and emit composed
 *  `henoyo:*` / `docket:*` CustomEvents, so the wrapper does exactly those two things and
 *  nothing else. The elements are registered by /assets/kit/henoyo-kit.js, loaded from
 *  index.html before this bundle runs. */
export function Kit({
  tag,
  props,
  on,
  className,
  style,
}: {
  tag: string;
  props: Record<string, unknown>;
  /** Event name -> handler, e.g. { "docket:open-app": (d) => go(`app/${d.id}`) }. */
  on?: Record<string, (detail: Record<string, string | undefined>) => void>;
  className?: string;
  style?: CSSProperties;
}) {
  const ref = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (el) Object.assign(el, props);
    // Runs when the props object changes, not on every render: a caller that memoises its props keeps
    // the element still (a setter such as `snapshots` resets the map's scrubber). Callers that pass a
    // fresh object each render behave exactly as before.
  }, [props]);

  useEffect(() => {
    const el = ref.current;
    if (!el || !on) return;
    const bound = Object.entries(on).map(([name, fn]) => {
      const listener = (e: Event) => fn((e as CustomEvent).detail ?? {});
      el.addEventListener(name, listener);
      return [name, listener] as const;
    });
    return () => bound.forEach(([name, l]) => el.removeEventListener(name, l));
  }, [on]);

  return createElement(tag, { ref, className, style: { display: "block", ...style } });
}
