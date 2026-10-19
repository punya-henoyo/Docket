import { useMemo } from "react";
import type { Level, Portfolio, Posture, PostureCategory, PostureLeader, QuadCell } from "../portfolio";
import { Card, Empty, Help, LEVELS, Lamp, PageHead } from "../hx/components";
import { hx } from "../hx/hx";
import { Kit } from "../kit/Kit";
import { firstSeenOf, moveWords, useStable } from "./postureParts";
import "./Home.css";

type Go = (name: string, param?: string | null) => void;

/** The kit's palette helper, exposed by app/kit/globals.ts. Series need paint to be drawn. */
type KitGlobal = { paint?: (key: string, index?: number) => Record<string, unknown> };
const paint = (key: string): Record<string, unknown> =>
  (window as unknown as { HenoyoKit?: KitGlobal }).HenoyoKit?.paint?.(key) ?? {};

const ORDER: Level[] = ["action", "attention", "unknown", "clear"];
const DAY = 86_400_000;
const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);
const longDate = (iso: string) =>
  new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });

/** Cells are decided by the server per application; this only counts the dots in each. */
const inCell = (p: Posture, k: QuadCell) => p.points.filter((x) => x.cell === k).length;

/** The headline: one bold sentence, then one short one. Counts come from the map's own dots. */
function Headline({ posture, total }: { posture: Posture; total: number }) {
  const bl = inCell(posture, "bl"), br = inCell(posture, "br"), tl = inCell(posture, "tl");
  const un = posture.unassessed.length;
  const first = posture.leaders.worst[0];
  const lead = bl
    ? <b>{bl} of {total} {plural(bl, "application has", "applications have")} proven problems and overdue checks.</b>
    : br
      ? <b>{br} of {total} {plural(br, "application has", "applications have")} proven problems open.</b>
      : <b className={hx("calm")}>No application has a proven problem open.</b>;
  const bits = [
    tl ? `${tl} ${plural(tl, "is", "are")} quiet only because checks are overdue` : "",
    un ? `${un} ${plural(un, "is", "are")} not assessed` : "",
  ].filter(Boolean);
  const second = [first ? `${first.label} first` : "", bits.join(" and ")].filter(Boolean).join("; ");
  return (
    <span className={hx("lead")}>
      {lead}
      {second ? <span className={hx("h2")}>{second}.</span> : null}
    </span>
  );
}

function Num({ value, label, tone, tip }: { value: string | number; label: string; tone?: string; tip: string }) {
  return (
    <div className={hx(`count ${tone ?? ""}`)}>
      <b>{value}</b>
      <span>{label}<Help text={tip} /></span>
    </div>
  );
}

/** One row of "Look here first" / "Clearest right now": a button, so it takes focus and Enter or Space. */
function LeaderRow({ l, posture, go }: { l: PostureLeader; posture: Posture; go: Go }) {
  const tone = LEVELS[l.level].tone;
  const point = posture.points.find((p) => p.id === l.id);
  const moved = moveWords(l.moved, l.moved_since, firstSeenOf(point));
  return (
    <li>
      <button type="button" className={hx("lrow")} onClick={() => go("app", l.id)}
              aria-label={`${l.label}, ${LEVELS[l.level].word}. ${l.reason}.${moved ? ` ${moved}.` : ""} Open application`}>
        <span className={hx("lamp-col")}><Lamp level={l.level} /></span>
        <span className={hx("lb")}>
          <span className={hx("t")}>
            {l.label} <span className={hx("chip neutral")}>{l.tier}</span>
            <span className={hx(`lw ${tone}`)}>{LEVELS[l.level].word}</span>
          </span>
          <span className={hx("r")}>{l.reason}</span>
          {moved ? <span className={hx("mv")}>{moved}</span> : null}
        </span>
      </button>
    </li>
  );
}

function CategoryRow({ c }: { c: PostureCategory }) {
  const bits = [
    c.levels.action ? `${c.levels.action} need action` : "",
    c.levels.attention ? `${c.levels.attention} to watch` : "",
  ].filter(Boolean).join(", ");
  return (
    <div className={hx("covrow cat")}>
      <div className={hx("cl")}><span className={hx("cn")}>{c.key}</span><span className={hx("cs")}>{bits || "None need attention"}</span></div>
      <div className={hx("cbar")} role="img" aria-label={`${c.checks_current} of ${c.apps} applications have every required check current`}>
        <span className="h" style={{ width: `${c.apps ? (c.checks_current / c.apps) * 100 : 0}%` }} />
      </div>
      <div className={hx("cc")}>{c.checks_current} of {c.apps}</div>
    </div>
  );
}

function PostureHome({ portfolio, posture, go }: { portfolio: Portfolio; posture: Posture; go: Go }) {
  const { applications: apps, counts } = portfolio;
  const total = apps.length;
  const sa = portfolio.severity_age;

  // The one total this page adds up: every category's "required checks current" count. The server
  // does not send the sum (see the report); each term is its own server number.
  const currentN = posture.categories.reduce((a, c) => a + c.checks_current, 0);
  const currentOf = posture.categories.reduce((a, c) => a + c.apps, 0);

  // The map is the part that must not redraw on a quiet re-poll: its setters reset the scrubber.
  const stable = useStable({ ...posture, as_of: "" });
  const asOf = useMemo(() => posture.as_of, [stable]); // eslint-disable-line react-hooks/exhaustive-deps
  const quad = useMemo(() => ({
    heading: "Posture map",
    points: stable.points, unassessed: stable.unassessed, quadrants: stable.quadrants,
    snapshots: stable.snapshots, bySnapshot: stable.by_snapshot,
    asOfNote: `As of ${longDate(asOf)}.`,
    source: { label: "Docket scans" }, asOf,
  }), [stable, asOf]);

  const rest = useMemo(() => {
    const as = portfolio.generated_at;
    const to = Date.parse(as);
    const W = posture.assessments.weekly;
    return {
      weekly: {
        heading: "Assessments, by week",
        periods: W.map((w) => ({ key: w.label, label: w.label })),
        series: ([["proven", "Proven", "critical"], ["candidates", "Candidates", "medium"], ["clean", "Clean", "low"], ["incomplete", "Incomplete", "info"]] as const)
          .map(([key, label, sev]) => ({ key, label, ...paint(sev), values: W.map((w) => w[key]) })),
        helpText: "Each scan or pull-request check, by the worst thing it found: proven (a reproduced exploit or a deterministic secret), incomplete (coverage partial or failed), candidates (scanner hits nobody has proven), or clean. Candidates never move a dot on the map.",
        source: { label: "Docket scans" }, asOf: as,
      },
      continuum: {
        heading: "Scan continuum",
        rows: [...apps].sort((a, b) => ORDER.indexOf(a.level) - ORDER.indexOf(b.level))
          .map((a) => ({ id: a.id, label: a.label, sub: a.tier, level: a.level, events: a.events })),
        from: new Date(to - portfolio.window_days * DAY).toISOString(), to: as, cadenceDays: portfolio.cadence_days,
        helpText: "Every scan of every application. A red diamond is a scan that proved an exploit. Amber hatching is time beyond the policy cadence with no scan.",
        source: { label: "Docket scans" }, asOf: as,
      },
      sevAge: {
        heading: "Open findings and candidates by severity and age",
        colourScheme: "editorial",
        oldCritical: sa.old_critical, oldAge: sa.old_age,
        rows: sa.rows.map((s) => ({ id: s, label: s.charAt(0).toUpperCase() + s.slice(1), tone: s })),
        columns: sa.columns.map((c) => ({ id: c, label: `${c.replace("-", " to ")} days`, tone: "" })),
        cells: sa.cells,
        helpText: "How many open items sit in each severity and age band, candidates included. Darker means more items; the row says how severe. Old criticals are the ones to chase.",
        source: { label: "Findings" }, asOf: as,
      },
    };
    // everything above derives from the payload; a re-poll that changes nothing keeps the elements still
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [portfolio]);

  const events = useMemo(() => ({
    "docket:open-app": (d: Record<string, string | undefined>) => d.id && go("app", d.id),
    "docket:open-scan": (d: Record<string, string | undefined>) => d.id && go("scan", d.id),
  }), [go]);

  const { worst, best } = posture.leaders;
  return (
    <div className={hx("stack")}>
      <div className={hx("res six")}>
        <Num value={total} label="Applications" tip="Every application the policies cover, assessed or not." />
        <Num value={posture.assessments.total} label={`Assessments in ${posture.assessments.days} days`}
             tip="A scan or a pull-request check. Candidates and clean results count; only proven problems move a dot." />
        <Num value={counts.action} label="Need action today" tone="bad"
             tip="Applications with a reproduced exploit, a secret in code or a broken policy. Reproduced exploits stay counted until an exploit run shows them closed." />
        <Num value={`${currentN} of ${currentOf}`} label="Required checks current" tone="ok"
             tip="Applications whose every required check finished inside its window. This is about running the checks, not a verdict on any regulation." />
        <Num value={posture.unassessed.length} label="Not assessed" tone="un"
             tip="No scan has run, so there is no position. They sit in the tray under the map." />
        <Num value={sa.old_critical} label={`Criticals open over ${sa.old_age}`} tone="na"
             tip="Open critical items older than this. A critical that stays open is the one to chase first." />
      </div>

      <div className={hx("mapcols")}>
        <Kit tag="docket-quadrant" props={quad} on={events} />
        <div className={hx("stack")}>
          <Card title="Look here first" flush sub="Proven problems first, then overdue checks."
                tip="The three applications to open first: reproduced exploits before anything else, then overdue checks, then the fewest problems open.">
            {worst.length
              ? <ol className={hx("wq wql")}>{worst.map((l) => <LeaderRow key={l.id} l={l} posture={posture} go={go} />)}</ol>
              : <Empty>No application needs action or a watch.</Empty>}
          </Card>
          <Card title="Clearest right now" flush sub="Checks current, nothing proven."
                tip="Never padded: fewer than three means fewer than three qualify. Not 'best' and not 'safest'.">
            {best.length ? (
              <>
                <ol className={hx("wq wql")}>{best.map((l) => <LeaderRow key={l.id} l={l} posture={posture} go={go} />)}</ol>
                <p className={hx("note flat")}>Only applications whose required checks are current and have nothing proven open. That is not a promise of safety.</p>
              </>
            ) : <Empty>No application currently has current checks and nothing proven open.</Empty>}
          </Card>
        </div>
      </div>

      <div className={hx("cols2")}>
        <Card title="Required checks current, by category" sub="Under each application's own policy"
              tip="Grouped by category and exposure. A bar is the share of applications whose required checks are all current under their own policy. Not applicable steps are left out of both counts.">
          {posture.categories.length ? posture.categories.map((c) => <CategoryRow key={c.key} c={c} />) : <Empty>No application has a policy yet.</Empty>}
          <p className={hx("note")} style={{ marginTop: 12 }}>Applications whose every required check finished inside its window. This counts checks that ran; it is not a verdict on any regulation.</p>
        </Card>
        <Kit tag="henoyo-discovery-trend" props={rest.weekly} />
      </div>
      <Kit tag="docket-continuum" props={rest.continuum} on={events} />
      <Kit tag="henoyo-severity-age" props={rest.sevAge} />
    </div>
  );
}

export function Home({ portfolio, error, go }: { portfolio: Portfolio | null; error: string | null; go: Go }) {
  const actions = (
    <>
      <button className={hx("btn")} onClick={() => go("policy")}>Policies</button>
      <button className={hx("btn primary")} onClick={() => go("repos")}>Run a scan</button>
    </>
  );
  if (!portfolio) {
    return (
      <>
        <PageHead eyebrow="Code Security" title="Posture" actions={actions} />
        {error
          ? <div className={hx("notice bad")} role="alert"><b>Could not load the portfolio.</b> {error}</div>
          : <Empty>Loading the portfolio…</Empty>}
      </>
    );
  }
  const posture = portfolio.posture;
  const total = portfolio.applications.length;
  return (
    <>
      <PageHead eyebrow="Code Security" title="Posture" actions={actions}
                sub={posture && total
                  ? <Headline posture={posture} total={total} />
                  : <span className={hx("lead")}>{total ? "Posture needs a newer docket server." : "No applications yet. Connect a repository and Docket will scan it."}</span>} />
      {error ? <div className={hx("notice bad")} role="alert" style={{ marginBottom: 16 }}>Showing the last data loaded. The latest refresh failed: {error}</div> : null}
      {posture && total
        ? <PostureHome portfolio={portfolio} posture={posture} go={go} />
        : <Empty>{total ? "This server does not send posture data yet." : "Nothing to show until an application is connected."}</Empty>}
    </>
  );
}
