import { useMemo } from "react";
import type { Application, Level, Origin, Portfolio } from "../portfolio";
import { Card, Empty, Lamp, OriginChip, PageHead, ago } from "../hx/components";
import { hx } from "../hx/hx";
import { Kit } from "../kit/Kit";
import "./Home.css";

type Go = (name: string, param?: string | null) => void;

/** One required step of the default policy, and how many applications ran it inside the cadence
 *  window (api-contract.md, GET /api/portfolio). Not yet in src/portfolio.ts, so declared here. */
interface ScannerCoverage { id: string; label: string; tool?: string | null; origin: Origin; required?: boolean; current: number; of: number }
type HomePortfolio = Portfolio & { scanner_coverage?: ScannerCoverage[] };

/** The kit's palette helper, exposed by app/kit/globals.ts. Series need paint to be drawn. */
type KitGlobal = { paint?: (key: string, index?: number) => Record<string, unknown> };
const paint = (key: string): Record<string, unknown> =>
  (window as unknown as { HenoyoKit?: KitGlobal }).HenoyoKit?.paint?.(key) ?? {};

const ORDER: Level[] = ["action", "attention", "unknown", "clear"];
const DAY = 86_400_000;
const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

const lastScan = (a: Application) =>
  a.age_days == null ? "" : a.age_days < 1 ? "Scanned today" : `Scanned ${ago(a.age_days)} ago`;

function Lead({ counts, total }: { counts: Record<Level, number>; total: number }) {
  if (total === 0) return <span className={hx("lead")}>No applications yet. Connect a repository and Docket will scan it.</span>;
  const { action, attention, unknown, clear } = counts;
  const rest = [
    attention ? `${attention}${action ? " more" : ""} ${plural(attention, "needs", "need")} a look this week` : "",
    unknown ? `${unknown} ${plural(unknown, "has", "have")} never been scanned` : "",
    clear ? `${clear} ${plural(clear, "is", "are")} clear` : "",
  ].filter(Boolean);
  const tail = rest.length > 1 ? `${rest.slice(0, -1).join(", ")}, and ${rest[rest.length - 1]}.` : rest[0] ? `${rest[0]}.` : "";
  return (
    <span className={hx("lead")}>
      {action
        ? <b>{action} of {total} {plural(total, "application needs", "applications need")} action today.</b>
        : <b className={hx("calm")}>No application needs action today.</b>}
      {tail ? ` ${tail}` : ""}
    </span>
  );
}

function QueueGroup({ title, apps, go }: { title: string; apps: Application[]; go: Go }) {
  if (!apps.length) return null;
  return (
    <>
      <li className={hx("wqh")}>{title}<b>{apps.length}</b></li>
      {apps.map((a) => (
        <li key={a.id} tabIndex={0} onClick={() => go("app", a.id)}
            onKeyDown={(e) => e.key === "Enter" && go("app", a.id)}>
          <div><Lamp level={a.level} /></div>
          <div>
            <div className={hx("t")}>{a.label} <span className={hx("chip neutral")} style={{ marginLeft: 6 }}>{a.tier}</span></div>
            <div className={hx("r")}>{a.reason}</div>
          </div>
          <div className={hx("age")}>
            {a.level === "unknown" ? null : lastScan(a)}
            <span className={hx("go")}>{a.level === "unknown" ? "Connect repo" : "Open"} →</span>
          </div>
        </li>
      ))}
    </>
  );
}

function Posture({ portfolio, go }: { portfolio: HomePortfolio; go: Go }) {
  const { applications: apps, counts } = portfolio;
  const by = (l: Level) => apps.filter((a) => a.level === l);
  const act = by("action"), att = by("attention"), unk = by("unknown");

  const kit = useMemo(() => {
    const asOf = portfolio.generated_at;
    const to = Date.parse(asOf);
    const trend = portfolio.trend;
    const sa = portfolio.severity_age;
    return {
      ring: {
        heading: "Application health", showPercent: false, centerLabel: "applications",
        finding: `${act.length} need action, ${att.length} need a look`,
        helpText: "Every application is in one state. Act today means a reproduced exploit, a secret in code, or a broken policy. Watch means something to look at this week.",
        parts: [
          { label: "Act today", count: counts.action, tone: "bad" },
          { label: "Watch", count: counts.attention, tone: "warn" },
          { label: "Clear", count: counts.clear, tone: "ok" },
          { label: "Not scanned", count: counts.unknown, tone: "neutral" },
        ],
        source: { label: "Docket scans" }, asOf,
      },
      continuum: {
        heading: "Scan continuum",
        rows: [...apps].sort((a, b) => ORDER.indexOf(a.level) - ORDER.indexOf(b.level))
          .map((a) => ({ id: a.id, label: a.label, sub: a.tier, level: a.level, events: a.events })),
        from: new Date(to - portfolio.window_days * DAY).toISOString(), to: asOf, cadenceDays: portfolio.cadence_days,
        helpText: "Every scan of every application. A red diamond is a scan that proved an exploit. Amber hatching is time beyond the policy cadence with no scan.",
        source: { label: "Docket scans" }, asOf,
      },
      trend: {
        heading: "Open findings and candidates, by week",
        helpText: "What was open at the end of each week, by severity. It counts scanner candidates as well as proven exploits, so read the shape, not the headline percentage.",
        periods: trend.periods, series: trend.series.map((s) => ({ ...s, ...paint(s.key) })),
        source: { label: "Findings" }, asOf,
      },
      sevAge: {
        heading: "Open findings and candidates by severity and age",
        colourScheme: "editorial",
        oldCritical: sa.old_critical, oldAge: sa.old_age,
        rows: sa.rows.map((s) => ({ id: s, label: s.charAt(0).toUpperCase() + s.slice(1), tone: s })),
        columns: sa.columns.map((c) => ({ id: c, label: `${c.replace("-", " to ")} days`, tone: "" })),
        cells: sa.cells,
        helpText: "How many open items sit in each severity and age band, candidates included. Darker means more items; the row says how severe. Old criticals are the ones to chase.",
        source: { label: "Findings" }, asOf,
      },
    };
    // everything above derives from the payload; a re-poll that changes nothing keeps the elements still
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [portfolio]);
  const events = useMemo(() => ({
    "docket:open-app": (d: Record<string, string | undefined>) => d.id && go("app", d.id),
    "docket:open-scan": (d: Record<string, string | undefined>) => d.id && go("scan", d.id),
  }), [go]);

  const cov = portfolio.scanner_coverage ?? [];
  return (
    <div className={hx("stack")}>
      <div className={hx("cols")}>
        <Card title="Needs you" flush sub="Worst first. Only the first group needs someone today."
              tip="Applications that are not clear, grouped by urgency. Each line says why in one sentence.">
          {act.length + att.length + unk.length === 0
            ? <Empty>Nothing needs you. Every scanned application is clear.</Empty>
            : (
              <ul className={hx("wq")}>
                <QueueGroup title="Act today" apps={act} go={go} />
                <QueueGroup title="Watch this week" apps={att} go={go} />
                <QueueGroup title="Not scanned" apps={unk} go={go} />
              </ul>
            )}
        </Card>
        <div className={hx("stack")}>
          <Kit tag="henoyo-ring" props={kit.ring} />
          {cov.length ? (
            <Card title="Required scanners, this week" sub={`Inside the ${portfolio.cadence_days}-day window`}
                  tip={`How many applications ran each scanner the policy requires, inside the ${portfolio.cadence_days}-day window. Verdant is a Henoyo-built scanner; grey is a third-party tool Docket runs for you.`}>
              {cov.map((s) => (
                <div key={s.id} className={hx("covrow")}>
                  <div className={hx("cl")}><OriginChip origin={s.origin} name={s.tool ?? undefined} /><span className={hx("cn")}>{s.label}</span></div>
                  <div className={hx("cbar")} role="img" aria-label={`${s.current} of ${s.of} applications ran ${s.label} inside ${portfolio.cadence_days} days`}>
                    <span className={s.origin === "henoyo" ? "h" : "t"} style={{ width: `${s.of ? (s.current / s.of) * 100 : 0}%` }} />
                  </div>
                  <div className={hx("cc")}>{s.current} of {s.of}</div>
                </div>
              ))}
            </Card>
          ) : null}
        </div>
      </div>
      <Kit tag="docket-continuum" props={kit.continuum} on={events} />
      <div className={hx("cols2")}>
        <Kit tag="henoyo-discovery-trend" props={kit.trend} />
        <Kit tag="henoyo-severity-age" props={kit.sevAge} />
      </div>
    </div>
  );
}

export function Home({ portfolio, error, go }: { portfolio: Portfolio | null; error: string | null; go: Go }) {
  const actions = (
    <>
      <button className={hx("btn")} onClick={() => go("policy")}>Policy</button>
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
  return (
    <>
      <PageHead eyebrow="Code Security" title="Posture" actions={actions}
                sub={<Lead counts={portfolio.counts} total={portfolio.applications.length} />} />
      {error ? <div className={hx("notice bad")} role="alert" style={{ marginBottom: 16 }}>Showing the last data loaded. The latest refresh failed: {error}</div> : null}
      <Posture portfolio={portfolio} go={go} />
    </>
  );
}
