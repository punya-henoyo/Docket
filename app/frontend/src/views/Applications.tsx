import { useMemo } from "react";
import type { AppProfile, Application, Level, Portfolio, QuadCell } from "../portfolio";
import { Card, Empty, LevelLabel, PageHead, ago, useSort } from "../hx/components";
import { hx } from "../hx/hx";
import { usePolicyNames } from "./postureParts";
import "./Home.css";

const ORDER: Level[] = ["action", "attention", "unknown", "clear"];

/** What the latest scan proved: the proof column answers "is anything reproduced right now". */
const latest = (a: Application) =>
  a.events.reduce<Application["events"][number] | null>((m, e) => (!m || Date.parse(e.at) > Date.parse(m.at) ? e : m), null);

/** Worst cell first, then the quiet ones, then the best: the order of the sort, not a score. */
const CELL_RANK: Record<QuadCell, number> = { bl: 0, br: 1, tl: 2, tr: 3 };

interface Row { a: Application & AppProfile; proven: number | null; policy: string | null; quadrant: string; rank: number }

const ACCESS = {
  health: (r: Row) => ORDER.indexOf(r.a.level),
  app: (r: Row) => r.a.label,
  tier: (r: Row) => r.a.tier,
  proof: (r: Row) => r.proven,
  last: (r: Row) => r.a.age_days,
  why: (r: Row) => r.a.reason,
  owner: (r: Row) => r.a.owner,
  policy: (r: Row) => r.policy,
  quadrant: (r: Row) => r.rank,
};

export function Applications({ portfolio, go }: { portfolio: Portfolio | null; go: (name: string, param?: string | null) => void }) {
  // worst first is the default order; the third click on any header returns to it
  const names = usePolicyNames();
  const base = useMemo<Row[]>(() => {
    const posture = portfolio?.posture;
    const title = new Map((posture?.quadrants ?? []).map((q) => [q.key, q.title]));
    const point = new Map((posture?.points ?? []).map((p) => [p.id, p]));
    return [...(portfolio?.applications ?? [])]
      .sort((x, y) => ORDER.indexOf(x.level) - ORDER.indexOf(y.level))
      .map((a: Application & AppProfile) => {
        const pt = point.get(a.id);
        const id = a.assignment?.policy ?? a.policy ?? pt?.policy ?? null;
        return {
          a, proven: latest(a)?.proven ?? null,
          policy: id ? names.get(id) ?? pt?.policy_name ?? id : null,
          // an application with no point has no position: it is "Not assessed", never a corner
          quadrant: pt ? title.get(pt.cell) ?? pt.cell : "Not assessed",
          rank: pt ? CELL_RANK[pt.cell] : 4,
        };
      });
  }, [portfolio, names]);
  const { rows, Th } = useSort(base, ACCESS);
  return (
    <>
      <PageHead eyebrow="Code Security" title="Applications"
                sub="Every application the policy covers, worst first. Open one for its health report, scan pipeline and findings."
                actions={<button className={hx("btn primary")} onClick={() => go("repos")}>Add application</button>} />
      <Card title="All applications" flush>
        {!portfolio ? <Empty>Loading applications…</Empty> : rows.length === 0 ? <Empty>No applications yet. Connect a repository to add one.</Empty> : (
          <table className={hx("lv")}>
            <thead>
              <tr>
                <Th k="health">Health</Th><Th k="app">Application</Th><Th k="tier">Tier</Th><Th k="proof">Proof</Th>
                <Th k="last">Last scan</Th><Th k="policy">Policy</Th><Th k="quadrant">Quadrant</Th><Th k="why">Why</Th><Th k="owner">Owner</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ a, proven, policy, quadrant }) => (
                <tr key={a.id} tabIndex={0} onClick={() => go("app", a.id)} onKeyDown={(e) => e.key === "Enter" && go("app", a.id)}>
                  <td className={hx("nw")}><LevelLabel level={a.level} /></td>
                  <td><div className={hx("tt")}>{a.label}</div><div className={hx("ms mono")}>{a.repo} · {a.lang}</div></td>
                  <td className={hx("nw")}>{a.tier}</td>
                  <td className={hx("nw")}>
                    {proven == null
                      ? <span className={hx("proof n")}>Not scanned</span>
                      : proven > 0 ? <span className={hx("proof y")}>◆ {proven} proven</span> : <span className={hx("proof n")}>None proven</span>}
                  </td>
                  <td className={hx("nw")}>{a.age_days == null ? "Never" : a.age_days < 1 ? "Today" : `${ago(a.age_days)} ago`}</td>
                  <td>{policy ?? "None"}</td>
                  <td>{quadrant}</td>
                  <td>{a.reason}</td>
                  <td>{a.owner}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
