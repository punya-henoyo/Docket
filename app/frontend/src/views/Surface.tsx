import type { ScanState } from "../types";
import { SurfacePanel } from "../components/SurfacePanel";
import { Empty, Panel } from "../components/ui";

/** The map, on its own page. It is a different artefact from a findings list: entry
 *  points and an auth model describe what the application IS, not what matched. */
export function Surface({ scan, onGoRepos }: {
  scan: ScanState | null;
  onGoRepos: () => void;
}) {
  return (
    <>
      <div className="page-head">
        <h1>Attack surface</h1>
        {scan?.surface && (
          <div className="head-actions">
            <span className="chip">{scan.surface.entry_points?.length ?? 0} entry points</span>
            <span className="chip">{scan.surface.candidates?.length ?? 0} candidates</span>
          </div>
        )}
      </div>

      {!scan?.recon && !scan?.surface ? (
        <Panel>
          <Empty>
            <div style={{ maxWidth: "52ch" }}>
              Not mapped for this run. Turn on <b>AI recon</b> when starting a scan and an
              agent will read the repository to find where input enters, how auth works, and
              what no scanner rule would flag.
            </div>
            <button className="btn primary" onClick={onGoRepos}>Start a scan</button>
          </Empty>
        </Panel>
      ) : (
        <SurfacePanel scan={scan} title="" />
      )}
    </>
  );
}
