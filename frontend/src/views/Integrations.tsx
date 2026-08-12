import { AUTH_START } from "../api";
import type { Session } from "../types";
import { Panel } from "../components/ui";

export function Integrations({ session }: { session: Session | null }) {
  const connected = session?.connected ?? false;
  const configured = session?.configured ?? false;

  return (
    <>
      <div className="page-head">
        <h1>Integrations</h1>
      </div>

      <div className="cols">
        <Panel title="GitHub">
          <div className="note" style={{ color: "var(--ink-2)" }}>
            Authorize docket on the repositories you want scanned. You pick which ones, docket
            sees nothing outside that selection, and you can revoke it from GitHub at any time.
          </div>

          <div className="eyebrow">Permissions requested</div>
          <ul className="scopes">
            <li>
              <span className="yes">✓</span>
              <span>
                <b>Contents: read</b> — download the source to scan it
              </span>
            </li>
            <li>
              <span className="yes">✓</span>
              <span>
                <b>Metadata: read</b> — list the repositories you selected
              </span>
            </li>
          </ul>
          <div className="note">No write access. Docket opens no branches and pushes no commits.</div>

          {connected ? (
            <div className="note good">Connected as {session?.login ?? "GitHub user"}.</div>
          ) : configured ? (
            <a className="btn primary" href={AUTH_START} style={{ textDecoration: "none", alignSelf: "flex-start" }}>
              Connect GitHub
            </a>
          ) : (
            <>
              <button className="btn primary" disabled>
                Connect GitHub
              </button>
              <div className="note bad">
                Not configured. Register a GitHub App, then set the two environment variables
                below and restart <span className="mono">docket connect</span>.
              </div>
            </>
          )}
        </Panel>

        <Panel title="Setting it up">
          <div className="note" style={{ color: "var(--ink-2)" }}>
            GitHub → Settings → Developer settings → <b>GitHub Apps</b> → New. Enable “Request
            user authorization (OAuth) during installation”, set the callback to:
          </div>
          <div className="evidence">
            <pre>http://127.0.0.1:8765/auth/callback</pre>
          </div>
          <div className="note" style={{ color: "var(--ink-2)" }}>
            Then export the app's credentials:
          </div>
          <div className="evidence">
            <pre>{`export DOCKET_GITHUB_CLIENT_ID=...
export DOCKET_GITHUB_CLIENT_SECRET=...
docket connect`}</pre>
          </div>
          <div className="note">
            A classic OAuth App cannot do this read-only: its <span className="mono">repo</span>{" "}
            scope grants write access too. Only a GitHub App has{" "}
            <span className="mono">contents: read</span>.
          </div>
        </Panel>

        <Panel title="Scope of this build" dashed>
          <ul className="scopes">
            <li>
              <span className="yes">✓</span>
              <span>Authorize, list repos, fetch source read-only, scan, show findings</span>
            </li>
            <li>
              <span className="yes">✓</span>
              <span>CSRF-checked callback; the token never reaches the browser</span>
            </li>
            <li>
              <span className="no">✗</span>
              <span>
                Session is <b>in memory</b> — no accounts, no tenant isolation
              </span>
            </li>
            <li>
              <span className="no">✗</span>
              <span>
                Scans run on a thread, not a <b>job queue</b> — one at a time, no retries
              </span>
            </li>
            <li>
              <span className="no">✗</span>
              <span>
                AI agents do not run here — route discovery is still hardcoded to the test
                fixture, so only the static scanners are wired
              </span>
            </li>
          </ul>
        </Panel>
      </div>
    </>
  );
}
