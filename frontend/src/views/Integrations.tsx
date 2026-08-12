import { AUTH_START } from "../api";
import type { Session } from "../types";
import { Panel } from "../components/ui";

export function Integrations({ session }: { session: Session | null }) {
  const connected = session?.connected ?? false;
  const configured = session?.configured ?? false;
  const scope = session?.scope ?? "repo";

  return (
    <>
      <div className="page-head">
        <h1>Integrations</h1>
      </div>

      <div className="cols">
        <Panel title="GitHub" action={<span className="chip">{scope}</span>}>
          <div className="note" style={{ color: "var(--ink-2)" }}>
            Authorize once and docket can scan any repository your account reaches, including
            ones you only collaborate on. Nobody else has to install anything, and you can
            revoke it from GitHub at any time.
          </div>

          <div className="eyebrow">What this grants</div>
          <ul className="scopes">
            <li>
              <span className="yes">✓</span>
              <span>
                Every repo your account can reach, <b>owned or collaborated on</b>
              </span>
            </li>
            <li>
              <span className="no">!</span>
              <span>
                The <b>{scope}</b> scope also carries <b>write</b> access. GitHub publishes no
                read-only scope for private code, so this cannot be narrowed further.
              </span>
            </li>
          </ul>
          <div className="note">
            Docket only ever reads. It clones nothing and pushes nothing — source arrives as a
            tarball precisely so there is no remote to push back to.
          </div>

          {connected ? (
            <div className="note good">Connected as {session?.login ?? "GitHub user"}.</div>
          ) : configured ? (
            <a
              className="btn primary"
              href={AUTH_START}
              style={{ textDecoration: "none", alignSelf: "flex-start" }}
            >
              Connect GitHub
            </a>
          ) : (
            <>
              <button className="btn primary" disabled>
                Connect GitHub
              </button>
              <div className="note bad">
                Not configured. Register an OAuth App, then set the two variables below and
                restart <span className="mono">docket connect</span>.
              </div>
            </>
          )}
        </Panel>

        <Panel title="Setting it up">
          <div className="note" style={{ color: "var(--ink-2)" }}>
            GitHub → Settings → Developer settings → <b>OAuth Apps</b> → New OAuth App. Three
            fields, no permissions to pick and no install step. Set the callback to:
          </div>
          <div className="evidence">
            <pre>http://127.0.0.1:8765/auth/callback</pre>
          </div>
          <div className="note" style={{ color: "var(--ink-2)" }}>
            Then export the credentials:
          </div>
          <div className="evidence">
            <pre>{`export DOCKET_GITHUB_CLIENT_ID=...
export DOCKET_GITHUB_CLIENT_SECRET=...
docket connect`}</pre>
          </div>
          <div className="note">
            <span className="mono">DOCKET_GITHUB_SCOPE</span> defaults to{" "}
            <span className="mono">repo</span>. Set it to <span className="mono">public_repo</span>{" "}
            to limit docket to public repositories.
          </div>
        </Panel>

        <Panel title="Scope of this build" dashed>
          <ul className="scopes">
            <li>
              <span className="yes">✓</span>
              <span>Authorize, list repos, fetch source, scan, show findings</span>
            </li>
            <li>
              <span className="yes">✓</span>
              <span>CSRF-checked callback; the token never reaches the browser</span>
            </li>
            <li>
              <span className="no">✗</span>
              <span>
                Session is <b>in memory</b> — no accounts, no tenant isolation, and a
                write-capable token with nowhere safe to persist it
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
              <span>AI agents do not run here; the static scanners do</span>
            </li>
          </ul>
        </Panel>
      </div>
    </>
  );
}
