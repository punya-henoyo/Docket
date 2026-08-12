# docket console

One browser console for both halves of docket:

- **Repo scan** — authorize GitHub, pick a repo, pull it read-only, and run the
  deterministic scanners (trivy, semgrep, nuclei) over it. Four ordered stages, polled.
- **Live run** — agents choosing payloads against a target and proving what they find.
  Bursts and stalls unpredictably, so it streams over a WebSocket.

There used to be two consoles, one at the repo root and one here. This is the merge:
Sarthak's console (rail, radar, views, GitHub connect) is the base, with the live-run
half folded in as a fifth view.

**Not part of the tool.** `docket scan` and `docket view` do not need any of this, and
none of it ships in the wheel. It exists so a scan can be demonstrated to people who are
not going to watch a terminal.

## Run it

```bash
uv sync --extra app                          # fastapi + uvicorn
cd app/frontend && npm install && npm run build && cd ../..
uv run python -m app.run                     # http://127.0.0.1:7717
```

Frontend work instead of a demo:

```bash
uv run python -m app.run                     # terminal 1, the API
cd app/frontend && npm run dev               # terminal 2, hot reload on :5173
```

## Seed a demo dataset without an API key

The full-run test drives 4 agents through a real container and produces three findings
whose evidence is real sqlmap output, a real measured latency delta, and a real Chromium
dialog capture. It normally deletes its run directory; keep it instead:

```bash
DOCKET_KEEP_RUN=1 uv run python tests/test_full_run.py
```

That leaves `docket_runs/m9-full-run`, which the app lists like any other run. Needs
Docker, needs no model or key. It is the best thing to open a demo on.

## Live scans

A live scan needs `DOCKET_LLM` and a key in `.env`, plus a target. Start the bundled
vulnerable fixture:

```bash
uv run python tests/serve_target.py 8000     # admin / admin123
```

Then use the Start scan form. Avoid ports 5000 and 7000: macOS binds both to the AirPlay
Receiver.

## Layout

| Path | Role |
|---|---|
| `backend/main.py` | Composes the app, mounts both routers, serves the built console |
| `backend/routers/runs.py` | Local runs: history, payloads, artifacts, WebSocket, scan control |
| `backend/routers/github.py` | Session, repos, auth, repo scans — thin over `interface/connect.py` |
| `backend/scans.py` | Subprocess lifecycle and the loopback target guard |
| `frontend/src/api/` | One client per backend surface, over a shared fetch wrapper |
| `frontend/src/hooks/` | `useRunStream` (WebSocket), `useHashRoute` |
| `frontend/src/views/` | Dashboard, Live run, Findings, Repositories, Integrations |
| `frontend/src/components/` | Radar, FindingsTable, charts, AgentTree, Activity, StatBar, ui |

Routes are split by which half they serve, not by HTTP verb, so a change to one cannot
quietly reach into the other. The GitHub router is thin on purpose: `connect.py` already
separates its logic from its HTTP layer, so this exposes those functions rather than
duplicating 600 lines.

The backend is thin because docket already writes what a UI needs. Run payloads come
straight from `docket.interface.viewer.transcript.build_payload`, the same function the
built-in `docket view --web` dashboard uses, which renders both a live run (from
`events.jsonl` alone) and a finished one (from the validated `report.json`).

## Two decisions worth knowing

**Scans run as subprocesses, not coroutines.** `run_scan()` calls `asyncio.run()`
internally, which raises inside a running event loop — which is where every FastAPI
handler lives. A subprocess sidesteps that and adds process isolation: a scan that dies
inside Playwright cannot take the server with it. Stopping one sends SIGINT to the
process group, so docket writes a report of whatever it confirmed and the container and
sqlmap children die with it, rather than being orphaned.

**Targets are loopback-only by default.** A browser button that fires real exploit
payloads is a foot-gun in front of an audience. `DOCKET_APP_ALLOW_ANY_TARGET=1` lifts it,
and the UI shows a standing banner when it is lifted. The guard keys on the parsed
hostname, not a substring, so `http://evil.test/localhost` is refused.

## Security

Binds to 127.0.0.1 and must stay there. This process can launch one that attacks things.


## Two things that bit during the merge

**One endpoint, one shape.** Both old backends served `/api/runs`, with different shapes —
mine omitted `finding_count` for a run with no report, his required it. The dashboard does
`runs.map(r => r.finding_count)` and feeds that to a chart, so one `undefined` blanked the
whole page. Every row now carries every field, defaulted, and `routers/runs.py`'s demo
asserts it so the shapes cannot drift apart again.

**A display helper must not be able to blank the page.** `ruleLeaf` assumed `rule_id` was
a string. A run with no `report.json` is projected from `events.jsonl`, where a finding
carries `rule_type` but not `rule_id` — and that one missing optional field took the
console down. The `Finding` type now marks what is optional, which immediately surfaced
the same latent crash in `FindingsTable` and `Radar`.
