#!/bin/bash
# Live view of a running scan. Usage: ./watch-scan.sh [scan-id]
#
# Reads the API for scan state AND the session database for triage progress. The API
# only publishes verdicts when the run finishes, so mid-run it always reports 0 judged;
# the session db is written per agent turn and shows what is really happening.
sid="${1:-$(ls -td docket_runs/connect-* 2>/dev/null | head -1 | sed 's|.*/connect-||')}"
[ -z "$sid" ] && { echo "no runs found"; exit 1; }
echo "watching $sid   (ctrl-c to stop)"
while :; do
python3 - "$sid" <<'PY'
import glob, json, os, sqlite3, sys, time, urllib.request
sid = sys.argv[1]
try:
    s = json.loads(urllib.request.urlopen(f"http://127.0.0.1:8765/api/scan/{sid}", timeout=5).read())
except Exception as e:
    print(f"  server unreachable ({type(e).__name__})"); sys.exit(0)

want = s.get("triage_max") or 0
db = glob.glob(f"docket_runs/connect-{sid}/.state/sessions.db")
done = running = 0
if db:
    try:
        c = sqlite3.connect(f"file:{db[0]}?mode=ro", uri=True)
        ids = [r[0] for r in c.execute(
            "select distinct session_id from agent_messages where session_id like 'triage-%'")]
        # An agent that produced a verdict has its result in the store; one that has
        # only messages is still working. Started-minus-one is the honest live count.
        done, running = max(0, len(ids) - 1), min(len(ids), 1) if ids else 0
    except Exception:
        pass
bar = ("#" * int(20 * done / want)).ljust(20) if want else ""
# SQLite in WAL mode writes to <db>-wal, not the db file, so timing the db file
# reported a busy scan as idle for minutes. Take the newest of both.
    mtimes = [os.path.getmtime(p) for p in (db[0], db[0] + "-wal") if os.path.exists(p)]
    age = f"{time.time()-max(mtimes):.0f}s ago" if mtimes else "-"
print(f"  {s['status']:<9} [{bar}] ~{done}/{want} agents done"
      f"{' (+1 running)' if running else ''}   {s['finding_count']} findings"
      f"   last activity {age}", flush=True)
sys.exit(9 if s["status"] in ("done", "error") else 0)
PY
  [ $? -eq 9 ] && break
  sleep 5
done
