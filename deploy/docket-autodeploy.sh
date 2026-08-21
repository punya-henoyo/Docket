#!/usr/bin/env bash
# Redeploy the docket console whenever origin/main moves. Driven by docket-autodeploy.timer.
#
# POLL, NOT GITHUB ACTIONS — and not by preference:
#   - the repo token lacks the `workflow` scope, so ANY push touching .github/workflows/
#     fails atomically. A workflow file cannot be committed from a normal clone at all.
#   - a push-based deploy needs a private key parked in a CI provider and an inbound path
#     to this VM. Port 22 is already open to 0.0.0.0/0 here; adding a deploy key to that
#     is the wrong direction.
#   - the box already fetches this repo unauthenticated-to-us (credentials are cached in
#     its own git config), so polling introduces no new secret anywhere.
#
# Runs as root because it needs systemctl, but does every git operation as the repo owner
# so nothing in the working tree ends up root-owned and unwritable afterwards.
set -uo pipefail

REPO=/home/sarthak/Docket
BRANCH=main
SVC=docket
HEALTH=http://127.0.0.1:8765/api/session
GIT_USER='sarthak@gptfyai.onmicrosoft.com'
IMAGE=docket-sandbox:latest
GIT=(sudo -u "$GIT_USER" git -C "$REPO")

log() { echo "[docket-autodeploy] $*"; }

"${GIT[@]}" fetch --quiet origin "$BRANCH" || { log "fetch failed"; exit 1; }

LOCAL=$("${GIT[@]}" rev-parse HEAD)
REMOTE=$("${GIT[@]}" rev-parse FETCH_HEAD)
[ "$LOCAL" = "$REMOTE" ] && exit 0    # nothing new — the quiet path, every 2 minutes

# Fast-forward only. A force-push to the deployed branch should stop the pipeline and wait
# for a human, not silently rewrite what is running in front of a customer.
if ! "${GIT[@]}" merge-base --is-ancestor "$LOCAL" "$REMOTE"; then
    log "REFUSING: origin/$BRANCH is not a fast-forward from ${LOCAL:0:8} (forced push?) — no deploy"
    exit 1
fi

log "deploying ${LOCAL:0:8} -> ${REMOTE:0:8}"
"${GIT[@]}" pull --ff-only --quiet origin "$BRANCH" || { log "pull failed"; exit 1; }

# THE SANDBOX IMAGE IS PART OF THE DEPLOY, AND IT IS THE HALF THAT FAILS SILENTLY.
#
# runtime/sandbox.py build_image() is `if not force and image_exists(image): return False`
# — absent, not stale. So after a code deploy the console serves NEW code while every scan
# still runs the OLD engine baked into the existing image. Nothing reports the mismatch;
# the scan looks perfectly healthy and is testing the previous commit.
#
# Rebuild only when the layers that carry our code actually moved. The Dockerfile COPYs
# engine/docket/, so those two paths are the whole trigger; a README-only commit skips a
# multi-minute build.
if "${GIT[@]}" diff --name-only "$LOCAL" "$REMOTE" | grep -qE '^(engine/docket/|containers/Dockerfile)'; then
    log "engine or Dockerfile moved — rebuilding $IMAGE"
    if ! docker build -q -f "$REPO/containers/Dockerfile" -t "$IMAGE" "$REPO" >/dev/null 2>&1; then
        log "image rebuild FAILED — rolling back to ${LOCAL:0:8}, not serving code the sandbox cannot run"
        "${GIT[@]}" reset --hard --quiet "$LOCAL"
        exit 1
    fi
fi

systemctl restart "$SVC"

# A deploy that leaves the console down is worse than no pipeline, so prove it answers
# before declaring success, and put the previous commit back if it does not.
for _ in $(seq 1 15); do
    sleep 2
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$HEALTH" || true)
    if [ "$code" = "200" ]; then
        log "deployed ${REMOTE:0:8} OK (/api/session 200)"
        exit 0
    fi
done

log "HEALTH CHECK FAILED after 30s — rolling back to ${LOCAL:0:8}"
"${GIT[@]}" reset --hard --quiet "$LOCAL"
systemctl restart "$SVC"
exit 1
