# docket sandbox image — where the agents' shell/HTTP/exploit actions actually execute.
#
# Deliberately NOT a Kali base. Kali's value is breadth across an unknown estate
# (subdomains, ports, many hosts, mixed CVEs); vulnshop is one process with three
# known routes, so that breadth buys nothing and costs a multi-GB pull plus a much
# larger patch surface. Cut for this target, each for a concrete reason:
#   nuclei          - template-matches known CVEs/misconfigs; this app has none and no
#                     template will ever match hand-planted business logic.
#   ffuf / dirb / param discovery - nothing to discover; all three routes and their
#                     exact parameter names are already known.
#   subdomain enum, port scanning, WAF detection - one process, one port, no WAF, no DNS.
#   JWT / secret scanning / SAST linters - no JWTs, no planted secrets, and source
#                     review is vulnshop's separate Semgrep workflow, not this tool's job.
#   OOB/interactsh callback catcher - every vuln here is provable in-band (SQLi via
#                     boolean/UNION, RCE via a timing side-channel, XSS via a real
#                     DOM-executed alert), so no external callback listener is needed.
# Build context is the REPO ROOT (see docket/runtime/sandbox.py), not containers/.
FROM python:3.13-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        procps \
    && rm -rf /var/lib/apt/lists/*

# sqlmap, pinned to a release tag for deterministic behavior (Debian's package is
# often stale; tracking master would make results drift between runs). This is the one
# tool that turns V1 from "I guessed a payload" into an automated, tool-confirmed
# injection - which is the point of having real tooling rather than just an HTTP client.
ARG SQLMAP_TAG=1.9.9
RUN git clone --depth 1 --branch ${SQLMAP_TAG} \
        https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && rm -rf /opt/sqlmap/.git

# mitmproxy as the intercepting-proxy tool: open-source and scriptable, unlike the
# commercial GUI-first proxies that ship their own SDK client. Note this target is plain
# HTTP, so there is no TLS to intercept and no CA-cert bootstrap step at all - a real
# chunk of usual proxy setup that simply evaporates here.
RUN pip install mitmproxy

# Playwright + Chromium. This is what makes an XSS finding a PROOF rather than an
# inference: the agent navigates to a reflected alert() payload and captures the real
# dialog the DOM raises, instead of grepping for its own payload in the HTML.
# --with-deps lets playwright apt-install Chromium's shared libraries itself, so there
# is no hand-maintained library list to rot.
RUN pip install playwright \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Source is engine/docket/ on the host but stays /app/docket/ in the image, so the
# in-container import path and CMD below are unaffected by the host-side layout.
COPY engine/docket/ /app/docket/

# The shim itself imports only stdlib-backed modules (shell/http_request/output_store),
# so nothing above is needed to serve tool calls - the deps are for the tools the
# agents invoke, not the transport.
EXPOSE 8765
CMD ["python3", "-m", "docket.runtime.server"]
