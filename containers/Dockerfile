# docket sandbox image — where the agents' shell/HTTP/exploit actions actually execute,
# and where the deterministic scanner pre-scans (docket/tools/scanners/) run.
#
# Deliberately NOT a Kali base. Kali's value is breadth across an unknown estate
# (subdomains, ports, many hosts, mixed CVEs); still cut for that reason, each for a
# concrete reason:
#   ffuf / dirb / param discovery - the test fixture's three routes and exact parameter
#                     names are already known; add when target discovery lands (see
#                     README "Current limits").
#   subdomain enum, port scanning, WAF detection - out of scope for a single target URL.
#   JWT / secret scanning - no JWTs/secrets planted in the fixture yet.
#   OOB/interactsh callback catcher - every fixture vuln is provable in-band (SQLi via
#                     boolean/UNION, RCE via a timing side-channel, XSS via a real
#                     DOM-executed alert), so no external callback listener is needed.
# nuclei/trivy/semgrep ARE installed (below) — unlike the agent's shell/browser tools,
# these run as a deterministic PRE-SCAN (docket/tools/scanners/), not an LLM-chosen
# shell command: their JSON output is parsed straight into a Finding, no transcription
# step to get wrong. trivy/semgrep only run when `--source` mounts real code to scan.
# Build context is the REPO ROOT (see docket/runtime/sandbox.py), not containers/.
FROM python:3.13-slim-bookworm

# Populated by BuildKit ("amd64"/"arm64") — matches nuclei's release-asset naming
# directly, so one URL works on both native Linux/CI and Apple Silicon dev boxes.
ARG TARGETARCH

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        procps \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# sqlmap, pinned to a release tag for deterministic behavior (Debian's package is
# often stale; tracking master would make results drift between runs). This is the one
# tool that turns V1 from "I guessed a payload" into an automated, tool-confirmed
# injection - which is the point of having real tooling rather than just an HTTP client.
ARG SQLMAP_TAG=1.9.9
RUN git clone --depth 1 --branch ${SQLMAP_TAG} \
        https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && rm -rf /opt/sqlmap/.git

# nuclei: pinned release binary (Debian ships nothing recent). Template-matches known
# CVEs/misconfigs deterministically — feeds docket/tools/scanners/nuclei.py, which
# parses its JSON directly into a Finding rather than handing raw output to an LLM.
ARG NUCLEI_VERSION=3.3.7
RUN curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei \
    && nuclei -update-templates -silent || true

# trivy: dependency (SCA) scanning against source mounted at /work/source when
# `--source` is passed. Feeds docket/tools/scanners/trivy.py.
# Pinned release binary, downloaded directly from GitHub — same reasoning as nuclei
# above. The official install.sh (contrib/install.sh) routes through get.trivy.dev,
# which 404'd for this pin during testing; a direct release asset is one less moving
# part to go flaky.
ARG TRIVY_VERSION=0.73.0
RUN case "${TARGETARCH}" in \
      amd64) TRIVY_ARCH=64bit ;; \
      arm64) TRIVY_ARCH=ARM64 ;; \
      *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl -sL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && chmod +x /usr/local/bin/trivy

# semgrep: static-analysis (SAST) scanning, same /work/source mount as trivy. Feeds
# docket/tools/scanners/semgrep.py. Pinned like sqlmap/mitmproxy, for the same reason:
# deterministic results across runs.
# setuptools, PINNED below 81: semgrep's opentelemetry-instrumentation dep imports
# pkg_resources at import time; setuptools dropped that module entirely as of 81 (the
# unpinned install resolved to 84.0.0 and broke `semgrep --version` outright — confirmed
# by running it in the built image, not guessed). 75.8.0 still ships it.
RUN pip install semgrep==1.90.0 setuptools==75.8.0

# sonar-scanner: the CLIENT half of SonarQube. Unlike every other scanner in this image
# it analyses nothing here — it uploads /work/source to a SonarQube Community Build
# server (started by docket/runtime/sonar_service.py) which analyses asynchronously, and
# docket/tools/scanners/sonar.py then pulls the results over the Web API.
#
# The bundled-JRE build, deliberately: this is a python:slim base with no Java, and the
# alternative is apt-installing a JDK that nothing else in the image wants. Costs ~200MB.
# Pinned like nuclei/trivy above, for the same reason — results must not drift between
# runs because a download moved.
# Node.js, required by SonarQube's JavaScript/TypeScript/CSS analyzers — they shell out
# to `node` and abort the ENTIRE analysis if it is missing, not just the JS part. On a
# repo with one .js file in it that looked like:
#   ERROR Error when running: 'node -v'. Is Node.js available during analysis?
#   Caused by: java.io.IOException: Cannot run program "node"
# and the scan reported sonar as failed having analysed nothing. A Python-only image is
# not enough for a scanner that is handed whatever the customer's repo contains.
#
# Pinned like everything else here. SonarQube 26.x supports Node 20/22/24; this is the
# current LTS. The .tar.gz rather than .tar.xz, so no xz-utils is needed on slim.
ARG NODE_VERSION=v24.19.0
RUN case "${TARGETARCH}" in \
      amd64) NODE_ARCH=x64 ;; \
      arm64) NODE_ARCH=arm64 ;; \
      *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl -sL "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-${NODE_ARCH}.tar.gz" -o /tmp/node.tar.gz \
    && tar -xzf /tmp/node.tar.gz -C /opt \
    && rm /tmp/node.tar.gz \
    && mv "/opt/node-${NODE_VERSION}-linux-${NODE_ARCH}" /opt/node \
    && ln -s /opt/node/bin/node /usr/local/bin/node \
    && ln -s /opt/node/bin/npm /usr/local/bin/npm \
    && node --version

ARG SONAR_SCANNER_VERSION=7.0.2.4839
RUN case "${TARGETARCH}" in \
      amd64) SONAR_ARCH=x64 ;; \
      arm64) SONAR_ARCH=aarch64 ;; \
      *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl -sL "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-${SONAR_ARCH}.zip" -o /tmp/sonar.zip \
    && unzip -q /tmp/sonar.zip -d /opt \
    && rm /tmp/sonar.zip \
    && mv "/opt/sonar-scanner-${SONAR_SCANNER_VERSION}-linux-${SONAR_ARCH}" /opt/sonar-scanner \
    && ln -s /opt/sonar-scanner/bin/sonar-scanner /usr/local/bin/sonar-scanner \
    && chmod +x /opt/sonar-scanner/bin/sonar-scanner

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
