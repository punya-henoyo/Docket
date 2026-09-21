# Docket — Software Bill of Materials

`sbom/docket.cdx.json` · CycloneDX 1.6 · 89 components · generated 2026-09-21

Regenerate with `make sbom`. `make sbom-check` fails if the committed copy and a
fresh generation disagree, so this can be checked rather than trusted.

## Why this is not just a dependency scan

A scanner reading this repository's lockfiles sees the Python and npm packages
and stops. Three further kinds of component are part of what docket delivers:

- **What the sandbox ships.** Every scan executes semgrep, nuclei, trivy,
  mitmproxy and Chromium inside the container built by `containers/Dockerfile`.
  Versions are parsed from that file, so they cannot drift from what is built.
- **Third-party content.** 50 agent playbooks are derived from the strix project
  under Apache-2.0 (`NOTICE`). No lockfile records prose.
- **Why each package is here.** Every transitive package below carries the
  shortest path back to a dependency docket declared, from `uv.lock`'s graph.

## Components by origin

| Origin | Count | What it is |
|---|---|---|
| `core` | 73 | required by docket's four declared runtime dependencies |
| `extra:app` | 6 | only installed with `--extra app` (the console) |
| `sandbox-image` | 6 | executed inside the scan container |
| `console-bundle` | 3 | delivered to a browser; build tooling excluded |
| `vendored-content` | 1 | third-party material under an attribution obligation |

## Licences

87 of 89 components declare one.

| Licence | Components |
|---|---|
| MIT | 42 |
| Apache-2.0 | 16 |
| BSD-3-Clause | 13 |
| PSF-2.0 | 2 |
| BSD License | 2 |
| Apache-2.0 AND MIT | 1 |
| MPL-2.0 | 1 |
| MIT-0 | 1 |
| Apache-2.0 OR BSD-3-Clause | 1 |
| ISC | 1 |
| Apache-2.0 OR BSD-2-Clause | 1 |
| BSD-2-Clause | 1 |
| Apache-2.0 AND CNRI-Python | 1 |
| MIT OR Apache-2.0 | 1 |
| MPL-2.0 AND MIT | 1 |
| multiple (Debian main) | 1 |
| LGPL-2.1-only | 1 |

Identifiers come from each package's own published metadata. Unambiguous
spelling variants normalise to SPDX ids; ambiguous ones are left exactly as
declared — `BSD License` does not say 2-clause or 3-clause, and docket does not
choose on the publisher's behalf.

### Copyleft, called out

**semgrep is LGPL-2.1-only** — the one component here under a copyleft licence.
A dependency scan of this repository would not surface it, because it is
installed into the sandbox container and not into `uv.lock`. docket invokes it
as a subprocess inside that container: not linked against, not modified, not
redistributed. That distinction governs the obligation, so it is stated here
rather than left for a reviewer to establish.

### 2 component(s) with no licence recorded

Left blank rather than guessed. Usually a platform-specific or optional
package that the lockfile resolves but that is not installed on the machine
generating this, so there was no local metadata to read.

- `colorama 0.4.6` (core)
- `pywin32 312` (core)

## Known vulnerabilities

**No known vulnerabilities** were reported against the Python and npm components as of 2026-09-21 by trivy.

A point-in-time statement about what had been published by that date. It is
not a claim that the software is free of defects, it does not stay true, and
it does not cover the sandbox tools above — those are container images and
are scanned separately.

## Independent cross-check

trivy, reading the same lockfiles independently, agreed on 82 packages.

It found nothing this generator missed.

## Declared dependencies

Everything else in the inventory is transitive or shipped in the container.

| Package | Version | Origin | Licence |
|---|---|---|---|
| `react` | 19.2.8 | console-bundle | MIT |
| `react-dom` | 19.2.8 | console-bundle | MIT |
| `openai-agents` | 0.19.4 | core | MIT |
| `pydantic` | 2.13.4 | core | MIT |
| `python-dotenv` | 1.2.2 | core | BSD-3-Clause |
| `textual` | 8.2.8 | core | MIT |
| `tokenizers` | 0.23.1 | core | Apache-2.0 |
| `uvicorn` | 0.52.1 | core | BSD-3-Clause |
| `fastapi` | 0.141.1 | extra:app | MIT |
| `pypdf` | 6.18.1 | extra:app | BSD-3-Clause |

## Full inventory

| Component | Version | Origin | Licence | Required by / role |
|---|---|---|---|---|
| `react` | 19.2.8 | console-bundle | MIT |  |
| `react-dom` | 19.2.8 | console-bundle | MIT |  |
| `scheduler` | 0.27.0 | console-bundle | MIT | react-dom -> scheduler |
| `aiohappyeyeballs` | 2.7.1 | core | PSF-2.0 | openai-agents[litellm] -> litellm -> aiohttp -> aiohappyeyeballs |
| `aiohttp` | 3.14.3 | core | Apache-2.0 AND MIT | openai-agents[litellm] -> litellm -> aiohttp |
| `aiosignal` | 1.4.0 | core | Apache-2.0 | openai-agents[litellm] -> litellm -> aiohttp -> aiosignal |
| `annotated-types` | 0.8.0 | core | MIT | pydantic -> annotated-types |
| `anyio` | 4.14.2 | core | MIT | openai-agents[litellm] -> mcp -> anyio |
| `attrs` | 26.1.0 | core | MIT | openai-agents[litellm] -> mcp -> jsonschema -> attrs |
| `certifi` | 2026.7.22 | core | MPL-2.0 | openai-agents[litellm] -> requests -> certifi |
| `cffi` | 2.1.1 | core | MIT-0 | openai-agents[litellm] -> mcp -> pyjwt[crypto] -> cryptography -> cffi |
| `charset-normalizer` | 3.4.9 | core | MIT | openai-agents[litellm] -> requests -> charset-normalizer |
| `click` | 8.4.2 | core | BSD-3-Clause | openai-agents[litellm] -> litellm -> click |
| `colorama` | 0.4.6 | core | — | openai-agents[litellm] -> openai -> tqdm -> colorama |
| `cryptography` | 50.0.0 | core | Apache-2.0 OR BSD-3-Clause | openai-agents[litellm] -> mcp -> pyjwt[crypto] -> cryptography |
| `distro` | 1.9.0 | core | Apache-2.0 | openai-agents[litellm] -> openai -> distro |
| `fastuuid` | 0.14.0 | core | BSD License | openai-agents[litellm] -> litellm -> fastuuid |
| `filelock` | 3.32.2 | core | MIT | openai-agents[litellm] -> litellm -> tokenizers -> huggingface-hub -> filelock |
| `frozenlist` | 1.8.0 | core | Apache-2.0 | openai-agents[litellm] -> litellm -> aiohttp -> frozenlist |
| `fsspec` | 2026.7.0 | core | BSD-3-Clause | openai-agents[litellm] -> litellm -> tokenizers -> huggingface-hub -> fsspec |
| `griffelib` | 2.1.0 | core | ISC | openai-agents[litellm] -> griffelib |
| `h11` | 0.16.0 | core | MIT | openai-agents[litellm] -> mcp -> uvicorn -> h11 |
| `hf-xet` | 1.6.0 | core | Apache-2.0 | openai-agents[litellm] -> litellm -> tokenizers -> huggingface-hub -> hf-xet |
| `httpcore` | 1.0.9 | core | BSD-3-Clause | openai-agents[litellm] -> mcp -> httpx -> httpcore |
| `httpx` | 0.28.1 | core | BSD-3-Clause | openai-agents[litellm] -> mcp -> httpx |
| `httpx-sse` | 0.4.3 | core | MIT | openai-agents[litellm] -> mcp -> httpx-sse |
| `huggingface-hub` | 1.27.0 | core | Apache-2.0 | openai-agents[litellm] -> litellm -> tokenizers -> huggingface-hub |
| `idna` | 3.18 | core | BSD-3-Clause | openai-agents[litellm] -> requests -> idna |
| `importlib-metadata` | 8.9.0 | core | Apache-2.0 | openai-agents[litellm] -> litellm -> importlib-metadata |
| `jinja2` | 3.1.6 | core | BSD License | openai-agents[litellm] -> litellm -> jinja2 |
| `jiter` | 0.16.0 | core | MIT | openai-agents[litellm] -> openai -> jiter |
| `jsonschema` | 4.26.0 | core | MIT | openai-agents[litellm] -> mcp -> jsonschema |
| `jsonschema-specifications` | 2025.9.1 | core | MIT | openai-agents[litellm] -> mcp -> jsonschema -> jsonschema-specifications |
| `linkify-it-py` | 2.1.0 | core | MIT | textual -> markdown-it-py[linkify] -> linkify-it-py |
| `litellm` | 1.96.0 | core | MIT | openai-agents[litellm] -> litellm |
| `markdown-it-py` | 4.2.0 | core | MIT | textual -> markdown-it-py[linkify] |
| `markupsafe` | 3.0.3 | core | BSD-3-Clause | openai-agents[litellm] -> litellm -> jinja2 -> markupsafe |
| `mcp` | 1.29.0 | core | MIT | openai-agents[litellm] -> mcp |
| `mdit-py-plugins` | 0.6.1 | core | MIT | textual -> mdit-py-plugins |
| `mdurl` | 0.1.2 | core | MIT | textual -> markdown-it-py[linkify] -> mdurl |
| `multidict` | 6.7.1 | core | Apache-2.0 | openai-agents[litellm] -> litellm -> aiohttp -> multidict |
| `openai` | 2.53.0 | core | Apache-2.0 | openai-agents[litellm] -> openai |
| `openai-agents` | 0.19.4 | core | MIT |  |
| `packaging` | 26.3 | core | Apache-2.0 OR BSD-2-Clause | openai-agents[litellm] -> litellm -> tokenizers -> huggingface-hub -> packaging |
| `platformdirs` | 4.11.2 | core | MIT | textual -> platformdirs |
| `propcache` | 0.5.2 | core | Apache-2.0 | openai-agents[litellm] -> litellm -> aiohttp -> propcache |
| `pycparser` | 3.0 | core | BSD-3-Clause | openai-agents[litellm] -> mcp -> pyjwt[crypto] -> cryptography -> cffi -> pycparser |
| `pydantic` | 2.13.4 | core | MIT |  |
| `pydantic-core` | 2.46.4 | core | MIT | pydantic -> pydantic-core |
| `pydantic-settings` | 2.15.0 | core | MIT | openai-agents[litellm] -> mcp -> pydantic-settings |
| `pygments` | 2.20.0 | core | BSD-2-Clause | textual -> pygments |
| `pyjwt` | 2.13.0 | core | MIT | openai-agents[litellm] -> mcp -> pyjwt[crypto] |
| `python-dotenv` | 1.2.2 | core | BSD-3-Clause |  |
| `python-multipart` | 0.0.32 | core | Apache-2.0 | openai-agents[litellm] -> mcp -> python-multipart |
| `pywin32` | 312 | core | — | openai-agents[litellm] -> mcp -> pywin32 |
| `pyyaml` | 6.0.3 | core | MIT | openai-agents[litellm] -> litellm -> tokenizers -> huggingface-hub -> pyyaml |
| `referencing` | 0.37.0 | core | MIT | openai-agents[litellm] -> mcp -> jsonschema -> referencing |
| `regex` | 2026.7.19 | core | Apache-2.0 AND CNRI-Python | openai-agents[litellm] -> litellm -> tiktoken -> regex |
| `requests` | 2.34.2 | core | Apache-2.0 | openai-agents[litellm] -> requests |
| `rich` | 15.0.0 | core | MIT | textual -> rich |
| `rpds-py` | 2026.6.3 | core | MIT | openai-agents[litellm] -> mcp -> jsonschema -> rpds-py |
| `sniffio` | 1.3.1 | core | MIT OR Apache-2.0 | openai-agents[litellm] -> openai -> sniffio |
| `sse-starlette` | 3.4.8 | core | BSD-3-Clause | openai-agents[litellm] -> mcp -> sse-starlette |
| `starlette` | 1.6.0 | core | BSD-3-Clause | openai-agents[litellm] -> mcp -> starlette |
| `textual` | 8.2.8 | core | MIT |  |
| `tiktoken` | 0.13.0 | core | MIT | openai-agents[litellm] -> litellm -> tiktoken |
| `tokenizers` | 0.23.1 | core | Apache-2.0 | openai-agents[litellm] -> litellm -> tokenizers |
| `tqdm` | 4.70.0 | core | MPL-2.0 AND MIT | openai-agents[litellm] -> openai -> tqdm |
| `typing-extensions` | 4.16.0 | core | PSF-2.0 | openai-agents[litellm] -> typing-extensions |
| `typing-inspection` | 0.4.3 | core | MIT | pydantic -> typing-inspection |
| `uc-micro-py` | 2.0.0 | core | MIT | textual -> markdown-it-py[linkify] -> linkify-it-py -> uc-micro-py |
| `urllib3` | 2.7.0 | core | MIT | openai-agents[litellm] -> requests -> urllib3 |
| `uvicorn` | 0.52.1 | core | BSD-3-Clause | openai-agents[litellm] -> mcp -> uvicorn |
| `websockets` | 16.1.1 | core | BSD-3-Clause | openai-agents[litellm] -> websockets |
| `yarl` | 1.24.5 | core | Apache-2.0 | openai-agents[litellm] -> litellm -> aiohttp -> yarl |
| `zipp` | 4.1.0 | core | MIT | openai-agents[litellm] -> litellm -> importlib-metadata -> zipp |
| `annotated-doc` | 0.0.5 | extra:app | MIT | fastapi -> annotated-doc |
| `fastapi` | 0.141.1 | extra:app | MIT |  |
| `httptools` | 0.8.0 | extra:app | MIT | uvicorn[standard] -> httptools |
| `pypdf` | 6.18.1 | extra:app | BSD-3-Clause |  |
| `uvloop` | 0.22.1 | extra:app | MIT | uvicorn[standard] -> uvloop |
| `watchfiles` | 1.2.0 | extra:app | MIT | uvicorn[standard] -> watchfiles |
| `mitmproxy` | 12.2.3 | sandbox-image | MIT | intercepting proxy for agent HTTP traffic |
| `nuclei` | 3.3.7 | sandbox-image | MIT | live-target vulnerability templates, when a target is given |
| `playwright` | 1.62.0 | sandbox-image | Apache-2.0 | browser automation; installs Chromium |
| `python:3.13-slim-bookworm` | debian-12-bookworm | sandbox-image | multiple (Debian main) | base image of containers/Dockerfile; every scanner runs in a container built from it |
| `semgrep` | 1.90.0 | sandbox-image | LGPL-2.1-only | static analysis over mounted source |
| `trivy` | 0.73.0 | sandbox-image | Apache-2.0 | dependency and CVE scanning; also the cross-check for this SBOM |
| `strix vulnerability playbooks (derived)` | derived | vendored-content | Apache-2.0 |  |

