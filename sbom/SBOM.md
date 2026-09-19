# Docket — Software Bill of Materials

`sbom/docket.cdx.json` · CycloneDX 1.7 · 85 components

Regenerate with `make sbom`. Do not hand-edit: `make sbom-check` fails if the
committed file and a fresh generation disagree.

## What is counted

Everything that ships. Excluded, with reasons:

- `docket_runs/` — docket's own scan output, including patched copies of other
  repositories' source. Not part of this product.
- `.venv/` — a local install of the same packages already listed from the lockfile.
- npm **dev** dependencies (vite, typescript, @vitejs/plugin-react) — they build
  the console bundle and are not in it. Only react, react-dom and scheduler are
  delivered to a browser.

## Components by ecosystem

| Ecosystem | Count |
|---|---|
| `pkg:pypi` | 80 |
| `pkg:npm` | 3 |
| `other` | 2 |

## Licences

81 of 83 packages carry one. (2 further entries are the lockfiles trivy parsed, not packages: `app/frontend/package-lock.json`, `uv.lock`.)

| Licence | Count |
|---|---|
| MIT | 40 |
| Apache-2.0 | 14 |
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

### 2 package(s) with no licence recorded

Left blank rather than guessed. A guessed licence gets relied on; a gap gets
looked at. Resolve these by hand before shipping to anyone who audits them.

Usually because the package is platform-specific or optional, so the lockfile
resolves it but it is NOT installed on the machine that generated this SBOM
and there was no local metadata to read. Generating on the target platform,
or installing every extra first, fills most of them in.

- `colorama 0.4.6`
- `pywin32 312`

## Declared direct dependencies

From `pyproject.toml`. Everything else in the list above is transitive.

| Package | Constraint | Why |
|---|---|---|
| `openai-agents[litellm]` | `>=0.19,<0.20` | the agent runtime; litellm routes every model |
| `pydantic` | `>=2` | every model that crosses a trust boundary |
| `python-dotenv` | `>=1` | `.env` loading |
| `textual` | `>=8.2.8` | the `--tui` live view |
| `fastapi` (extra `app`) | `>=0.115` | the console API |
| `uvicorn[standard]` (extra `app`) | `>=0.32` | serves it |
| `pypdf` (extra `app`) | `>=5` | reading an uploaded compliance policy as PDF |
| `tokenizers` (extra `tokenizer`) | `>=0.20` | real token counting; a char fallback works without it |

Four runtime packages, three optional. `CONTRIBUTING.md`: every dependency earns
its place — `web_search` talks to five providers over plain `urllib` rather than
pulling in five SDKs.

## Tools invoked, not linked

These run as subprocesses inside the sandbox container and are not Python or npm
components of docket. They carry their own licences and are listed so an auditor
is not surprised by them.

| Tool | Role |
|---|---|
| `semgrep` | static analysis over mounted source |
| `trivy` | dependency and CVE scanning — and the generator of this SBOM |
| `nuclei` | live-target templates, when a target is given |
| `docker` | the sandbox itself |

