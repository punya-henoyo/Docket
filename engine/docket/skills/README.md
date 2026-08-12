# Skills

Markdown playbooks agents load on demand via the `load_skill` tool.

Adding one is dropping a `.md` file into a category directory — no code change. The
skill name is `<category>/<filename-without-extension>`, e.g. `custom/blind_injection`.

Loading on demand rather than baking everything into the system prompt is deliberate:
an agent working blind command injection wants that playbook, and paying for every
other playbook on every turn is wasted context.

## Categories

| Directory | Loaded by | Contains |
|---|---|---|
| `recon/` | the recon agent | where a bug class lives and what it looks like in source |
| `triage/` | the triage agent | what makes a finding of that class NOT a bug |
| `coordination/` | root | how to run a multi-agent scan |
| `custom/` | specialists | technique playbooks |

`recon/` and `triage/` are generated from strix (Apache-2.0) by
`scripts/build_skills.py` — do not hand-edit them, the next run overwrites it.
Verify with `python scripts/build_skills.py --check`. Attribution is in NOTICE.

Always load these with their prefix (`recon/idor`, not `idor`): the same class name
now exists in both directories, so a bare name is ambiguous and the loader will
refuse it rather than guess which one you meant.
