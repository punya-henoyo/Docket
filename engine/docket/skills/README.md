# Skills

Markdown playbooks agents load on demand via the `load_skill` tool.

Adding one is dropping a `.md` file into a category directory — no code change. The
skill name is `<category>/<filename-without-extension>`, e.g. `custom/blind_injection`.

Loading on demand rather than baking everything into the system prompt is deliberate:
an agent working blind command injection wants that playbook, and paying for every
other playbook on every turn is wasted context.
