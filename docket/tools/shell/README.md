# shell

Runs a command inside the sandbox container. Implementation in `tools.py` (stdlib only,
because it is imported by the in-container shim where no dependencies are installed).

**Never executes on the host.** With no sandbox present the tool refuses outright rather
than falling back — an LLM-authored shell command belongs in the container or nowhere.

Notable tools available inside: `sqlmap` at `/opt/sqlmap/sqlmap.py`, `mitmdump`, `curl`.
