# apply_patch

Backed by the SDK's native `ApplyPatchTool` (see `docket/agents/factory.py`), not a
custom implementation — same as upstream, where this directory is README-only.

Scoped to the sandbox filesystem. docket pentests rather than remediates, so this is for
an agent that needs to write a helper script or an exploit file mid-investigation, not
for editing the target's source.
