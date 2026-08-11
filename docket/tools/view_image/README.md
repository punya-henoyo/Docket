# view_image

Backed by the SDK's native image-input support rather than a custom tool, which is why
this directory is README-only.

The `browser` tool writes screenshots to `<run>/artifacts/screenshots/` and returns a
run-relative path; this is how a vision-capable model reads one back. Screenshots are
never base64-inlined into a tool result, which would blow the context window.
