# telemetry

**docket collects nothing and transmits nothing.**

Upstream Docket has `posthog.py` and `scarf.py` here (product analytics and download
tracking). Both are deliberately absent: this is an internal security tool, and a
pentesting agent phoning home about what you scanned is not a defensible default.

What remains is `logging.py` — local logging only, off by default, controlled by
`DOCKET_LOG_LEVEL`. The one other outbound-capable path in the codebase,
`interface/update_check.py`, is likewise disabled unless `DOCKET_UPDATE_URL` is set.
