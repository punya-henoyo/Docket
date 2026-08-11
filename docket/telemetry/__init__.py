"""Telemetry package. See README.md — docket collects and transmits nothing.

Intentionally does NOT re-export from `logging`: importing it here makes
`python -m docket.telemetry.logging` double-import and warn, and callers import
`docket.telemetry.logging` explicitly anyway.
"""
