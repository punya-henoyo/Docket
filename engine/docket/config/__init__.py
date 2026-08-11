"""Configuration package.

Intentionally does NOT re-export from `settings`: importing it here makes
`python -m docket.config.settings` double-import the module and emit a RuntimeWarning,
and every caller already imports `docket.config.settings` explicitly.
"""
