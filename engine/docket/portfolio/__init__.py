"""The Code Security console's read model: applications, health, pipeline, policy.

Everything here is COMPUTED FROM DISK on each request (docket_runs/*/report.json,
events.jsonl, docket_portfolio.json, docket_policy.json). There is no database and no
cache that outlives a file's mtime, so the console and `docket view` can never disagree
about a run, and a value with no source on disk is null or absent, never a default
dressed up as a measurement. The wire contract is docs/ui/api-contract.md.

Nothing in this package runs a scan, calls a model or touches the network.
"""
