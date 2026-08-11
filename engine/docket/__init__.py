"""docket — autonomous pentesting agents that report only reproduced findings.

This module is deliberately near-empty except for one environment default that MUST be
set before litellm is imported anywhere. Keep it stdlib-only: the in-container shim
imports `docket.*`, and the sandbox image installs no project dependencies.
"""
from __future__ import annotations

import os

__version__ = "0.1.0"

# litellm fetches its model price map over the network at IMPORT time — an unconditional
# httpx GET to raw.githubusercontent.com from litellm/__init__.py. That happens before any
# docket code runs and regardless of provider, which flatly contradicts this project's
# "nothing leaves your machine" claim: a host that is neither the scan target nor the
# configured LLM provider learns that someone imported litellm, and when.
#
# Forcing the bundled local map removes the call. The cost is that a model released after
# the pinned litellm has no price entry, which surfaces honestly — core/hooks.py already
# detects an unpriced model and warns once rather than silently reporting $0.
#
# setdefault, not assignment: an operator who would rather have current prices than the
# offline guarantee can export LITELLM_LOCAL_MODEL_COST_MAP=false and get the old
# behaviour back.
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "true")
