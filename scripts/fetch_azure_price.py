#!/usr/bin/env python3
"""Look up a model's real token prices in Azure's public retail catalogue.

    .venv/bin/python scripts/fetch_azure_price.py DeepSeek-V4-Pro eastus2 --write

Prints the input/output rates and, with --write, sets DOCKET_PRICE_INPUT_PER_1M and
DOCKET_PRICE_OUTPUT_PER_1M in .env so budgets stop being a silent no-op.

WHY THIS EXISTS
---------------
LiteLLM prices models it knows by name. It cannot price an Azure AI Foundry
DEPLOYMENT, because a deployment name is arbitrary text the operator chose — nothing
connects "DeepSeek-V4-Pro" on one resource to any published price. Unpriced means
docket reports $0.00 and DOCKET_MAX_COST_USD is never enforced, so max-steps is the
only ceiling. These are the real numbers, from Microsoft, keyed by region.

NOT called at scan time. A price lookup on a hot path would add a network round trip
per turn to compute a number that changes about never; run this when a deployment or
region changes and the value lives in .env.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

PRICES_API = "https://prices.azure.com/api/retail/prices"
ENV = Path(__file__).resolve().parents[1] / ".env"

# Azure meter names are abbreviated and positional: "<family> Inp DZ Tokens" is input,
# "Outp" output, and "Ch Inp" is CACHED input — a separate, far cheaper rate that only
# applies to prompt prefixes the provider already has. Matching on these substrings is
# what keeps the three apart; "Inp" alone would also match "Ch Inp".
_OUTPUT = re.compile(r"\bOutp\b", re.I)
_CACHED_INPUT = re.compile(r"\bCh\s+Inp\b", re.I)
_INPUT = re.compile(r"\bInp\b", re.I)


def fetch(model: str, region: str) -> dict[str, float]:
    """{"input", "output", "cached_input"} in USD per MILLION tokens."""
    query = urllib.parse.quote(f"contains(meterName, '{model}')")
    with urllib.request.urlopen(f"{PRICES_API}?$filter={query}", timeout=60) as response:
        items = json.loads(response.read()).get("Items", [])

    rates: dict[str, float] = {}
    for item in items:
        if item.get("armRegionName") != region:
            continue
        name, price = item.get("meterName", ""), item.get("retailPrice")
        if not price or "1K" not in (item.get("unitOfMeasure") or ""):
            continue
        per_million = price * 1000
        if _CACHED_INPUT.search(name):
            rates.setdefault("cached_input", per_million)
        elif _OUTPUT.search(name):
            rates.setdefault("output", per_million)
        elif _INPUT.search(name):
            rates.setdefault("input", per_million)
    return rates


def write_env(rates: dict[str, float]) -> None:
    lines = ENV.read_text().splitlines() if ENV.exists() else []
    for key, value in (("DOCKET_PRICE_INPUT_PER_1M", rates["input"]),
                       ("DOCKET_PRICE_OUTPUT_PER_1M", rates["output"])):
        for i, line in enumerate(lines):
            if line.lstrip("# ").startswith(f"{key}="):
                lines[i] = f"{key}={value}"
                break
        else:
            lines.append(f"{key}={value}")
    ENV.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("model", nargs="?", default="DeepSeek-V4-Pro",
                        help="substring of the Azure meter name (default: DeepSeek-V4-Pro)")
    parser.add_argument("region", nargs="?", default="eastus2",
                        help="armRegionName, e.g. eastus2 (default: eastus2)")
    parser.add_argument("--write", action="store_true", help="set the rates in .env")
    args = parser.parse_args()

    rates = fetch(args.model, args.region)
    if "input" not in rates or "output" not in rates:
        print(f"no input/output meters for {args.model!r} in {args.region!r}; "
              f"found {sorted(rates) or 'nothing'}", file=sys.stderr)
        return 1

    print(f"  model  : {args.model}   region: {args.region}")
    print(f"  input  : ${rates['input']:.4f} / 1M tokens")
    print(f"  output : ${rates['output']:.4f} / 1M tokens")
    if "cached_input" in rates:
        ratio = rates["input"] / rates["cached_input"]
        print(f"  cached : ${rates['cached_input']:.4f} / 1M tokens  "
              f"({ratio:.0f}x cheaper than uncached input)")
        print("           docket does not enable prompt caching for this provider, so the"
              " uncached rate is what you pay.")

    if args.write:
        write_env(rates)
        print(f"\n  wrote DOCKET_PRICE_INPUT_PER_1M / _OUTPUT_PER_1M -> {ENV}")
        print("  restart docket for it to take effect.")
    else:
        print("\n  re-run with --write to set these in .env")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
