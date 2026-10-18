#!/usr/bin/env bash
# Bundle the Henoyo Visual Kit web components plus the Docket elements into one script.
# The kit sources under frontend/src are a pinned copy of henoyo-core's
# origin/integ/visual-kit-review (see PIN.md), kept at the same paths so a Docket element
# can be upstreamed by moving docket*.ts across. Output is committed: running the console
# needs no Node toolchain.
set -euo pipefail
cd "$(dirname "$0")"
WC=frontend/src/components/webcomponents
{
  for f in "$WC"/henoyo*.ts "$WC"/docket*.ts; do
    case "$f" in *docketKit.ts) continue;; esac
    echo "import './${f}';"
  done
  echo "import './globals.ts';"
} > entry.ts
ESB="${ESBUILD:-../frontend/node_modules/.bin/esbuild}"
[ -x "$ESB" ] || ESB="$(command -v esbuild || true)"
[ -x "$ESB" ] || ESB="npx --yes esbuild"
$ESB entry.ts --bundle --format=iife --minify --target=es2020 --legal-comments=none \
  --outfile=../frontend/public/assets/kit/henoyo-kit.js
ls -la ../frontend/public/assets/kit/henoyo-kit.js
