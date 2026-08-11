#!/usr/bin/env bash
# Refresh the Cloudflare IP ranges this gateway trusts.
#
# They live in TWO places that must agree:
#   1. traefik/traefik.yaml - entryPoints.*.forwardedHeaders.trustedIPs, twice
#      (once per entryPoint). Literal, because Traefik does not expand env vars
#      in static config, and a YAML anchor is not an option either: Traefik
#      rejects unknown top-level keys with "field not found".
#   2. .env - TRUSTED_PROXY_IPS, consumed by the ratelimit/inflight labels.
#
# This script rewrites (1) in place and prints (2) for you to paste. Diff before
# committing; a bad list here either breaks rate limiting or, worse, trusts
# someone you do not sit behind.
#
#   ./scripts/update-cf-ips.sh            # rewrite traefik.yaml, print .env line
#   ./scripts/update-cf-ips.sh --check    # exit 1 if stale, change nothing (CI)
#
# Traefik must be restarted, not reloaded, for static config to take effect:
#   make restart
set -euo pipefail

cd "$(dirname "$0")/.."
YAML=traefik/traefik.yaml
CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

# Cloudflare serves these without a trailing newline, so read them as fields
# rather than lines - `wc -l` undercounts by one and a while-read loop drops
# the last range entirely.
fetch() {
  curl -fsS --max-time 20 "https://www.cloudflare.com/ips-$1" | tr -s '[:space:]' '\n' | sed '/^$/d'
}

echo "Fetching Cloudflare ranges..." >&2
RANGES="$(fetch v4)"$'\n'"$(fetch v6)"

# Sanity gate: a truncated or hijacked response must not silently narrow the
# trusted set to something wrong. Cloudflare has published ~22 ranges for years.
COUNT=$(printf '%s\n' "$RANGES" | wc -l | tr -d ' ')
if (( COUNT < 15 )); then
  echo "Refusing to continue: got only $COUNT ranges, expected ~22." >&2
  echo "Check https://www.cloudflare.com/ips-v4 by hand before rerunning." >&2
  exit 3
fi

printf '%s\n' "$RANGES" | while read -r r; do
  [[ "$r" =~ ^[0-9a-fA-F:.]+/[0-9]+$ ]] || { echo "Not a CIDR: '$r'" >&2; exit 4; }
done

YAML_BLOCK="$(printf '%s\n' "$RANGES" | sed 's/^/        - "/; s/$/"/')"
ENV_LINE="TRUSTED_PROXY_IPS=$(printf '%s\n' "$RANGES" | paste -sd, -)"

if (( CHECK )); then
  if grep -qF "$(printf '%s\n' "$RANGES" | head -1 | sed 's/^/        - "/; s/$/"/')" "$YAML" \
     && [[ "$(grep -c '^        - "' "$YAML")" == "$((COUNT * 2))" ]]; then
    echo "up to date ($COUNT ranges)"; exit 0
  fi
  echo "STALE: $YAML does not match the published list ($COUNT ranges)" >&2; exit 1
fi

# Replace every trustedIPs list: from the line after `trustedIPs:` up to the
# last `        - "..."` entry that follows it.
#
# The block is passed through the environment, NOT interpolated into the Python
# source: it ends in a double quote, which would collide with the heredoc's own
# quoting and produce an unterminated string literal.
YAML_BLOCK="$YAML_BLOCK" python3 - "$YAML" <<'PY'
import os, re, sys
path = sys.argv[1]
block = os.environ["YAML_BLOCK"]
src = open(path).read()
new, n = re.subn(
    r'(^[ \t]*trustedIPs:\n)(?:^[ \t]+- "[^"]+"\n)+',
    lambda m: m.group(1) + block + "\n",
    src, flags=re.M)
if n == 0:
    sys.exit("No trustedIPs block found in " + path)
open(path, "w").write(new)
print(f"Rewrote {n} trustedIPs block(s) in {path}", file=sys.stderr)
PY

sed -i -E "s|^# Cloudflare, fetched .*|# Cloudflare, fetched $(date +%Y-%m-%d).|" "$YAML"

echo >&2
echo "Now put this in .env (and restart, not reload):" >&2
echo "$ENV_LINE"
