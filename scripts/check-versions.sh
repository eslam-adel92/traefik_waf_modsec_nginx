#!/usr/bin/env bash
# Compare pinned versions against the latest upstream releases.
# Renovate does this automatically on GitHub; this is the manual equivalent.
set -uo pipefail
cd "$(dirname "$0")/.."

gh_latest() { curl -s --max-time 15 "https://api.github.com/repos/$1/releases/latest" \
  | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p'; }

row() { printf '  %-34s %-28s %s\n' "$1" "$2" "$3"; }

printf '  %-34s %-28s %s\n' "COMPONENT" "PINNED" "LATEST"
printf '  %-34s %-28s %s\n' "---------" "------" "------"

pinned_traefik=$(grep -oE 'image: traefik:v[0-9.]+' docker-compose.yaml | head -1 | cut -d: -f3)
row "traefik" "$pinned_traefik" "$(gh_latest traefik/traefik)"

pinned_whoami=$(grep -oE 'image: traefik/whoami:v[0-9.]+' docker-compose.yaml | head -1 | cut -d: -f3)
row "traefik/whoami" "$pinned_whoami" "$(gh_latest traefik/whoami)"

pinned_plugin=$(grep -A1 'traefik-modsecurity-plugin' traefik/traefik.yaml | grep -oE 'v[0-9.]+' | head -1)
row "modsecurity plugin" "$pinned_plugin" "$(gh_latest acouvreur/traefik-modsecurity-plugin)"

pinned_crs=$(grep -oE 'owasp/modsecurity-crs:[^ ]+' docker-compose.yaml | head -1 | cut -d: -f2)
row "owasp/modsecurity-crs" "$pinned_crs" "$(gh_latest coreruleset/coreruleset) (rule set)"

pinned_nginx=$(grep -oE 'image: nginx:[^ ]+' docker-compose.yaml | head -1 | cut -d: -f3-)
row "nginx (ip-blocker)" "$pinned_nginx" "see hub.docker.com/_/nginx"

echo
echo "  Update:  edit the tag, then \`make update\` and \`make test\`."
echo "  Majors:  read the upstream changelog first - Traefik majors change config."
