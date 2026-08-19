# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A reusable **edge gateway**: Traefik v3 (TLS termination, routing, L7 flood control) in front of the OWASP ModSecurity CRS on nginx. Application-agnostic — apps live in their own compose files, join the external `webproxy` network, and opt in with `middlewares=waf@docker`. There is no application code here; it is entirely infrastructure config.

## Common commands

```bash
docker network create webproxy   # REQUIRED once before first run (external network)
cp .env.example .env             # review; CERT_RESOLVER must be empty for .localhost
make up                          # gateway only
make demo                        # gateway + whoami demo backend (compose profile)
make test                        # smoke tests: attacks blocked, real traffic allowed
make triggered                   # rank CRS rule IDs that are firing (start tuning here)
make reload                      # restart WAF after editing custom-rules.conf
make versions                    # pinned vs latest upstream
```

`make test` needs a routed backend — run `make demo` first, or point it at a real host: `./scripts/smoke-test.sh app.example.com`. Local testing resolves `*.localhost` to 127.0.0.1 automatically.

Compose/`.env` changes need `make restart` (recreate), not `docker compose restart`.

## Request flow — and the constraints it imposes

```
client → Traefik :443 → ratelimit → inflight → cors → modsecurity → securityHeaders → app [webproxy]
                                                           │ copy of request
                                                           ▼
                                                 modsecurity (CRS/nginx) → waf-dummy [internal]
```

The plugin sends a **copy** of each request to the WAF and reads back a status code; `>=400` blocks, otherwise Traefik forwards the original. Five consequences drive most of this config — check against them before changing anything:

- **`BACKEND` must be a dummy service.** The WAF proxies its copy to `BACKEND` to get a response. Pointing it at a real app executes every request **twice**. `waf-dummy` exists for this; the WAF is on `internal` only and cannot reach the app network.
- **Response-phase rules cannot work.** The real response never traverses ModSecurity, so phase 4 / `RESPONSE_BODY` rules and outbound anomaly scoring are inert. `MODSEC_RESP_BODY_ACCESS=Off` is deliberate.
- **The WAF never sees the real `Host`** — it is `modsecurity:8080`. Host-scoped rules must match `REQUEST_HEADERS:X-Forwarded-Host`. Safe only because Traefik overwrites client-supplied `X-Forwarded-*` and the WAF is off the shared network; keep both true.
- **WebSockets bypass the WAF** entirely.
- **`timeoutMillis` must scale with the body limit.** Plugin default is 2000 ms and it buffers the whole body in memory.

## Middleware chains — the public interface

Defined as Traefik `chain` middlewares on the traefik service's labels:

- `waf@docker` — default. `WAF_MAX_BODY_SIZE` (20 MB), `INFLIGHT_LIMIT` (50/IP).
- `waf-uploads@docker` — large-upload routes. `WAF_UPLOAD_MAX_BODY_SIZE` (300 MB), `UPLOAD_INFLIGHT_LIMIT` (4/IP).

Body limits are a **memory cost** — the plugin buffers bodies in RAM, so worst case is roughly `body limit × concurrency × client IPs`. That is why the default is low and large uploads get a separate route.

A more specific router (e.g. `Host(...) && PathPrefix('/upload')`) **must set an explicit high `priority`**. Traefik's default priority is rule length, so the broader `Host()` router otherwise wins and the specific route never matches.

## Editing WAF rules

`modsec/custom-rules.conf` is the only mounted rules file, at `/etc/modsecurity.d/owasp-crs/plugins/custom-after.conf` — the CRS "after" hook, **not** under `rules/`. Load-bearing: `ctl:ruleRemoveById` resolves at parse time, and files under `rules/` with a numeric prefix are globbed *before* CRS, so exclusions written there fail silently.

- Custom detection uses IDs 1200–1299; exclusions/tuning 5000–5999. CRS owns 900000+.
- **All rules are active** (1200–1240: exposed files, PHP/Laravel, WordPress, Node/JS, Java/.NET). Nothing is commented out for a server operator to enable — the repo is the only place this file is edited. Do not reintroduce opt-in blocks.
- One gateway fronts several stacks at once, so every rule must be safe against **all** of them. Target attacker-only paths, not whole directories: `/vendor/*.php` not `/vendor/`, `/storage/*.log` not `/storage/` (Laravel's `storage:link` serves real uploads there), `/.next/` not `/_next/`. Add both a blocked case and an allowed-lookalike case to `scripts/smoke-test.sh` for any new rule.
- To tune: `make triggered` for the rule ID, then a scoped `ctl:ruleRemoveById` / `ctl:ruleRemoveTargetById` keyed on `X-Forwarded-Host`.
- Never `ctl:ruleEngine=Off` — kills protection *and* logging. `DetectionOnly` is the escape hatch.
- Default paranoia is 2; PL3 rejects newlines in input (920272) and tends to get switched off wholesale.

## Behind a CDN (Cloudflare)

Three changes that are only correct together — see README "Behind Cloudflare".

- `forwardedHeaders.trustedIPs` on both entryPoints, literal in `traefik.yaml`
  (no env expansion; no YAML anchor either — Traefik rejects unknown top-level
  keys). `TRUSTED_PROXY_IPS` in `.env` feeds the same list to
  `ipStrategy.excludedIPs` on `ratelimit`/`inflight`. Both empty by default.
- **`excludedIPs`, never `depth=1`.** One gateway fronts both proxied and
  directly-resolving hostnames; `excludedIPs` is correct for both, `depth` reads
  an attacker-supplied header on the direct ones.
- **Trusting the CDN breaks the `X-Forwarded-Host` guarantee** the WAF
  exclusions rest on, because a client-supplied value now survives. Every router
  must stamp its own literal via an `xfh-` middleware placed before `waf@docker`.
  A literal cannot cover two names, so **a multi-hostname service needs one
  router per hostname** sharing one service, with an explicit `.service=`.
- `scripts/update-cf-ips.sh` rewrites both `traefik.yaml` blocks and prints the
  `.env` line; `--check` for CI. Static config needs `make restart`.

## Migrating off certbot

`HOST_CERT_STORE` mounts a host `/etc/letsencrypt` read-only at
`/letsencrypt-host`; serve those certs from `traefik/dynamic/` with no
`certresolver` on the routers, so the cutover involves no ACME and rollback is
instant. Mount the whole tree — `live/` symlinks into `archive/`. Switch to
`certresolver=letsencrypt` and disable the host's certbot timer as a separate,
later step; a live `--nginx` authenticator will fight Traefik for port 80.

**Handing renewals back to ACME: file certs suppress ACME.** Setting
`certresolver=letsencrypt` on every router is **not enough**. Traefik skips ACME
for any domain already covered by a certificate in its store, so while a
`tls.certificates` entry covers the host, `acme.json` stays **empty** — no error,
no warning. It looks correct until the borrowed certs expire, then every host
fails at once.

Retiring the file certs is what triggers issuance. Order matters:

1. Set `certresolver` on **every** router first — a router without one has no
   certificate at all once the file certs go, and serves Traefik's self-signed
   cert (a `526` behind Cloudflare).
2. Confirm via `/api/http/routers` that every router reports `certResolver`.
3. Only then remove `traefik/dynamic/certs.yaml` (the live copy, made from
   `certs.yaml.example` and gitignored). Issuance is quick — 14 hosts
   took under 25 seconds — but there is a brief window where uncovered hosts
   serve the self-signed cert, so do it at a low-traffic time.
4. Verify the **served** certificate changed (`openssl s_client` → `notBefore`
   should be today), not just that `acme.json` has entries.

Do not keep the retired file around where it can be dropped back in: restoring
it silently re-suppresses renewals.

## CRS 931130 can never be satisfied here

`931130` ("RFI: Off-Domain Reference/Link") is chained on:

```
SecRule TX:/rfi_parameter_.*/ "!@endsWith .%{request_headers.host}"
```

The plugin opens its **own** connection to the WAF, so `request_headers.host` is
always `modsecurity:8080`. No real URL ends with that, so the negated match is
always true: **every url-bearing parameter scores CRITICAL**, including an
application's own links.

One URL scores 5 against a threshold of 10, so ordinary pages look fine — which
is what makes this hard to spot. It surfaces on requests carrying *several*
URLs. Observed live: payment webhooks whose JSON bodies held 6–10 URL fields
scored 40–50 and were 403'd, so payment confirmations failed intermittently.

Scope the rule off the affected routes rather than removing it globally — it
still does real work through the other RFI rules' scoring. Verified: dropping it
everywhere takes `?f=php://input` from 403 to 200.

```
SecRule REQUEST_HEADERS:X-Forwarded-Host "@rx (?i)^api\.example\.com$" \
    "id:5120,phase:1,pass,nolog,ctl:ruleRemoveById=931130,chain"
    SecRule REQUEST_URI "@rx (?i)^/api/v[0-9]+/webhooks?/"
```

## `DetectionOnly` does not cover the phase-1 custom rules

`ctl:ruleEngine=DetectionOnly` in `site-rules.conf` is a **phase 1** rule, and
`site-after.conf` loads **after** `custom-after.conf`. Within a phase, rules run
in load order — so the phase-1 rules in `custom-rules.conf` (1200 dotfiles, 1201
manifests, 1202 backups, 1203 status pages, 1211, 1212, 1220, 1231, 1240) have
already run `deny` before the `ctl` takes effect, and **still block**. Only
phase-2 rules — the CRS 942xxx SQLi family, 941 XSS, the `ARGS`-based custom
rules 1210/1230 — actually observe it.

Verified on a live deployment: a `DetectionOnly` host returned 200 for an SQLi
probe (logged, not blocked) while still returning 403 for `/.env`,
`/.git/config` and `/composer.json`.

Usually this is what you want — an exempted admin tool has no business serving
`/.env` either. But do not describe such a host as "WAF off": it is exempt from
the phase-2 rules only. To exempt a phase-1 custom rule for one host, use a
scoped `ctl:ruleRemoveById=1200` **in `custom-rules.conf` itself**, where it can
run before the rule it targets.

## Reading WAF decisions in a script

Two traps when asserting on `docker logs modsecurity`:

- ModSecurity's rule messages go to the container's **stderr** (nginx
  `error_log`). `2>/dev/null` silently discards exactly the lines you want.
- Piping into `grep -q` under `set -o pipefail` reports failure even on a match:
  `grep -q` exits at the first hit, `docker logs` takes SIGPIPE, and the
  pipeline's status becomes 141. Capture into a variable first, then match.

## CORS

A WAF 403 carries no `Access-Control-Allow-Origin`, so browsers report it as a CORS error and hide the real cause — the most common misdiagnosis in this stack. Three mechanisms: `cors` runs before the WAF and Traefik answers preflight without forwarding it; `CORS_HEADER_403_*` puts CORS headers on WAF blocks (the plugin copies them through); `ALLOWED_METHODS` includes PUT/PATCH/DELETE, which CRS 911100 rejects by default (`GET HEAD POST OPTIONS`).

## Scope

Handles request-side OWASP Top 10 (CRS), L7 floods (`ratelimit`), slowloris (`inflight`), and body-based memory exhaustion. Does **not** handle volumetric L3/L4 DDoS — that needs upstream scrubbing. Don't claim otherwise in docs.

## Environment notes

- `CERT_RESOLVER` must be empty for `.localhost`/`.test`/internal names; Let's Encrypt rejects non-public TLDs and Traefik retries against the rate limit. This is what the old empty `tls.certresolver=` labels were working around.
- ACME email in `traefik/traefik.yaml` must be a literal — Traefik does not expand env vars in static config.
- Dashboard has no auth (`api.insecure: true`), published to `127.0.0.1:8085` only. Keep it off `0.0.0.0`.
- Traefik and the WAF log to **stdout**, rotated by Docker's json-file driver. Traefik does not rotate its own log files, so don't reintroduce a file bind mount.
- On SELinux hosts (developed on Fedora), bind mounts need `:z`, which is set. The docker socket is intentionally not relabelled, so Traefik cannot read it under enforcing SELinux without `security_opt: [label=disable]` or a socket proxy.
