# Traefik + ModSecurity WAF Gateway

A reusable edge gateway: **Traefik v3** terminating TLS, with the **OWASP
ModSecurity Core Rule Set** inspecting every request, plus L7 rate limiting and
concurrency control. Application-agnostic — put any HTTP service behind it.

This repository is infrastructure config only; there is no application code.

## Quick start

```bash
docker network create webproxy      # once, before the first run
cp .env.example .env                # review it; leave CERT_RESOLVER empty for local
make up                             # or: docker compose up -d
```

Smoke-test the gateway with the bundled demo backend:

```bash
make demo                           # starts whoami behind the WAF
make test                           # 23 checks: attacks blocked, real traffic allowed
```

`make help` lists everything. The demo backend sits behind a compose profile,
so `make up` alone runs the gateway only.

## Putting an application behind the WAF

Your app lives in its own compose file. Join the `webproxy` network and opt in
with **one middleware label**:

```yaml
networks:
  webproxy:
    external: true

services:
  myapp:
    image: myorg/myapp:1.2.3
    networks: [webproxy]
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.myapp.rule=Host(`app.example.com`)"
      - "traefik.http.routers.myapp.entrypoints=websecure"
      - "traefik.http.routers.myapp.middlewares=waf@docker"      # <- the WAF
      - "traefik.http.routers.myapp.tls.certresolver=letsencrypt"
      - "traefik.http.services.myapp.loadbalancer.server.port=8080"
```

Two chains are published by the gateway:

| Chain | Body limit | Concurrency/IP | Use for |
|---|---|---|---|
| `waf@docker` | `WAF_MAX_BODY_SIZE` (20 MB) | `INFLIGHT_LIMIT` (50) | everything |
| `waf-uploads@docker` | `WAF_UPLOAD_MAX_BODY_SIZE` (300 MB) | `UPLOAD_INFLIGHT_LIMIT` (4) | large-upload routes only |

Each chain is `ratelimit → inflight → cors → modsecurity → securityHeaders`.
Rate limiting runs first so floods are dropped before paying for the WAF hop.

### Large uploads

The plugin buffers each request body **in memory** before forwarding it to the
WAF, so the body limit is a memory cost — roughly
`body limit × concurrency × client IPs`. That is why the default is 20 MB and
big uploads get their own route:

```yaml
      - "traefik.http.routers.myapp-uploads.rule=Host(`app.example.com`) && PathPrefix(`/upload`)"
      - "traefik.http.routers.myapp-uploads.entrypoints=websecure"
      - "traefik.http.routers.myapp-uploads.priority=1000"
      - "traefik.http.routers.myapp-uploads.middlewares=waf-uploads@docker"
      - "traefik.http.routers.myapp-uploads.service=myapp"
```

**`priority` must be set and high.** Traefik's default priority is the rule's
length, so without it the broader `Host()` router outranks the more specific
one and your upload route never matches.

## Architecture

```
                        ┌───────────────────────────────────────────────┐
client ──TLS──> Traefik │ ratelimit → inflight → cors → WAF → headers   │ ──> your app
                :443    └────────────────────────┬──────────────────────┘     [webproxy]
                                                 │ copy of the request
                                                 ▼
                                        modsecurity (CRS/nginx) ──> waf-dummy
                                              [internal]              [internal]
```

The plugin (`acouvreur/traefik-modsecurity-plugin`) sends a **copy** of each
request to the WAF and reads back a status code. `>= 400` blocks; otherwise
Traefik forwards the original request onward. Five consequences shape this
config:

- **The WAF's `BACKEND` must be a dummy.** The WAF proxies its copy somewhere to
  produce a response. Pointing it at a real app runs every request **twice**.
  `waf-dummy` exists for this, and the WAF cannot reach the app network at all.
- **Response inspection is impossible.** The real response never passes through
  ModSecurity, so phase-4 / `RESPONSE_BODY` rules and outbound anomaly scoring
  do nothing. `MODSEC_RESP_BODY_ACCESS` is off deliberately.
- **The WAF does not see the real `Host`** — it is `modsecurity:8080`. The
  client hostname arrives only in `X-Forwarded-Host`; host-scoped rules must
  match on that.
- **WebSockets bypass the WAF** entirely.
- **`timeoutMillis` must track the body limit.** The plugin's default is 2000 ms,
  so any sizeable upload fails with `502` unless it is raised.

## CORS and the WAF

**A WAF block looks exactly like a CORS error in the browser.** A 403 from
ModSecurity carries no `Access-Control-Allow-Origin`, so the browser reports
"blocked by CORS policy" and hides the real 403. Disabling the WAF makes the
message disappear — which is why this gets misdiagnosed as a CORS problem.

Three mechanisms handle it:

1. **Traefik answers preflight itself.** `cors` runs before the WAF and Traefik
   does not forward preflight requests, so an `OPTIONS` preflight cannot be
   blocked.
2. **Blocks carry CORS headers.** `CORS_HEADER_403_*` attaches
   `Access-Control-Allow-Origin` to WAF 403s and the plugin copies them
   through, so the browser shows the real 403.
3. **`ALLOWED_METHODS` includes the REST verbs.** CRS rule 911100 rejects
   anything outside `tx.allowed_methods`, and the upstream default is
   `GET HEAD POST OPTIONS` — so **`PUT`, `PATCH` and `DELETE` are blocked out of
   the box**, a very common cause of "CORS errors" on REST APIs.

Set `CORS_ALLOW_ORIGIN` to explicit origins in production; `*` cannot be
combined with credentialed requests.

## What this does and does not stop

Handled here:

- **OWASP Top 10 request-side attacks** — SQLi, XSS, RCE, traversal, SSRF,
  log4shell/JNDI, scanner and bad-bot traffic, protocol abuse (CRS).
- **L7 floods and brute force** — `ratelimit` per IP.
- **Slowloris / connection exhaustion** — `inflight` caps concurrent requests
  per IP, which is what bounds the long read timeout uploads require.
- **Memory-exhaustion via large bodies** — body caps, tight upload concurrency.

**Not handled here, by design:** volumetric L3/L4 DDoS — SYN floods, UDP
amplification, anything that saturates your uplink. That traffic never reaches
Traefik's logic; it saturates the host first. Terminating it needs capacity
upstream of this box: Cloudflare, your cloud provider's scrubbing, or an ISP
filter. This gateway is the application-layer half of the answer, not the whole
one. If you front it with such a service, uncomment the `ipstrategy.depth`
line in `docker-compose.yaml` so rate limits count the real client IP rather
than the proxy's.

## Tuning false positives

Default paranoia is **2**. PL3 catches more but rejects things like newlines in
input (rule 920272), and a PL3 gateway that gets switched off protects less
than a PL2 one left on. Raise it once you are tuning regularly.

Find what actually fired:

```bash
make triggered      # ranks the CRS rule IDs that blocked traffic
```

Then add a **scoped exclusion** in `modsec/custom-rules.conf` — remove the
specific rule for the specific host or parameter, keyed on `X-Forwarded-Host`.
Worked examples are in that file. Never use `ctl:ruleEngine=Off`: it disables
protection *and* logging. `ctl:ruleEngine=DetectionOnly` is the correct escape
hatch.

Exclusions work only because the file is mounted on the CRS `*-after.conf`
hook. `ctl:ruleRemoveById` is resolved at parse time, so a rules file loaded
*before* CRS cannot exclude a CRS rule — it fails silently.

```bash
make reload         # after editing rules
```

`modsec/custom-rules.conf` also ships commented, opt-in profiles for PHP/Laravel,
WordPress, Node and Java/Spring. Nothing app-specific is enabled by default.

## Keeping it current

```bash
make versions       # pinned vs latest upstream
make update         # pull + recreate
make test           # verify nothing regressed
```

All images are pinned. `renovate.json` automates the bumps on GitHub: minor and
patch updates are grouped, majors need explicit approval (Traefik majors change
config), and the CRS image is checked monthly since its tags carry build dates.
The Traefik plugin version in `traefik/traefik.yaml` is tracked too.

## Deployment notes

- **`CERT_RESOLVER`** must be empty for `.localhost` / `.test` / internal names.
  Let's Encrypt rejects names without a valid public TLD and Traefik retries
  noisily against your rate limit. Set it to `letsencrypt` for real domains.
- **Change the ACME email** in `traefik/traefik.yaml`. Traefik does *not* expand
  environment variables in its static config, so it must be a literal.
- **The dashboard has no authentication** (`api.insecure: true`), published to
  `127.0.0.1:8085` only. Reach it over an SSH tunnel; never bind `0.0.0.0`.
- **Never set `forwardedHeaders.insecure: true`** or add untrusted
  `trustedIPs`. Traefik overwriting client-supplied `X-Forwarded-*` is what
  makes host-scoped WAF exclusions safe.
- **Logs go to stdout** and are rotated by Docker's json-file driver. Traefik
  does not rotate its own log files, so writing them to a bind mount grows
  without bound.
- **SELinux hosts (Fedora/RHEL):** bind mounts carry `:z`. The docker socket is
  deliberately not relabelled. If Traefik logs `Failed to retrieve information
  of the docker client`, run it with `security_opt: [label=disable]` or put a
  docker-socket-proxy in front.
- **Latency:** every request costs an extra HTTP round-trip to the WAF. If you
  serve many static assets through this gateway, consider a separate router for
  them that skips the `modsecurity` middleware.
