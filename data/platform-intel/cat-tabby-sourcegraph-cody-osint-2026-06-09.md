# Cat-Tabby: Sourcegraph (self-hosted) + Cody backend — Stage -1 OSINT brief

- Researcher:  squad 3 of 4
- Date: 2026-06-09
- Status: CANDIDATE (no operator probing performed)
- Tier hypothesis: **Tier-C (auth-on-default)**, with one explicit research-gap toggle (`auth.public: true`) and a thin unauth introspection surface on `/.api/graphql`.

## Lane 1 — Auth modes & deploy config

Sourcegraph self-hosted ships **no default auth provider**. Site config requires explicit `auth.providers[]`. Supported: builtin password, GitHub OAuth, GitLab OAuth, Bitbucket Cloud/Server OAuth, Gerrit (Beta), SAML, OIDC (Google Workspace / Okta / Auth0 / Azure AD), HTTP auth proxy (oauth2_proxy header).

The fresh-install flow is **first-admin-wins**: the docker quickstart docs say "navigate to port 7080, create the admin account, then you'll be guided through setup." There is a small window after `docker run` and before admin creation where the install is unauthenticated — a race condition with finite human-attention cost (one of the recurring  attack-surface classes: install-state-races).

**Public toggle (research-gap-grade):** `auth.public` (default `false`). Setting to `true` allows anonymous users to access and use the instance without signing in. This is the canonical anonymous-mode switch.

Cody itself authenticates with Sourcegraph access tokens. The Cody Gateway in self-hosted mode auto-uses the license-key-derived token; admins are explicitly told **not** to set an access token manually.

Access modes per docs: site-admin / authenticated user / unauthenticated. `authz.enforceForSiteAdmins` toggle exists — when off, admins bypass per-repo perms (lateral-movement primitive once admin is held).

Docs: `sourcegraph.com/docs/admin/auth`, `/docs/admin/config/site_config` (auth.public), `/docs/admin/deploy/docker-single-container` (removed in 7.0.0).

## Lane 2 — Shodan fingerprint & population

Default external ports: **7080** (single-container, legacy ≤6.x), **80/443** (Caddy front in docker-compose / Helm), **3080** historical web port. Port 3370 is bound to 127.0.0.1 by the documented quickstart — *not* a host-exposed port unless rebound.

Primary tells:
- HTML title `Sourcegraph` and the SPA shell `<div id="root"></div>` with Sourcegraph webpack bundle paths.
- Response header `X-Trace` (Jaeger trace ID, always set on GraphQL responses).
- Response header `X-Trace-Url` when `X-Sourcegraph-Should-Trace: true` request header is sent.
- GraphQL surface at `/.api/graphql`.
- Sign-in route `/sign-in`, admin route `/site-admin`.
- Caddy as front proxy → `Server: Caddy` header on compose installs.

Best Shodan dorks (ranked low → high FP risk):

| Tier | Dork | Rationale |
|---|---|---|
| basic | `http.title:"Sourcegraph"` | high recall, some FP on docs mirrors |
| strict | `http.html:"/.api/graphql" http.title:"Sourcegraph"` | path + title both required |
| version | `http.html:"productVersion"` `http.html:"/.assets/scripts/"` | webpack bundle path is install-pinned |
| header | `http.headers.x-trace:` | Jaeger trace header rarely set by anything else |

aimap: **no existing fingerprint** in `~/aimap/fingerprints/` (Stage 0d gap — scaffold needed). nuclei-templates: no Sourcegraph template in projectdiscovery/nuclei-templates (verified via GitHub code search 2026-06-09 → 0 results). Both are tooling debt to write before Cat-Tabby active.

## Lane 3 — API surface & data exposure

GraphQL `/.api/graphql` is the primary surface. Authentication is via access token (`Authorization: token <sgp_...>`) or OAuth.

Unauth GraphQL behavior (from docs + the public sourcegraph.com instance, which historically had `auth.public: true`):
- `site.productVersion` — typically returns even when most resolvers reject (version fingerprint primitive).
- `currentUser` — returns `null` for unauth.
- Schema **introspection** is enabled by default (debug API, "no backwards-compat guarantee" per docs). This is itself the assessment surface: the resolver list, argument shapes, and admin-only field names leak the deployment surface area without exercising any resolver.
- `repositories(first: 5)`, `users`, `search` — gated when `auth.public` is false; **fully readable** when `auth.public: true`.

Cody-specific endpoints (do-not-call class):
- `/.api/completions/stream` — LLM completion stream (token-billing impact if abused).
- `/.api/cody/context` — context-fetch for code-aware completions.
- `/.api/sg/embeddings` — embedding generation; pulls indexed repo chunks if hit unauthed on a misconfig.
- `/.api/llm/v1/chat/completions` — OpenAI-compat shim (Sourcegraph 6.x+).
- `/.api/registry/extensions` — extension registry.

**Do-NOT-call list (LLM-cost / state-mutating / hard-to-defend):**
1. `/.api/completions/stream` (POST) — bills LLM tokens.
2. `/.api/cody/context` (POST) — bills + can pull private repo snippets.
3. `/.api/sg/embeddings` (POST) — embedding generation cost.
4. `/.api/llm/v1/chat/completions` (POST).
5. Any GraphQL mutation (`mutation { ... }`).
6. `/.api/repos/{}/git/upload-pack` and `/.api/repos/{}/git/receive-pack` (git proto).
7. `/.api/src-cli-version` is **GET-safe** but still log it.

Severity classes once unauth is observed:
- `site.productVersion` unauth → low (CVE scoping).
- Schema introspection unauth → low-medium (surface-area leak).
- `repositories` list unauth → medium-high (private code names = IP).
- `users` list unauth → high (PII + lateral-target list).
- Any Cody endpoint unauth → critical (LLM-cost theft + indexed-content disclosure).

## Lane 4 — CVEs & prior research

| CVE | Year | Severity | Note |
|---|---|---|---|
| CVE-2022-23642 | 2022 | High | gitserver RCE via `core.sshCommand` git-config injection; pre-3.37; **public PoC + ExploitDB 50964**. |
| pre-3.38 gitserver RCE | 2022 | High | residual fixes after 23642. |
| pre-3.41 saved-search overwrite | 2022 | Medium | authz check bug, write-only on other users' saved searches. |
| Cody VSCode `<0.14.1` | 2023 | Critical (low exploitability) | malicious-repo + `/explain` or `/doc` → arbitrary code exec on user host. Client-side, not server. |
| 2023-08 admin breach (sourcegraph.com) | 2023 | n/a (incident) | leaked site-admin token from PR; attacker minted admin account, ran LLM proxy off it. Not a CVE — process failure, but the **leaked-admin-token → admin-API → LLM-billing-theft chain is the canonical Cody-era pivot pattern**. |
| Redis CVE-2025-49844 / 46817 / 46818 / 46819 | 2025 | mixed | bundled-Redis patches, not Sourcegraph-native. |
| CVE-2026-25121 / 25122 / 26958 | 2026 | low/med | apko + edwards25519 dep updates. |
| CVE-2026-34986 | 2026 | medium | go-jose JWE DoS (dep update). |

No Sourcegraph entries in CISA KEV as of 2026-06-09. HackerOne program exists (`hackerone.com/sourcegraph`) but the listing is gated (403 to anonymous fetches) — public disclosure count not retrievable via passive fetch.

**Research gaps:**
- No public CVE for GraphQL info-disclosure under `auth.public: true` — the toggle is a documented config, not a "vuln," but it is the precise research surface for the auth-on-default thesis.
- Cody endpoints have **no documented unauth-on-misconfig CVE** despite the 2023 incident proving the LLM-billing-theft impact class. This is a hunting target.
- `authz.enforceForSiteAdmins: false` behavior — admin-token leak → all-repo read — has no dedicated advisory.

## Lane 5 — Deployment patterns

Per docs (2026-06-09):

1. **Sourcegraph Cloud** — managed, out of scope.
2. **Kubernetes Helm** — *preferred* self-hosted. Caddy or in-cluster ingress.
3. **Docker Compose** — single-node self-hosted. Caddy at `:80`/`:443`, Prometheus at `:9090`.
4. **Machine Images** — AWS AMI, Google Compute.
5. **Single-container** — **removed in 7.0.0** (still in the wild on older installs; legacy `:7080` exposure).

Compose service set (from `deploy-sourcegraph-docker` repo): sourcegraph-frontend-0, sourcegraph-frontend-internal, gitserver-0, searcher-0, zoekt-indexserver-0, zoekt-webserver-0, precise-code-intel-worker, syntactic-code-intel-worker, syntect-server, grafana, pgsql, codeintel-db, codeinsights-db, blobstore, redis-cache, redis-store, otel-collector, *-exporter sidecars, migrator, worker, caddy, prometheus, cadvisor, node-exporter.

Common K8s namespace: `sourcegraph` (Helm chart default). NodePort / LoadBalancer per env. Real-world GitHub YAML examples typically wrap a single Ingress in front of `sourcegraph-frontend` Service.

## Lane 6 — Ecosystem co-deployment & adjacent surface

The Sourcegraph stack is a **multi-service deployment on a single host** in the compose path. By design only Caddy (`:80`/`:443`) and Prometheus (`:9090`) bind to host. But: misconfigured firewall rules, `network_mode: host`, or naive `--network host` Docker runs expose:

| Service | Default port (internal) | If host-exposed → |
|---|---|---|
| **Prometheus** | 9090 | `/api/v1/targets` → entire stack inventory (Insight #11 directly applies). |
| **Grafana** | 3000 | Default admin/admin on un-bootstrapped installs (Insight #11 sibling). |
| **pgsql** | 5432 | Postgres — sourcegraph DB (users, repos, tokens). |
| **codeintel-db** | 5432 | LSIF + symbols data. |
| **codeinsights-db** | 5432 | Insights data. |
| **redis-cache / redis-store** | 6379 | Sessions, queues. |
| **blobstore (MinIO-compat)** | 9000 | LFS + uploads. |
| **zoekt-webserver** | 6070 | Code-search index API — `/search` returns matches across all indexed repos. |
| **zoekt-indexserver** | 6072 | Index admin. |
| **gitserver** | 3178 (HTTP) | Raw git proxy; CVE-2022-23642 surface. |
| **syntect-server** | 9238 | Syntax highlight. |
| **jaeger** | 16686 | Trace UI when enabled. |
| **otel-collector** | 4317 / 4318 | OTLP. |
| **cAdvisor** | 48080 | Container metrics — leaks docker labels (Insight #12 IP-direct shadow). |
| **node-exporter** | 9100 | Host metrics. |

**Insight #11 (Prometheus `/api/v1/targets`) and Insight #12 (IP-direct shadow port discovery) apply directly.** If a Sourcegraph instance has any single auxiliary port exposed, Prometheus alone hands the assessor the entire service inventory. Cert-pivot on Caddy-issued certs (`/etc/caddy/`) plus the standard `*.sourcegraph.*` CN patterns from license-managed deployments.

## Restraint posture & next-step gate

- Fingerprint only. **No** call to any Cody endpoint, **no** GraphQL mutation, **no** repo-content fetch.
- A 200 to `/.api/graphql` with `{ "data": { "site": { "productVersion": "..." } } }` from `query { site { productVersion } }` is the verified-unauth observation; capture and stop.
- An anonymous `/sign-in` page render is **not** a finding; it is the expected default.
- `auth.public: true` instances are the population worth a Stage-2 verify pass; everything else stays at Stage-1 surface-open.

## Sources

- [Sourcegraph docs — Authentication](https://sourcegraph.com/docs/admin/auth)
- [Sourcegraph docs — Site config (auth.public)](https://docs.sourcegraph.com/admin/config/site_config)
- [Sourcegraph docs — Docker single-container quickstart](https://sourcegraph.com/docs/admin/deploy/docker-single-container)
- [Sourcegraph docs — GraphQL API](https://sourcegraph.com/docs/api/graphql)
- [Sourcegraph docs — HTTP Tracing (X-Trace)](https://sourcegraph.com/docs/admin/observability/tracing)
- [Sourcegraph docs — Deploy options](https://sourcegraph.com/docs/admin/deploy)
- [deploy-sourcegraph-docker compose YAML](https://github.com/sourcegraph/deploy-sourcegraph-docker/blob/main/docker-compose/docker-compose.yaml)
- [CVE-2022-23642 gitserver RCE — PoC](https://github.com/Altelus1/CVE-2022-23642)
- [Sourcegraph 2023-08 admin-token incident postmortem](https://sourcegraph.com/blog/security-update-august-2023)
- [authentik analysis of the 2023 Sourcegraph incident](https://goauthentik.io/blog/2023-08-11-sourcegraph-security-incident/)
- [Sourcegraph CVE list (cvedetails)](https://www.cvedetails.com/vulnerability-list/vendor_id-23337/Sourcegraph.html)
- [Sourcegraph technical changelog](https://sourcegraph.com/docs/technical-changelog)
- [Cody Gateway docs](https://docs.sourcegraph.com/cody/core-concepts/cody-gateway)
