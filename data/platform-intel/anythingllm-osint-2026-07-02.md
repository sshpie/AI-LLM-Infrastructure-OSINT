---
category: cat-anythingllm
platform: AnythingLLM
date: 2026-07-02
status: pre-assessment
---

# AnythingLLM — Pre-Assessment OSINT
_NuClide Research · 2026-07-02 · Cat-AnythingLLM_
_6-squad OSINT Platoon output. Informs dorks, verification probes, aimap fingerprint, shadow sweep._

---

## Auth Posture

**Tier: A* (auth optional, OFF by default)**

Default install ships `RequiresAuth=false`. Source: `server/models/systemSettings.js`:
```js
RequiresAuth: !!process.env.AUTH_TOKEN  // false when AUTH_TOKEN unset
```

All four auth env vars (`AUTH_TOKEN`, `JWT_SECRET`, `SIG_KEY`, `SIG_SALT`) are **commented out** in `docker/.env.example`. First-visit onboarding shows the app before any password is set; password-protect is an opt-in toggle.

**Middleware bypass (global, not per-route):** `server/utils/middleware/validatedRequest.js`:
```js
if (
  process.env.NODE_ENV === "development" ||
  !process.env.AUTH_TOKEN ||
  !process.env.JWT_SECRET
) { next(); return; }
```
Either condition alone is sufficient. Operator can set `AUTH_TOKEN` but omit `JWT_SECRET` and all routes remain open.

**Known auth bug (Issue #5036):** Passwords containing `#` are silently truncated to empty string via `.env` comment-parsing. Instance restarts open even after password appears set.

---

## Kill Chain (3 requests, zero credentials)

```
1. GET /api/setup-complete       -> full stack config + storage paths + key booleans
                                    (pre-1.10.0: plaintext Qdrant/Ollama API keys)
2. POST /api/request-token       -> valid JWT, no credentials required when RequiresAuth=false
3. JWT -> GET /api/v1/workspaces -> workspace list, slugs, IDs
        -> GET /api/v1/workspace/{slug}/chats -> full conversation history
        -> POST /api/v1/workspace/{slug}/chat -> LLM inference via operator's API key
        -> GET /api/v1/documents             -> document listing
        -> POST /api/v1/admin/*              -> admin actions
```

Full tenant compromise: 3 requests. Network adjacency only.

---

## Unauthenticated Surface Map

### Critical (no auth middleware)

- **`GET /api/setup-complete`** — `SystemSettings.currentSettings()` blob:
  - `LLMProvider`, `LLMModel`, `VectorDB`, `EmbeddingEngine`, `StorageDir` (plaintext FS path)
  - Vector DB connection strings: `MilvusAddress`, `MilvusUsername`, `PineConeIndex`, `QdrantUrl` (plaintext)
  - API key presence booleans for: OpenAI, Anthropic, Gemini, Groq, Mistral, Pinecone, Qdrant, Weaviate, Voyage, ElevenLabs, SerpAPI, Brave
  - Pre-v1.10.0 (CVE-2024-6842/CVE-2026-24477): `QdrantApiKey`, `OllamaToken` returned in plaintext
  - Fields: `RequiresAuth`, `AuthToken` (bool), `JWTSecret` (bool), `MultiUserMode`, storage paths

- **`POST /api/request-token`** — returns valid JWT with zero credentials when no password set

### High (schema disclosure)

- **`GET /api/docs`** — Swagger UI, enabled by default (`DISABLE_SWAGGER_DOCS=true` to disable). Full OpenAPI spec + live "Try it out" interface. Identity probe AND schema disclosure.
- **CORS `origin: true`** (CVE-2026-32617) — accepts all origins. Cross-origin requests from any browser tab work.

### Medium (info only)

- `GET /api/onboarding` — `{onboardingComplete: bool}`
- `GET /api/system/multi-user-mode`
- `GET /api/system/custom-app-name`
- `GET /api/ping`

### Gated regardless of RequiresAuth

`/api/v1/*` uses separate `validApiKey` middleware — 403 without API key regardless of auth state.

---

## CVE Inventory

| CVE | CVSS | Type | Affected | Patched |
|-----|------|------|----------|---------|
| CVE-2024-3104 | 9.8 | OS cmd injection `/api/system/update-env`, no auth | < 1.0.0 | 1.0.0 |
| CVE-2024-13059 | 9.1 | Path traversal -> RCE via multer non-ASCII filename | < 1.3.1 | 1.3.1 |
| CVE-2024-3279 | 9.1 | Unauth DB import/delete/spoof | unknown | unknown |
| CVE-2024-3152 | 8.8 | SSRF + arbitrary file read/delete via collector (port 8888) | < 1.0.0 | 1.0.0 |
| CVE-2024-4287 | 8.1 | Manager->Admin priv esc via Prisma injection | unknown | unknown |
| CVE-2024-0549 | 8.1 | Relative path traversal, default role can delete anythingllm.db | unknown | commit 026849d |
| CVE-2024-6842 | 7.5 | Unauth info disclosure `/api/setup-complete` search engine API keys | <= 1.5.5 | post-1.5.5 |
| CVE-2024-22422 | 7.5 | Unauth DoS via data-export path manipulation | < 2024-01-18 | commit 08d33cfd8 |
| CVE-2024-8251 | - | Prisma injection in embed stream-chat | < 1.2.2 | 1.2.2 |
| CVE-2024-5213 | - | Password hash returned in login/register response | <= 1.5.3 | post-1.5.3 |
| GHSL-2025-056 | - | Ollama auth token exposed via `/api/setup-complete` | <= 1.7.8 | 2025-05-07 |
| CVE-2026-24477 | - | Qdrant API key plaintext in `/api/setup-complete` | < 1.10.0 | 1.10.0 |
| CVE-2026-32617 | - | Auth bypass no-password default, CORS origin:true | <= 1.11.1 | > 1.11.1 |
| CVE-2026-5627 | - | Path traversal Agent Flows uuid param (arbitrary .json r/w) | unknown | unknown |

**`/api/setup-complete` recurring leak surface: 3 separate CVE cycles (search keys, Ollama token, Qdrant key). Single GET, zero auth.**

**Version breakpoints:**
```
>= 1.10.0  Qdrant key safe
>  1.7.8   Ollama token safe
>  1.5.5   Search engine key safe
>  1.3.1   Path traversal/RCE safe
>= 1.0.0   Cmd injection (9.8) safe
<= 1.11.1  Auth bypass (CVE-2026-32617) still present
```

**Latest stable: v1.15.0 (June 2026)**
**CISA KEV: no entries**
**Nuclei templates: CVE-2024-6842.yaml, CVE-2026-24477 template**

---

## Shodan Fingerprint

**Primary dork (near-zero FP):**
```
http.title:"AnythingLLM"
```
Title hardcoded in `frontend/index.html`: `AnythingLLM | Your personal LLM trained on anything`

**Strict (port-constrained):**
```
http.title:"AnythingLLM" port:3001
```

**Secondary (catches non-standard titles):**
```
port:3001 http.html:"AnythingLLM" http.html:"workspace"
```

**Identity probe (active):**
```
GET /api/setup-complete -> 200 application/json with RequiresAuth + MultiUserMode fields
GET /api/docs           -> Swagger UI with AnythingLLM paths
```

**FP notes:**
- `http.title:"AnythingLLM"` — near zero, no other app uses this string
- `port:3001` only — high FP (many services on 3001)
- Favicon at `/favicon.png`, NOT `/favicon.ico` — Shodan hash misses it

**Estimated population:** ~3,766 (Arxiv April 2025, title-based). Fresh harvest expected 1,000-5,000 range.
**Default port:** 3001 (configurable via SERVER_PORT)
**Also seen on:** 80, 443, 8080 (operator-configured)

---

## Deployment Patterns

- **Operator profile:** SMBs, law firms, dev teams, privacy-first individuals. 1M+ Docker Hub pulls, ~58K/week.
- **Data in workspaces:** PDFs, DOCX, code repos, Confluence, YouTube transcripts, contracts, internal wikis.
- **LLM backends:** Ollama (most common in tutorials), OpenAI, Anthropic, Azure, Bedrock, Groq. API keys stored in `.env` mounted into container.
- **Vector DB:** LanceDB embedded default (zero-config, no separate port). Scale-out: Qdrant, Chroma, PGVector, Weaviate.
- **Container privilege:** Official compose includes `--cap-add SYS_ADMIN` (Chromium doc parsing). Container escape surface if initial access achieved.
- **Cloud:** Hetzner, DigitalOcean, AWS EC2 (free tier tutorials). Managed: Elestio (Hetzner/DO/Vultr under the hood).
- **Workspace slugs:** Auto-generated, lowercased, hyphenated. Common: `company-docs`, `legal`, `research`, `internal`, `knowledge-base`.

---

## Shadow Port Priority

| Port | Service | Priority |
|------|---------|---------|
| 8888 | AnythingLLM Collector (built-in) | HIGH - SSRF surface (CVE-2024-3152), rarely firewalled separately |
| 11434 | Ollama | HIGH - #1 local LLM backend, high prior for double-exposure |
| 4000 | LiteLLM proxy | MED |
| 5432 | PostgreSQL/pgvector | MED - first-class vector backend |
| 8000 | Chroma | MED |
| 6379 | Redis | LOW - only with LiteLLM caching layer |
| 9100 | node_exporter | LOW |

**Double-exposure pattern:** AnythingLLM + Ollama on same host = two unauthenticated surfaces. High confidence on any host using local LLM backend.

---

## aimap Fingerprint State

Existing fingerprint in `~/ai-recon/aimap/fingerprints.go` (validated 2026-05-29):
- Probe: `/api/setup-complete` with 4 conjuncts (status_code:200, json_field:results, body_contains:RequiresAuth, body_contains:MultiUserMode)
- Secondary: `/` with title match
- DefaultPorts: [3001, 80, 443]

**Enhancement needed:** Add `/api/docs` Swagger probe as third probe path. Add auth-bypass boolean extraction from `RequiresAuth` field to drive `auth_status` determination.

---

## Tome Status

Platform not yet in tome corpus. Write JSON after first population probe confirms live instances.
