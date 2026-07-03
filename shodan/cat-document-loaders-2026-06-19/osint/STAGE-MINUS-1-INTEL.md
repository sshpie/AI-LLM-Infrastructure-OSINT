# Cat-Document-Loaders — Stage -1 OSINT Intel

**Date:** 2026-06-19
**Category:** `document_loader` (RAG-pipeline ingest / document-parsing services)
**Platforms:** apache-tika · gotenberg · docling-serve · grobid · unstructured-api
**Thesis frame:** The document loader is the unguarded front door of every RAG pipeline. All 5 are
`auth_default: off`. Each parses attacker-suppliable documents and feeds extracted text into a
downstream LLM context — so each is simultaneously (a) a memory-unsafe/XXE/SSRF parser primitive and
(b) an indirect-prompt-injection on-ramp (OWASP LLM01 / MITRE ATLAS AML.T0051).

---

## Platform matrix

| Platform | Port(s) | Auth default | Headline CVE | Sev | Fingerprint anchor |
|----------|---------|--------------|--------------|-----|--------------------|
| apache-tika | 9998 | OFF (no native auth at all) | CVE-2025-66516 XXE via XFA-PDF, tika-core 1.13–3.2.1, fix 3.2.2 | **10.0** | GET /tika → `This is Tika Server. Please PUT` |
| gotenberg | 3000 | OFF (basic-auth opt-in ≥8.4.0) | CVE-2026-40281 ExifTool value-injection FS-write/RCE, ≤8.30.1, fix 8.31.0 | **10.0** | `Gotenberg-Trace` response header |
| unstructured-api | 8000 | OFF (community image) | CVE-2025-64712 path-traversal→RCE in `unstructured` lib, fix ≥0.18.18 | **9.8** | GET /general/openapi.json → title `Unstructured Pipeline API` |
| docling-serve | 5001 | OFF (key via `DOCLING_SERVE_API_KEY`) | CVE-2026-24009 PyYAML RCE in docling-core 2.21.0–2.48.3, fix 2.48.4 | **8.1** | /docs + /openapi.json convert/source path |
| grobid | 8070/8071 | OFF (no auth either port) | none cataloged (gap) | — | GET /api/isalive → `true`; /api/version clean |

---

## Per-platform briefs

### apache-tika (port 9998)
- **Auth:** zero built-in auth. Standalone jar → localhost; official `apache/tika` Docker image binds 0.0.0.0
  inside container (README itself warns Docker may expose it). Deploy pattern IS the vuln. Every Shodan-visible
  hit is unauth by construction.
- **CVE (verified):**
  - **CVE-2025-66516** CONFIRMED, CVSS 10.0 — XXE via XFA-in-PDF, root cause tika-core (supersedes CVE-2025-54988
    which only patched pdf-module). Affects tika-core 1.13–3.2.1, fixed **3.2.2**. One PUT of a poisoned PDF to
    /tika or /rmeta → file read / SSRF / DoS. **This is the live one.**
  - CVE-2018-1335 CONFIRMED, CVSS 8.1 — cmd injection via `X-Tika-OCRTesseractPath` header on PUT /meta, 1.7–1.17,
    fix 1.18. **Precondition:** Tesseract must be installed (full image, not minimal).
  - CVE-2019-10094 CONFIRMED — archive-quine StackOverflow DoS, 1.7–1.21, fix 1.22. DoS-only.
  - CVE-2016-6809 CONFIRMED, CVSS 9.8 — jmatio deserialization RCE, <1.14. Museum piece.
- **Fingerprint:** GET /tika → exact `This is Tika Server. Please PUT`. **No /version endpoint** — version only in
  startup log / welcome banner → CVE-66516 scoping needs a behavioral probe, not banner version. FP risk: greeting
  is short, could be proxy-echoed/honeypot — anchor exact string + port 9998 + `Allow: PUT`.
- **Population:** Censys ~565 exposed Dec 2025 CORROBORATED (floor — embedded tika-core in Solr/Open WebUI invisible to banner scan).
- **RAG context:** Open WebUI (`CONTENT_EXTRACTION_ENGINE=tika`), LangChain TikaLoader, Solr Cell, Unstructured all call it.

### gotenberg (port 3000)
- **Auth:** no auth by default. Basic-auth added v8.4.0 (`--api-enable-basic-auth`). The whole HTTP API is the attack
  surface; SSRF gated only by bypassable deny-list regexes, not auth. Single-process container → RCE = takeover.
- **CVE (ALL FOUR VERIFIED REAL — not fabricated; May 2026 disclosure cluster):**
  - **CVE-2026-40281** CONFIRMED, **CVSS 10.0** — ExifTool newline injection in metadata **value** (pseudo-tags
    `-FileName/-SymLink/-HardLink` → arbitrary FS write), ≤8.30.1, fix **8.31.0**. **[CORPUS CORRECTION: the 10.0 is
    40281, not 42589.]**
  - CVE-2026-42589 CONFIRMED, CVSS 9.8 — ExifTool key injection → `-if` Perl eval → unauth RCE, ≤8.29.1.
  - CVE-2026-42595 CONFIRMED, CVSS 8.6 — SSRF via Chromium /forms/chromium/convert/url, <8.32.0, fix 8.32.0.
  - CVE-2026-42596 CONFIRMED — SSRF via IPv4-mapped IPv6 `[::ffff:127.0.0.1]` deny-list bypass, <8.32.0.
  - Sibling cluster <8.32.0: 42592 (DNS-rebind), 42597 (file:// /tmp read), 40280, 39383, 45741. **Run ≥8.32.0 to clear all.**
- **SSRF→IMDS CONFIRMED:** POST /forms/chromium/convert/url url=http://169.254.169.254/... renders IMDS into the
  returned PDF (exfil-via-render). Default deny-list blocks only file://.
- **Fingerprint:** `Gotenberg-Trace` correlation-ID header on every API response — near-unique. Port 3000 heavily
  shared (Grafana/Flowise/Express) → high FP load; `Gotenberg-Trace` is load-bearing for isolation. Population
  expected **small** (Gotenberg skews internal/sidecar).

### unstructured-api (port 8000)
- **Auth:** community self-hosted image NO auth by default. `UNSTRUCTURED_API_KEY` optional; when set, plain
  string-equality check on `unstructured-api-key` header (no hashing/constant-time). Swagger at **`/general/docs`**
  (NOT `/docs`), OpenAPI at **`/general/openapi.json`**, `/healthcheck` → 200.
- **CVE:** **CVE-2025-64712** CONFIRMED, **CVSS 9.8** — path traversal → arbitrary file write → RCE in
  `partition_msg()`/`AttachmentPartitioner`: malicious .msg attachment named `../../root/.ssh/authorized_keys`
  writes anywhere. Bug is in the `unstructured` **library** (fix ≥0.18.18), so unstructured-api repo shows "no
  advisories" — **library-wide, not api-repo-scoped.** Reachable via unauth POST /general/v0/general with files=@evil.msg.
  - Bundled-parser supply chain (no CVE, high surface): libreoffice, tesseract, pdfminer, python-docx, pandoc, nltk,
    detectron2 — any future parser CVE auto-exposed via the single unauth endpoint.
- **Fingerprint:** GET /general/openapi.json → `"title":"Unstructured Pipeline API"` + version = unambiguous + free
  version disclosure. Port 8000 EXTREMELY noisy (Django/FastAPI/ChromaDB) → anchor on title string, not port.

### docling-serve (port 5001)
- **Auth:** OFF by default. Key env is **`DOCLING_SERVE_API_KEY`** (NOT `DOCLING_API_KEY`) → header `X-Api-Key`.
  Unset = /v1/convert/source, /v1/chunk/source, /docs open. **`/ui` (Gradio) is OFF by default** (gated by
  `DOCLING_SERVE_ENABLE_UI=true`). Container envs ship `DOCLING_SERVE_HOST=0.0.0.0`. Images:
  quay.io/ghcr.io docling-project/docling-serve. New project: v0.1.0 2025-01-28 → v1.24.0 2026-06-15.
- **CVE:** **CVE-2026-24009 / GHSA-vqxf-v2gg-x3hc** CONFIRMED, CVSS 8.1 — RCE in docling-core via PyYAML
  `yaml.FullLoader` in `DoclingDocument.load_from_yaml()`. Affects docling-core 2.21.0–2.48.3 with PyYAML <5.4,
  fix **2.48.4** (SafeLoader). docling-serve embeds docling-core → vulnerable if it ingests attacker YAML and pins
  old core. **Verify deployed core version before asserting exploitable.**
- **Fingerprint:** /docs (FastAPI/Scalar) + /openapi.json with convert/source + chunk/source paths (vendor-unique).
  No confirmed /version endpoint — do NOT FP on /version. Port 5001 high-FP (Flask dev / macOS AirPlay).

### grobid (ports 8070 service / 8071 admin)
- **Auth:** NO auth either port. 8070 = REST + web console, 8071 = admin/Prometheus metrics. CORS any-origin.
  Images grobid/grobid, lfoppiano/grobid. Deploy: research labs, CERN, scholarly RAG.
- **CVE:** **ZERO direct CVEs** (NVD + GHSA both 0). Surface uncataloged:
  - `/api/modelTraining`, `/api/createTraining`, `/api/model` all unauth → compute-exhaustion / model-poisoning DoS.
  - pdfalto (xpdf 4.0.0-based) inherits xpdf memory-safety DoS surface (UNVERIFIED reachable path).
  - TEI-XML output + XML config → plausible XXE (CANDIDATE, unconfirmed in source).
  - Historical Log4Shell (#872, patched) confirms Java dep-CVE exposure exists.
- **Fingerprint:** GET /api/isalive → plain `true` (200; 503 if not ready). **GET /api/version → clean
  git-describe version** (e.g. `0.9.0-70-g94429f4e2`) — excellent CVE/commit scoping. Port 8070 low-FP/niche.

---

## Tome corpus reconciliation (write-back required — "codify every platform into tome")

1. **apache-tika** — DROP `http.headers:"X-Tika-OCR"` from all dork tiers (request header, structurally 0-hit).
   DEMOTE `product:"Apache Tika"` to secondary/CANDIDATE (Shodan product facet inconsistently populated). Body
   marker `port:9998 "This is Tika Server"` is the strict tier. Add note: no /version endpoint → version-tier dork unreliable.
2. **docling-serve** — env var is `DOCLING_SERVE_API_KEY` (corpus said `DOCLING_API_KEY`). `/ui` is OFF by default
   (corpus implied open). Add CVE-2026-24009. FP anchor = /openapi.json convert/source path, not /version.
3. **unstructured-api** — Swagger is `/general/docs` not `/docs`. Add CVE-2025-64712 (CVSS 9.8) scoped to the
   `unstructured` library (fix ≥0.18.18), reachable via the api. `"unstructured-api-key"` strict dork ≈ 0-hit
   (request-header name, not echoed) — demote.
4. **gotenberg** — CVSS 10.0 belongs to CVE-2026-40281 (value injection), not 42589 (9.8 key injection). Add the
   sibling SSRF cluster note (<8.32.0). Population expected small.
5. **grobid** — tome entry thin/possibly missing; write full platform JSON. /api/version clean-scoping is the key add.

---

## Dork set for Stage 0 (Shodan harvest)

| Platform | basic | strict | version |
|----------|-------|--------|---------|
| apache-tika | `port:9998 http.html:"Tika Server"` | `port:9998 "This is Tika Server"` | `port:9998 product:"Apache Tika"` (weak) |
| gotenberg | `port:3000 http.headers:"Gotenberg-Trace"` | `port:3000 "Gotenberg-Trace"` | (no version in banner) |
| unstructured-api | `http.html:"Unstructured Pipeline API"` | `port:8000 http.html:"/general/v0/general"` | openapi.json title+version (active) |
| docling-serve | `port:5001 "docling-serve"` | `port:5001 http.html:"docling"` | /openapi.json convert/source (active) |
| grobid | `port:8070 http.html:"grobid"` | `port:8070 "GROBID"` | /api/version (active) |

**0-result discipline:** a 0-hit dork is a logged result, not a skip — generate header-case / body variants and pivot
to Censys (Step 0b) for header/JSON signals the Shodan web UI returns 0 on.

## Restraint ethic for this category
Document parsers. Enumerate the open parse surface + confirm version for CVE scoping. Do NOT fire XXE / SSRF / file-write
payloads at live third-party hosts. Open-no-auth + version-in-CVE-range = "exploitable IF," recorded as surface-open,
access-not-exercised (Insight #68 high-depth / low-breadth by choice). Names + version + unauth-confirmation ARE the finding.
