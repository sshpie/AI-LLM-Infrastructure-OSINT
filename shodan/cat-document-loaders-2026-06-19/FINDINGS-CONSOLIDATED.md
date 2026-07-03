# Cat-Document-Loaders 2026-06-19 — Consolidated Findings

## Headline
A **179-host unauthenticated Gotenberg fleet** where **100% of version-resolved instances
(109/109) run < 8.31.0** — every one in range for **CVE-2026-40281 (ExifTool RCE, CVSS 10.0)**,
**CVE-2026-42589 (ExifTool RCE, 9.8)**, and the full **SSRF→cloud-IMDS cluster (<8.32.0)**.
Zero patched. The May-2026 fix (8.32.0) has **0% adoption** in this population. Plus a
**22-host unauthenticated GROBID** scholarly-PDF ingest tier. **0 deception-fleet catch-alls** —
the entire population is genuine (the inverse of Cat-Langflow 2026-06-18).

Restraint ethic held: confirmed open + version (read-only); **no XXE/SSRF/RCE payload was fired**.
Every "exploitable" is recorded **surface-open, access-not-exercised** (Insight #68 high-depth/low-breadth).

## Category thesis
Document loaders are the unguarded front door of every RAG pipeline. All 5 surveyed platforms are
`auth_default: off`. Each is simultaneously (a) a memory-unsafe / XXE / SSRF / file-write parser
primitive and (b) an indirect-prompt-injection on-ramp (OWASP LLM01 / MITRE ATLAS AML.T0051): a
poisoned document parsed by an exposed loader feeds extracted text straight into the downstream LLM.

## Harvest funnel
```
Stage -1 OSINT (5 parallel lanes)  -> 5 platforms, all auth-off, CVE landscape verified, 5 corpus fixes
Stage 0  Shodan (Playwright web UI) -> Gotenberg 748 / GROBID 25 / docling 1; Tika+Unstructured SHODAN-DARK
Stage 0  harvested                  -> 210 unique candidate IPs (Gotenberg 184, GROBID 25, docling 1)
Stage 0d aimap fingerprints built   -> 5 new FPs (Apache Tika, Gotenberg, GROBID, docling-serve, Unstructured API)
Stage 3v VERIFY (marker+catchall+ver)-> 201 CONFIRMED-OPEN / 0 catch-all / 9 dead-or-refuted
```

## Confirmed population (Stage 3v, marker-anchored + catch-all-guarded)
| Platform | Confirmed open | Version-resolved | CVE-in-range | Headline CVE |
|----------|---------------:|-----------------:|--------------|--------------|
| Gotenberg | **179** | 109 (+70 ver-unknown) | **109/109 < 8.31.0** | CVE-2026-40281 ExifTool RCE 10.0 + SSRF→IMDS |
| GROBID | **22** | 22 (v0.7.3–0.9.1) | n/a (no CVE) | unauth /api/modelTraining DoS + open ingest |
| docling-serve | 0 | — | — | (1 Shodan hit did not confirm open) |
| apache-tika | 0 (Shodan-dark) | — | — | Censys-deferred (~565 baseline, scarce credits) |
| unstructured-api | 0 (Shodan-dark) | — | — | Censys-deferred |
| **TOTAL** | **201** | — | — | — |

### Gotenberg version distribution (109 resolved)
Top: 8.25.1 (23) · 8.27.0 (14) · 8.21.1 (10) · 8.24.0 (8) · 8.26.0 (8) · 8.20.1 (5) · 8.28.0 (5) · 8.23.1 (3)
Range observed: **8.5.0 → 8.28.0**. Newest fix 8.32.0. **None ≥ 8.31.0.**
- `< 8.31.0` → CVE-2026-40281 (ExifTool value-injection FS-write/RCE, **10.0**) + CVE-2026-42589 (key-injection `-if` Perl RCE, 9.8): **109/109**
- `< 8.32.0` → adds SSRF→IMDS (CVE-2026-42595 Chromium URL-to-PDF, CVE-2026-42596 IPv6 deny-list bypass) + DNS-rebind/file-read siblings: **109/109**
- 70 version-unknown hosts are confirmed-open (Gotenberg-Trace header present) but `/version` did not return a clean string; treat as probable-vulnerable, version-unconfirmed.

### GROBID version distribution (22 resolved)
0.8.2 (7) · 0.8.0 (5) · 0.7.3 (3) · 0.9.0 (3) · 0.9.1 (2) · 0.8.3 (2). All unauth on 8070.
No cataloged CVE. Surface: unauth `/api/processFulltextDocument` (free scholarly-PDF ingest +
indirect-injection on-ramp), unauth `/api/modelTraining` (compute-exhaustion DoS), pdfalto xpdf DoS inheritance.

## Why this is a finding, not a scan artifact
- **0 catch-all** across 210 probes. The LBot deception-fleet (Insight #107/#108) that poisoned
  Cat-Langflow returns 200+canned-body on nonsense paths; here every nonce path failed the marker —
  these are real services. The Gotenberg-Trace correlation header is a structural tell the fleet does not fake.
- **Observer-position gate (Insight #96) PASSED CLEAN**: control hosts (example.com, scanme.nmap.org)
  returned real content through the same path; no L7 rewriting. (Note: run was NOT on Mullvad — flagged;
  read-only marker probing, no payloads, so exposure is minimal, but a Mullvad re-confirm would harden.)
- **aimap independent corroboration**: the 5 new fingerprints fire on confirmed hosts and report
  `AUTH: NONE` independently of the verify prober (3/3 sampled: 2 Gotenberg, 1 GROBID).

## Pivot avenues (read-only, NOT exercised — operator's choice)
1. **Gotenberg SSRF→IMDS reachability test** (CVE-2026-42595): one `POST /forms/chromium/convert/url`
   with `url=http://169.254.169.254/latest/meta-data/` would render IMDS into the returned PDF on a
   cloud-hosted instance. Confirms credential-theft blast radius. NOT fired (restraint).
2. **Gotenberg ExifTool RCE** (CVE-2026-40281): metadata-write endpoint, value-injection. NOT fired.
3. **GROBID modelTraining DoS**: unauth POST triggers compute job. NOT fired.
4. **Operator attribution** (VisorGraph cert-pivot): cluster the 179 Gotenberg by ASN/cert to find
   multi-host operators (many on Hetzner/DO/OVH/Contabo prefixes — sidecar-in-RAG-stack pattern).
5. **Censys 0b** for the Shodan-dark Tika (~565) + Unstructured tiers (scarce credits — budget first).
6. **Indirect-injection chain mapping** (llm-redteam lens): which of these loaders front a public
   RAG chatbot — poisoned-doc → loader → vector store → LLM context (OWASP LLM01).

## CVE reference (in-range, not exercised)
- CVE-2026-40281 (10.0) ExifTool value-injection FS-write/RCE, Gotenberg ≤8.30.1, fix 8.31.0
- CVE-2026-42589 (9.8) ExifTool key-injection `-if` Perl RCE, ≤8.29.1
- CVE-2026-42595 (8.6) SSRF Chromium URL-to-PDF →IMDS, <8.32.0
- CVE-2026-42596 SSRF IPv6 deny-list bypass, <8.32.0  (+ siblings 42592/42597/40280/39383/45741)
- Tika CVE-2025-66516 (10.0) XXE→file-read/SSRF/IMDS, tika-core 1.13–3.2.1, fix 3.2.2 [Censys-deferred tier]
- Unstructured CVE-2025-64712 (9.8) path-trav→RCE, fix lib ≥0.18.18 [Censys-deferred tier]
- docling-serve CVE-2026-24009 (8.1) PyYAML RCE via docling-core 2.21.0–2.48.3, fix 2.48.4 [0 confirmed]

## Insight candidates
- **Cand #109**: auth-OFF-by-default infra-glue (Gotenberg/Tika/GROBID/Unstructured/docling) inverts the
  auth-on-default thesis (Insight #40). These are not user-facing AI apps under disclosure pressure;
  they are internal sidecars operators expose by accident. 100%-unpatched-fleet is the signature.
- **Cand #110**: patch-lag as population clock — a fleet 100% below a fix released ~1 month prior
  measures the update half-life of accidental-exposure infra (here: effectively infinite, 0% adoption).
