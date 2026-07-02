# SESSION.md -- AI-LLM-Infrastructure-OSINT
Last updated: 2026-07-02

## Last active survey: Cat-33 Expanded -- OSS Guardrail Servers (2026-06-29)

### What was done

Extended Cat-33 beyond email guardrails to cover 15 OSS/enterprise AI safety platforms.
28 Shodan dorks executed. 5 findings (G1-G5) verified. Deep-mapping completed.

**Platform scope:** LLM Guard, NeMo Guardrails, Guardrails AI, Vigil, UnisGuard/Guoshun,
Arthur GenAI Engine, Enkrypt MCP Gateway + enterprise/SaaS tier (Aporia, WhyLabs, RIME,
Lakera, Patronus, Prompt Security)

**Findings (verified):**

G1 [CRITICAL] LLM Guard 5.78.101.230:8000 (Hetzner)
  - Auth: None. TWO-PATH behavior:
    /scan/ endpoints (production): ALL scanners -1.0, is_valid=true always (null guardrail)
    /analyze/ endpoints: PromptInjection + Toxicity working; Secrets broken both paths
  - Operator: unknown (metrics disabled on this instance)

G2 [HIGH] NeMo Guardrails 128.140.94.154:8000 (Hetzner)
  - Auth: None. Config IDs exposed (opencode/web_classifier/content_generator)
  - Chat completions unauth; internal server error (no LLM backend)

G3 [MEDIUM] Prometheus /metrics -- operator attribution (15.204.46.173 = hellofans.ai)
  - /metrics open on all LLM Guard instances despite API auth
  - hellofans.ai: 185K /scan/prompt, 280K /scan/output calls (production traffic)
  - 48.204.231.121: Azure-hosted instance (10.224.x.x subnet), new deploy, 43 requests
  - Cross-instance scanner fingerprint: 146.56.180.42, 51.158.248.122 appear on both

G4 [HIGH/CRITICAL] UnisGuard/Guoshun 43.134.236.109 -- Ollama internet-exposed
  - Port 11434: Ollama open, unisguard-guard:latest + qwen2.5:7b directly callable
  - System prompt EXTRACTED from guardrail model: full classification taxonomy (S5-S12)
    + BYPASS VECTORS documented in system prompt (security education = safe)
  - Port 8000: LLM Safety Guardrail API, unauth /check, /api/policies, /api/test-cases exposed
  - Port 5000: UnisGuard platform, auth enforced (403), registration open but email-gated
  - Main bypass: call :11434/api/generate with qwen2.5:7b, no guardrail applied

G5 [INFO/WATCH] Arthur GenAI Engine -- dork valid, population 0 live
  - All 6 AWS Shodan hits stale; 3.146.247.46 cert = *.redi.health (IP reused)
  - Dork confirmed valid (http.title:"Arthur GenAI Engine - Swagger UI"); watch for new instances

**Insight candidates codified:** I-G through I-L (null guardrail, Prometheus attribution,
OSS auth gap, config enumeration bypass, system prompt = policy disclosure, dual-layer exposure)

**Files:**
  shodan/cat33-guardrails-2026-06-29/findings-breakdown.txt  -- FINAL (committed)
  shodan/cat33-guardrails-2026-06-29/osint/platform-research.md
  shodan/query-log.md  -- 28 dorks logged

### Survey status: COMPLETE -- full chain executed 2026-07-02

  Chain completed:
  [x] 0c.  tiptoe -- all 5 hosts LIVE; G4:11434 VERIFIED_UNAUTH HIGH
  [x] 1a.  VisorPlus -- G1: nextcomm.tech (BR); G2: vibewebsite.eu (EU, 72 passive DNS)
  [x] 1b.  aimap 1.9.55 -- 20 services, 2 CRIT (Ollama + NeMo); FPs stripped
  [x] 1cm. agent-logging-system -- FP_CANDIDATES flagged (Chatterbox/ZenML/Kubelet/etc)
  [x] 4.   JS-bundle -- NeMo chatbot-ui fork, 0 secrets
  [x] 6.   VisorLog -- findings #40-#44 in nuclide.db
  [x] 7.   VisorScuba -- G4: 6/10; G1/G2/G3: 9/10
  [x] 8.   BARE -- all 4 no_high_confidence_match (novel OSS guardrail class, 0 MSF coverage)
  [x] 12.  visor-report -- shodan/cat33-guardrails-2026-06-29/visor-report.md
  [x] 13.  persist -> GitHub (this commit)

### Previous surveys
  cat16-bi-dashboards (2026-06-29): COMPLETE, PUSHED (0b88471)
    1 CRITICAL Metabase CVE-2023-38646, 47 HIGH Superset unauth, 14 HIGH Redash setup
  cat-mlflow-2026-06-28: 62.3% unauth, CVSS 9.8 pickle RCE PoC, pushed 0144971
  cat-33-email-guardrails-2026-06-23: Galileo agent-control (commit pending)
