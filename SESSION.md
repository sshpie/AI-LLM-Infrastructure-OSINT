# SESSION — Cat-AnythingLLM

Last updated: 2026-07-02

## Status: COMPLETE

## What ran

Full NuClide assessment chain on AnythingLLM (mintplex-labs/anything-llm), port 3001.

## Key findings

1. **54.183.142.27** (VisorLog #84, MEDIUM) — Truly open but unconfigured
   - modernlending.useanything.com (Mintplex managed hosting, financial services)
   - RequiresAuth=false, MultiUserMode=false, JWTSecret=false
   - Kill chain broken: POST /api/request-token returns 500 (no JWT_SECRET)
   - Swagger UI /api/docs/ live without auth
   - No LLM/API keys, no embeddings — unconfigured instance

2. **54.241.60.205** (VisorLog #85, HIGH) — Multi-user gated, AWS Bedrock
   - AWS IAM AccessKeyId + AccessKey confirmed present in /api/setup-complete
   - Region: eu-north-1 (Stockholm). VectorDB: lancedb. Model: Claude 4.5
   - MultiUserMode=true (gated), access NOT exercised

3. **51.91.122.245** (VisorLog #86, HIGH) — Multi-user gated, Anthropic + corpus
   - AnthropicApiKey=True, claude-opus-4-7, HasExistingEmbeddings=True
   - OVH France VPS, GDPR scope. Port 8000 Uvicorn 401. Caddy frontend.
   - MultiUserMode=true (gated), access NOT exercised

4. **136.243.19.124** (VisorLog #87, HIGH) — Double-exposure (AnythingLLM secured, Ollama open)
   - AnythingLLM :3001 auth-on. Ollama :11434 OPEN, version 0.16.1
   - 4 models: gemma-4-12B-coder (6GB), glm-5.2:cloud, deepseek-v4-pro:cloud, llama3.2:3b
   - Hetzner dedicated server Germany, GDPR scope

## Key methodology findings

- Cat-07 71% open rate was WRONG — RequiresAuth alone insufficient
- Correct classifier: RequiresAuth=false AND MultiUserMode=false
- Corrected rate: 1/56 = 1.8% truly open
- Shadow port scan: 87.9% FP rate (dizquetv catch-all fleet, Linode/Akamai IPs)
- Insights #109 + #110 codified and pushed

## Population

- Shodan: 1,022 indexed, 92 harvested (web UI cap), 56 live
- Favicon hash (mmh3): -2031852229 (/favicon.png)
- BARE: all findings 0.471-0.520 (novel class, zero MSF coverage)
- VisorLog: #84-87 ingested

## Artifacts

- data/cat-anythingllm/findings-breakdown.txt
- data/cat-anythingllm/aimap-open.json (evidence)
- data/platform-intel/anythingllm-osint-2026-07-02.md
- research-program/insights/109-*.md
- research-program/insights/110-*.md
- shodan/query-log.md (updated)
- ~/tome/platforms/anythingllm.json (CONFIRMED, population_survey added)

## GitHub

Pushed: nuclide-research/AI-LLM-Infrastructure-OSINT @ 678c9d1
Pushed: nuclide-research/tome @ e2e720e

## Next

- aimap fingerprint enhancement: add MultiUserMode cross-check to auth_status determination
- Cat-Flowise findings (9 UNAUTH_CHATFLOWS found last session) not yet pushed
- Consider Cat-OpenWebUI or Cat-LibreChat as next category
