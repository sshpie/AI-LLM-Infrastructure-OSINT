# Insight #110: Shadow port uniform cohort = deception fleet — discrimination via spot-check

**Survey:** Cat-AnythingLLM, 2026-07-02
**Finding type:** Methodology / false positive discrimination
**Impact:** 87.9% false positive rate on shadow port scan for this corpus

## Statement

When a shadow port scan shows a cohort of IPs with ALL shadow ports open simultaneously,
the near-certain explanation is a catch-all deception fleet, not legitimate services.

Spot-check 2-3 IPs from any all-ports-open cohort. If they return the dizquetv payload
(`{"dizquetv":"1.5.3","ffmpeg":"root:wW0sffoqsk..."}`) on any port, the entire cohort is decoys.

## Evidence

Cat-AnythingLLM naabu shadow scan (ports 8888, 11434, 4000, 5432, 8000, 6379, 9100, 3000):
- 58/92 IPs with at least 1 shadow port "open"
- 51/58 showing ALL 8 shadow ports open simultaneously
- Spot-check of 3 Linode IPs: all returned `{"dizquetv":"1.5.3","ffmpeg":"root:wW0sffoqsk..."}` on port 11434
- Same catch-all payload on 8888 (HTML response)
- True positive rate: 2/58 = 3.4%

Real signals (not decoys):
- `51.91.122.245:8000` — Uvicorn 401 Basic auth (asymmetric: only port 8000 open)
- `136.243.19.124:11434` — Ollama 0.16.1 (asymmetric: only port 11434 open, 8888 refused)

## Discrimination rule

Deception tell: `|ports_open| == N` where N = entire scan target set, across a cohort of IPs.

Legitimate tell: asymmetric port set (some ports open, most not — reflects actual services deployed).

Spot-check protocol:
1. Identify any IP with ALL scanned ports showing "open"
2. Run `GET http://<ip>:<any_shadow_port>/` 
3. If response contains `"dizquetv"` or `"root:wW0sffoqsk"`, the IP is a decoy
4. Count how many IPs in the cohort share exact same port-open bitmask
5. If cohort size > 5 with identical bitmask, flag entire cohort as deception fleet

## Pattern provenance

Same dizquetv catch-all payload seen in:
- Cat-39 MCP servers (70-host canned-406 honeypot fleet)
- Cat-13 Milvus/Chroma survey
- Cat-AnythingLLM (51-host Linode cohort)

IP ranges: predominantly Linode/Akamai (45.33.x.x, 45.79.x.x, 172.104.x.x, 172.105.x.x,
172.233.x.x, 172.234.x.x, 50.116.x.x, 23.92.x.x, 23.239.x.x).

## Action

Add catch-all discrimination to shadow port scanning:
1. Group IPs by port-open bitmask
2. Any group with ≥5 IPs sharing identical full-bitmask: spot-check 1 IP before accepting results
3. Log deception fleet size alongside true positive count in findings breakdown
