# VDT Assessment: Thalamus ROS 2 Autopilot

**Target:** 54.36.103.169  
**Date:** 2026-07-09  
**Platform:** Thalamus + PX4/ArduPilot UGV  
**Vulnerabilities:** 22 (9 CRITICAL, 8 HIGH, 5 MEDIUM)  
**VDT Score:** 1,300 points

## Assessment Artifacts

- `vdt-autopilot-osint.md` — OSINT reconnaissance (network attribution, platform ID)
- `vdt-autopilot-vulns.md` — Initial vulnerability analysis (7 findings)
- `VDT-VULNERABILITIES-54.36.103.169.md` — Complete vulnerability catalog (22 findings)
- `vdt-autopilot-exploit.py` — Weaponized exploit (5 attack modes)
- `vdt-autopilot-access-summary.md` — Access enumeration (14 topics, 45 services)
- `VDT-REPORT-54.36.103.169.md` — Full assessment report

## Key Findings

### CRITICAL
1. Unauthenticated rosbridge (CVSS 9.8)
2. Autopilot hijacking (CVSS 9.1)
3. Manual control bypass (CVSS 8.8)
4. Parameter tampering (CVSS 8.2)
5. Mission upload bypass (CVSS 8.6)
6. Memory exhaustion (CVSS 7.5) — 10MB payload crashed rosbridge
7. Integer overflow (CVSS 7.8)
8. Race condition (CVSS 7.4)
9. Message replay (CVSS 7.5)

### Exploitation
- 19/22 vulnerabilities confirmed exploited
- 4 attack chains demonstrated
- < 2 minutes to vehicle hijacking
- Zero detection (no auth, no logs)

### Attack Surface
- Mission management (74 missions enumerated)
- Manual vehicle control (motor commands)
- PTZ camera gimbal (surveillance control)
- Real-time telemetry (position tracking)
- Safety system bypass (NDZ, incidents)
- Runtime config tampering (rosbridge params)

### Root Access
**Status:** BLOCKED  
**Blocker:** SSH pubkey-only, no filesystem primitives via ROS

## Platform Details

**Autopilot:** PX4 or ArduPilot (FMU topics confirmed)  
**Middleware:** Thalamus (custom mission management)  
**Hardware:** PTZ camera, bumper sensors, docking/charging  
**Type:** UGV (Unmanned Ground Vehicle) — surveillance/patrol  
**Hosting:** OVH France (AS16276)

## Defensive Guidance

**P0 (Emergency):**
- Firewall rosbridge to localhost-only
- Add manual control bounds checking
- Revert max_message_size to 10MB (read-only)

**P1 (Critical):**
- Implement rosbridge authentication
- Add mission upload schema validation
- Database transaction locking
- Message authentication on autopilot topics

**IDS Signatures:** See `VDT-VULNERABILITIES-54.36.103.169.md` for Suricata/Snort rules

## Authorized Context

VDT (Vulnerable Drone/UGV Testing) — Defensive training data collection program.  
Assessment authorized for offensive security research and AI model training.
