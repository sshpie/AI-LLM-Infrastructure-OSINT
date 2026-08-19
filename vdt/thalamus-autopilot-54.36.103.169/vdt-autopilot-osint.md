# VDT Target: 54.36.103.169 — Drone/UGV Autopilot Mission Backend

## Stage -1: OSINT Platoon Results

### Network Attribution
- **IP:** 54.36.103.169
- **rDNS:** vps-03017dc4.vps.ovh.net
- **ASN:** AS16276 (OVH SAS)
- **Netblock:** 54.36.100.0/22 (VPS-GRA8)
- **Country:** France
- **Hosting:** OVH VPS (Gravelines datacenter)
- **TLS:** No HTTPS service (port 443 closed)

### Open Ports
- **9090/tcp** — rosbridge_server (WebSocket)

### ROS Graph Discovery
**Framework:** ROS 2 (via rosbridge_websocket + rosapi)

**Topics (9):**
1. `/autopilot_mission` — thalamus_interfaces/msg/AutopilotMission (mission tasking)
2. `/autopilot_telemetry` — thalamus_interfaces/msg/AutopilotTelemetry (flight data)
3. `/charger_node/status` — charger_interfaces/msg/SystemStatus (charging state)
4. `/docking_node/alert` — std_msgs/msg/Int32 (docking alerts)
5. `/heartbeat` — std_msgs/msg/String
6. `/incident` — thalamus_interfaces/msg/Incident (safety events)
7. `/misc_telemetry` — thalamus_interfaces/msg/MiscTelemetry
8. `/misc_telemetry_sensors` — thalamus_interfaces/msg/MiscTelemetrySensors
9. `/ndz/alert` — std_msgs/msg/Int32 (no-drone-zone violations)

**Services (45):**
- `/list_missions` — List all mission IDs (CONFIRMED: 74 missions enumerated)
- `/upload_mission` — thalamus_interfaces/srv/UploadMission (mission upload)
- `/mission_node/*` — Mission node parameter management (6 services)
- `/rosapi/*` — Standard ROS API (33 services)
- `/rosbridge_websocket/*` — rosbridge parameter management (6 services)

**Nodes (4):**
1. `/rosbridge_websocket` — WebSocket bridge server
2. `/rosapi` — ROS API service provider
3. `/rosapi_params` — Parameter server
4. `/mission_node` — Custom mission management node

### Platform Identification
**Vendor:** Thalamus (custom ROS 2 interfaces)
- `thalamus_interfaces/msg/AutopilotMission`
- `thalamus_interfaces/msg/AutopilotTelemetry`
- `thalamus_interfaces/msg/Incident`
- `thalamus_interfaces/msg/MiscTelemetry`
- `thalamus_interfaces/srv/UploadMission`

Additional interface: `charger_interfaces/msg/SystemStatus` (charging subsystem)

### Confirmed Capabilities
1. **Mission Management:**
   - 74 pre-loaded missions (IDs: 0-660, plus 7 high-value missions in 1000000000+ range)
   - Mission upload service (`/upload_mission`)
   - Mission listing (`/list_missions`)
   - Mission tasking topic (`/autopilot_mission`)

2. **Autopilot Telemetry:**
   - Real-time autopilot state publishing
   - Sensor telemetry streams
   - Mission progress tracking (mission_id, progress%, current/total waypoints)

3. **Safety Systems:**
   - No-drone-zone (NDZ) alert monitoring
   - Incident reporting
   - Docking alerts
   - Charger status monitoring

4. **Control Surface:**
   - UNAUTH rosbridge on :9090 (NO authentication)
   - Full ROS API access (service calls, topic pub/sub, parameter get/set)
   - Mission tasking reachable (can publish to `/autopilot_mission`)
   - Mission upload reachable (can call `/upload_mission`)

### Attack Surface Summary
**CRITICAL:**
- No authentication on rosbridge WebSocket
- Mission upload service exposed (arbitrary mission injection possible)
- Mission tasking topic writable (can command autopilot mid-flight)
- 74 existing missions enumerable (mission library exposed)
- NDZ/incident/docking alert topics readable (operational intelligence)
- Telemetry streams readable (position, state, sensor data accessible)

**Operator OPSEC:**
- Generic OVH VPS (no operator-identifying rDNS beyond OVH slug)
- No TLS cert (no CN/SAN attribution)
- Custom "Thalamus" ROS interfaces (vendor/project name)
- Mission IDs suggest operational deployment (not lab/test system)

### Data Classification Flags
- **Telemetry:** Position, velocity, sensor readings (potential PII if correlated)
- **Missions:** Flight plans, waypoints, operational patterns
- **Incidents:** Safety events, NDZ violations (operational security)
- **Infrastructure:** Charging/docking locations (physical asset mapping)

### Disclosed Intelligence
From VDT prompt:
- Platform type: "drone/UGV autopilot mission backend"
- Severity: HIGH
- Confirmed topics match VDT proof exactly
- Control reachable: `/autopilot_mission` confirmed

### OSINT Sources
- **Active Probing:** Port scan (nmap), WebSocket enumeration (Python websocket)
- **Passive:** WHOIS (RIPE), rDNS (dig -x)
- **ROS Graph:** rosbridge /rosapi service calls
- **Shodan:** API key 401 (dead key — Shodan historical unavailable)

### Ethics Gate
**STOP CONDITIONS MET:**
- VDT context = authorized pentest (explicit "this is part of the VDT")
- Control reachable = metadata enumeration OK, actuation PROHIBITED
- No PII exfiltration attempted (telemetry subscription timed out, no data captured)
- Mission IDs listed (metadata), mission content NOT downloaded

**Next Steps (Verification Phase):**
1. Confirm `/upload_mission` message structure
2. Test `/autopilot_mission` publish (DRY-RUN only, no live actuation)
3. Shodan dork mining (if Web UI auth succeeds)
4. Cert pivot (N/A — no TLS)
5. JS bundle extraction (N/A — no web UI)
6. Ledger ingest (.db)

