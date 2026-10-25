# Task 4: Network Intrusion Detection System (NIDS)

**CodeAlpha Cyber Security Internship**  
**Author:** Karan Yadav  
**Project Workspace:** `codealpha_tasks/task-4-network-intrusion-detection/`

---

## 1. Project Overview & Objectives

This project implements an enterprise-grade, reproducible **Network Intrusion Detection System (NIDS)** environment utilizing the **official Suricata 7.0.10 RELEASE** engine on Windows 11. 

Rather than relying on mock scripts or Python-only simulations, this implementation exercises the **genuine Suricata deep-packet inspection engine** in an offline PCAP analysis workflow, generates customized RFC-compliant synthetic network traffic, applies tailored detection rules across Layer 4 (TCP/UDP) and Layer 7 (HTTP/DNS), parses structured `eve.json` telemetry, and provides a modern SOC analyst web dashboard for interactive alert triage.

### Core Objectives
1. **Real Detection Engine:** Verify and execute the native `suricata.exe` (v7.0.10) engine without simulating detection logic.
2. **Custom Signature Engineering:** Develop 7 production-grade Suricata rules detecting telemetry markers, port sweeps, TCP flag anomalies (XMAS, NULL), DNS canaries, and remote command execution.
3. **Safe Synthetic Lab Traffic:** Use Scapy to construct safe, non-destructive test PCAP files using RFC 5737 documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`).
4. **Automated Offline Pipeline:** Provide single-command orchestration (`run_offline_analysis.py`) that checks engine health, validates syntax with `-T`, executes against PCAP with `-r`, and verifies rule triggering.
5. **SOC Analyst Web Dashboard:** A lightweight local web application bound strictly to `127.0.0.1:8080` featuring live metric counters, severity filtering, raw EVE JSON modal inspector, and CSV export.
6. **Incident Response & Live Playbooks:** Complete operational documentation for SOC incident handling (`docs/response_playbook.md`) and live physical network interface capture (`docs/live_monitoring.md`).

---

## 2. Directory Structure

```text
task-4-network-intrusion-detection/
├── README.md                      # Comprehensive project guide and reference
├── requirements.txt               # Python package dependencies (scapy, pefile, olefile)
├── config/
│   ├── suricata.yaml              # Suricata 7 configuration tuned for offline analysis
│   ├── classification.config      # Attack classification hierarchy and priority mapping
│   └── reference.config           # Security advisory and CVE URL reference definitions
├── rules/
│   └── local.rules                # 7 production-ready custom Suricata detection rules
├── scripts/
│   ├── generate_lab_pcap.py       # Scapy synthetic PCAP generator (40 packets)
│   ├── run_offline_analysis.py    # Automated end-to-end verification and analysis pipeline
│   └── parse_eve.py               # EVE JSON parser supporting CLI summary, JSON, and CSV
├── dashboard/
│   ├── server.py                  # Local Python HTTP server (127.0.0.1:8080) with REST API
│   └── static/
│       ├── index.html             # SOC analyst web dashboard interface
│       ├── styles.css             # Cyber defense responsive dark UI styling
│       └── app.js                 # Frontend telemetry polling, filtering, and export logic
├── data/
│   └── lab_traffic.pcap           # Generated synthetic test capture (3,657 bytes)
├── logs/
│   ├── eve.json                   # Real Suricata Extensible Event Format (EVE) output
│   ├── fast.log                   # Real Suricata fast alert summary log
│   └── suricata.log               # Engine operational status and diagnostic log
├── tests/
│   └── test_ids_pipeline.py       # Automated 6-test suite for engine, rules, parser, API
├── docs/
│   ├── response_playbook.md       # 5-phase SOC incident triage and containment playbook
│   └── live_monitoring.md         # Operational guide for live physical interface capture
└── evidence/
    ├── README.md                  # Verification summary and execution metadata
    ├── test_execution_log.txt     # Terminal execution log confirming 7/7 rules triggered
    ├── sample_fast.log            # Sample fast.log output for quick review
    └── sample_eve.json            # Sample eve.json output
```

---

## 3. Technology Stack & Prerequisites

- **Host Operating System:** Windows 11 Enterprise / Pro (x64)
- **IDS Engine:** Suricata 7.0.10 RELEASE (installed in `%LOCALAPPDATA%\Suricata\suricata.exe`)
- **Python Runtime:** Python 3.14+ (64-bit)
- **Python Dependencies:**
  - `scapy>=2.5.0` (Packet crafting and PCAP generation)
  - `pefile>=2023.2.7` & `olefile>=0.46` (MSI extraction and PE linking)
- **Web Dashboard:** Vanilla HTML5, CSS3, modern ES6 JavaScript (No external frameworks, strictly bound to `127.0.0.1`).

---

## 4. Custom Suricata Detection Rules

All rules reside in [`rules/local.rules`](rules/local.rules) and have been tested against Suricata 7.0.10.

| SID | Priority | Category / Classtype | Signature Message | Detection Mechanism |
|:---:|:---:|:---|:---|:---|
| **1000001** | 3 (Low) | `misc-activity` | `CODEALPHA LAB - Unique Telemetry Lab Marker Detected` | Matches unique HTTP payload token `X-CodeAlpha-Telemetry: VerificationMarker-2026` via `http.header`. |
| **1000002** | 2 (Medium) | `attempted-recon` | `CODEALPHA LAB - Suspicious Reconnaissance User-Agent Header` | Inspects HTTP `User-Agent` for automated scanner strings (`sqlmap`, `nikto`, `masscan`, `nmap`). |
| **1000003** | 2 (Medium) | `attempted-recon` | `CODEALPHA LAB - Reconnaissance TCP SYN Port Sweep Probe` | Detects bare TCP SYN probes directed against sensitive management ports (21, 22, 23, 25, 445). |
| **1000004** | 2 (Medium) | `attempted-recon` | `CODEALPHA LAB - Suspicious TCP XMAS Tree Scan Probe` | Detects abnormal TCP flag combinations (`flags:FPU,12;` FIN, PSH, and URG simultaneously set). |
| **1000005** | 2 (Medium) | `attempted-recon` | `CODEALPHA LAB - Suspicious TCP NULL Scan Probe` | Detects packets with zero TCP flags (`flags:0,12;`), a classic reconnaissance technique to bypass stateless packet filters. |
| **1000006** | 2 (Medium) | `bad-unknown` | `CODEALPHA LAB - Suspicious DNS Query to Canary Domain` | Inspects UDP DNS queries for simulated C2/canary domain `bad-recon-canary.example.internal`. |
| **1000007** | 1 (High) | `attempted-admin` | `CODEALPHA LAB - Potential Web Shell Command Execution Detected` | Inspects HTTP URI query strings for remote code execution patterns (e.g. `cmd=whoami`, `exec=cat+/etc/passwd`). |

### Detection Limitations & Nuance
- **Synthetic vs. Real Scans:** Signature 1000003 flags individual SYN probes toward reserved administration ports. In high-throughput production environments, a `threshold` or `flowint` rule is recommended to prevent alert exhaustion from isolated connection requests.
- **Payload Evasion:** L7 rules matching raw strings can be bypassed by URL-encoding (`%77%68%6F%61%6D%69`), compression, or end-to-end TLS encryption unless Suricata TLS inspection or reverse-proxy termination is deployed.

---

## 5. Synthetic Lab Traffic Generation

The synthetic PCAP (`scripts/generate_lab_pcap.py`) creates 40 deterministic, non-destructive packets:
- **Baseline Benign Traffic:** Valid HTTP GET requests for static assets (`/index.html`, `/assets/style.css`) to verify that the ruleset produces zero false positives on normal traffic.
- **Harmless Telemetry Markers:** Synthetic requests containing the verification marker.
- **Reconnaissance Probes:** Standalone TCP SYN, XMAS (`FPU`), and NULL flag combinations targeting documentation addresses (`192.0.2.100` -> `198.51.100.50`).
- **Canary DNS Queries:** Standard DNS query packet requesting resolution for `bad-recon-canary.example.internal`.
- **Simulated Web Shell Parameter:** HTTP GET to `/admin/shell.php?cmd=whoami`.

All IP addresses adhere strictly to **RFC 5737** (`192.0.2.0/24` TEST-NET-1 and `198.51.100.0/24` TEST-NET-2). No packets are sent across real network interfaces or to external hosts.

---

## 6. How to Run & Verify the Project

### Step 1: Install Python Dependencies
```bash
pip install -r task-4-network-intrusion-detection/requirements.txt
```

### Step 2: Run the Automated Offline Analysis Pipeline
Execute the complete end-to-end orchestration script:
```bash
python task-4-network-intrusion-detection/scripts/run_offline_analysis.py
```
This script will:
1. Locate the native `suricata.exe` engine.
2. Validate the rules and configuration syntax (`suricata -c config/suricata.yaml -T`).
3. Re-generate the synthetic PCAP (`data/lab_traffic.pcap`).
4. Execute Suricata against the PCAP (`suricata -c config/suricata.yaml -r data/lab_traffic.pcap -l logs`).
5. Parse `logs/eve.json` and print the verification matrix and summary table.

### Step 3: Run the SOC Alert Dashboard
Launch the lightweight local web triage server:
```bash
python task-4-network-intrusion-detection/dashboard/server.py
```
Open your browser and navigate to:
```text
http://127.0.0.1:8080/
```

#### Dashboard Features:
- **System Metrics Bar:** Real-time counters for High, Medium, and Low severity alerts, unique signatures, and engine status.
- **Interactive Severity Filters:** Instantly toggle all alerts, High, Medium, or Low alerts.
- **Instant Search:** Full-text filtering across signature text, source IP, destination IP, and ports.
- **Raw EVE Inspector Modal:** Click on any alert event to inspect the complete, raw JSON telemetry record from Suricata.
- **One-Click Re-run:** Trigger pipeline re-analysis directly from the web interface.
- **Export Capabilities:** Download filtered alerts to CSV or JSON for incident escalation.

---

## 7. Command-Line EVE Log Parsing

You can also parse Suricata's JSON output directly in the console:

```bash
# Print formatted CLI summary and triage table
python task-4-network-intrusion-detection/scripts/parse_eve.py task-4-network-intrusion-detection/logs/eve.json

# Filter by severity
python task-4-network-intrusion-detection/scripts/parse_eve.py task-4-network-intrusion-detection/logs/eve.json --severity high

# Export parsed alerts to CSV
python task-4-network-intrusion-detection/scripts/parse_eve.py task-4-network-intrusion-detection/logs/eve.json --format csv -o alerts.csv

# Export parsed alerts to structured JSON
python task-4-network-intrusion-detection/scripts/parse_eve.py task-4-network-intrusion-detection/logs/eve.json --format json -o alerts.json
```

---

## 8. Live Packet Capture & Operational Status

- **Current Host Status:** Windows 11 without administrative kernel drivers.
- **Offline Mode:** 100% operational with native Suricata 7.0.10.
- **Live Mode Requirements:** Running Suricata live on a physical Windows NIC requires the **Npcap kernel-mode driver** (`npcap-1.80.exe` installed with WinPcap-compatible mode enabled).
- Consult [`docs/live_monitoring.md`](docs/live_monitoring.md) for step-by-step instructions on device enumeration (`suricata --pcap --list-submodes`), interface binding, and background service execution.

---

## 9. Incident Response Playbook Summary

When Suricata detects an anomaly, SOC analysts follow the 5-phase procedure detailed in [`docs/response_playbook.md`](docs/response_playbook.md):
1. **Identification & Triage:** Verify alert validity in `eve.json` and rule SID; distinguish true positives from network scanner noise.
2. **Scoping & Correlation:** Check source IP host records, firewall flow logs, and endpoint telemetry for concurrent activity.
3. **Containment:** Block offending IP addresses on perimeter firewalls, isolate compromised internal hosts, or revoke active session tokens.
4. **Eradication:** Terminate unauthorized processes, remove web shell backdoors, and close exposed listening ports.
5. **Recovery & Lessons Learned:** Re-image affected systems, restore from verified backups, and refine detection rules to suppress future false positives.

---

## 10. Automated Test Suite

A complete unit and integration test suite is provided in [`tests/test_ids_pipeline.py`](tests/test_ids_pipeline.py):

```bash
python task-4-network-intrusion-detection/tests/test_ids_pipeline.py
```

### Verified Test Cases:
1. `test_01_environment_and_suricata_executable`: Confirms native `suricata.exe` is present and returns version `7.0.10`.
2. `test_02_pcap_generation`: Confirms Scapy generates valid PCAP containing expected packet types.
3. `test_03_suricata_rule_syntax_validation`: Runs `suricata -T` to verify zero rule syntax errors.
4. `test_04_offline_analysis_and_rule_verification`: Runs `suricata -r` and verifies all 7 SIDs trigger.
5. `test_05_parse_eve_script`: Confirms JSON and CSV exports function accurately.
6. `test_06_dashboard_api_endpoints`: Verifies dashboard REST endpoints (`/api/status`, `/api/alerts`, `/api/export`) return HTTP 200 with valid JSON.
