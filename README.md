# CodeAlpha Cyber Security Internship (`codealpha_tasks`)

**Intern:** Karan Yadav  
**Organization:** CodeAlpha  
**Track:** Cyber Security Internship  
**Batch:** October Batch  
**Repository:** `codealpha_tasks`

---

## 1. Repository & Internship Overview

This repository contains the completed, production-quality cyber security practical projects developed during the **CodeAlpha Cyber Security Internship**. Each project is housed in its own self-contained folder with full source code, test suites, reproducible environments, and extensive documentation:

* **[Task 2: Phishing Awareness Training Platform](task-2-phishing-awareness/README.md)** — An accessible, interactive cybersecurity education web application with real-world threat inspection, an evaluated 10-question quiz, dynamic checklist, and remediation runbooks.
* **[Task 4: Network Intrusion Detection System](task-4-network-intrusion-detection/README.md)** — An enterprise-grade NIDS implementation utilizing the genuine **Suricata 7.0.10 RELEASE** engine, custom Snort/Suricata detection rules, deterministic Scapy synthetic packet generation, automated EVE telemetry parsing, and a local SOC analyst triage dashboard.

---

## 2. Repository Layout

```text
codealpha_tasks/
├── README.md                               # Repository portfolio index (this file)
├── SUBMISSION_CHECKLIST.md                 # Batch submission status and verification checklist
├── .gitignore                              # Clean Git exclusion rules for Python & caches
├── task-2-phishing-awareness/              # Task 2: Phishing Awareness Training Platform
│   ├── index.html                          # Interactive educational web application
│   ├── css/                                # Responsive stylesheets & themes
│   ├── js/                                 # Interactive quiz engine, scenarios, & app logic
│   ├── assets/                             # SVG icons and visual assets
│   ├── tests/                              # Automated CDP headless browser test suite
│   ├── README.md                           # Comprehensive Task 2 documentation
│   ├── references.md                       # Official CISA, FTC, and NIST references
│   └── demo-script.md                      # Video demonstration walkthrough script
└── task-4-network-intrusion-detection/     # Task 4: Network Intrusion Detection System
    ├── config/                             # Suricata 7 configuration and classifications
    ├── rules/                              # Production Suricata detection rules (local.rules)
    ├── scripts/                            # Synthetic PCAP generation & offline analysis pipeline
    ├── dashboard/                          # Local SOC alert triage web server & console
    ├── data/                               # Synthetic PCAP test captures (RFC 5737 compliant)
    ├── logs/                               # Real Suricata output logs (eve.json, fast.log)
    ├── docs/                               # SOC response playbook and live monitoring guides
    ├── evidence/                           # Verified engine execution logs and sample data
    ├── tests/                              # End-to-end Python integration test suite
    ├── requirements.txt                    # Project dependencies (scapy, pefile, olefile)
    └── README.md                           # Comprehensive Task 4 documentation
```

---

## 3. Technology Stack

| Domain | Technologies Used |
|:---|:---|
| **Web & UI** | HTML5, CSS3 (Modern Flexbox/Grid, Dark/Light Themes), Vanilla JavaScript (ES6+), Local Storage API |
| **Cybersecurity Tools** | Suricata 7.0.10 RELEASE (Deep Packet Inspection), Scapy 2.6.1 (Packet crafting) |
| **Scripting & Backend** | Python 3.14 (HTTP servers, CDP test automation, EVE JSON stream parsing) |
| **Standards & Protocols** | RFC 5737 (Test Address Ranges), Suricata EVE JSON Format, WCAG 2.1 AA Accessibility |

---

## 4. Projects Summary & Run Instructions

### [Task 2: Phishing Awareness Training Platform](task-2-phishing-awareness/README.md)
* **Location:** [`task-2-phishing-awareness/`](task-2-phishing-awareness/)
* **Features:**
  * **Educational Lessons:** 6 core cybersecurity modules (phishing fundamentals, attack vectors, warning signs, social engineering, technical verification, incident response).
  * **Threat Inspector:** Interactive inspection of suspicious emails, SMS smishing, weaponized attachments, and malicious QR codes (quishing) with clickable red flag hotspots.
  * **Interactive Quiz:** 10 questions with immediate rationales for right/wrong answers, dynamic percentage scoring, skill badge award, and state reset.
  * **Safety Checklist:** Dynamic pre-interaction checklist with real-time risk level verdict calculation.
  * **Accessibility:** Full keyboard navigation, semantic markup, high-contrast dark/light modes, reduced-motion compliance.
* **Run Locally:**
  ```bash
  cd task-2-phishing-awareness
  python -m http.server 8000
  # Browse to http://127.0.0.1:8000
  ```
* **Run Tests:**
  ```bash
  python task-2-phishing-awareness/tests/test_browser.py
  # Verified: 10/10 test suites pass via Chrome/Edge CDP
  ```

---

### [Task 4: Network Intrusion Detection System](task-4-network-intrusion-detection/README.md)
* **Location:** [`task-4-network-intrusion-detection/`](task-4-network-intrusion-detection/)
* **Features:**
  * **Real Suricata Engine:** Executes official `suricata.exe` 7.0.10 without simulated shortcuts.
  * **7 Detection Signatures:** Covers telemetry markers (SID 1000001), scanner User-Agents (1000002), TCP SYN sweeps (1000003), TCP XMAS scans (1000004), TCP NULL scans (1000005), canary DNS queries (1000006), and web shell RCE parameters (1000007).
  * **Safe Synthetic PCAP:** 40 synthetic packets generated via Scapy using RFC 5737 test addresses (`192.0.2.0/24`, `198.51.100.0/24`).
  * **Automated Offline Pipeline:** Single command validates configuration (`-T`), replays PCAP (`-r`), and parses `eve.json` alerts.
  * **Local SOC Web Dashboard:** Binds strictly to `127.0.0.1:8080` with alert metrics, live search, severity filters, raw EVE JSON modal inspector, and CSV/JSON export.
  * **Response Playbook:** Complete 5-phase incident containment procedures in [`docs/response_playbook.md`](task-4-network-intrusion-detection/docs/response_playbook.md).
* **Run Locally:**
  ```bash
  # 1. Install dependencies
  pip install -r task-4-network-intrusion-detection/requirements.txt

  # 2. Run automated offline detection pipeline
  python task-4-network-intrusion-detection/scripts/run_offline_analysis.py

  # 3. Launch local SOC Alert Dashboard
  python task-4-network-intrusion-detection/dashboard/server.py
  # Browse to http://127.0.0.1:8080
  ```
* **Run Tests:**
  ```bash
  python task-4-network-intrusion-detection/tests/test_ids_pipeline.py
  # Verified: 6/6 integration tests pass cleanly
  ```

---

## 5. Verified Test Outcomes

| Project | Test Suite | Scope | Result | Status |
|:---|:---|:---|:---:|:---:|
| **Task 2** | `tests/test_browser.py` | 10 browser integration suites (DOM, links, quiz, inspector, mobile viewport) | 10 / 10 Suites Passed | Verified Live |
| **Task 4** | `tests/test_ids_pipeline.py` | 6 integration tests (Suricata engine, PCAP, syntax check, 7 SIDs, EVE parser, Dashboard API) | 6 / 6 Tests Passed | Verified Live |

---

## 6. Environmental Limitations

1. **Live NIC Packet Capture (Task 4):**
   - The current Windows 11 host environment does not have the Npcap kernel-mode driver installed.
   - Offline PCAP deep-packet inspection is **100% functional** and tested with native Suricata 7.0.10.
   - For live physical interface monitoring, see [`docs/live_monitoring.md`](task-4-network-intrusion-detection/docs/live_monitoring.md) for Npcap setup instructions.

---

## 7. Security & Authorized-Use Policy

- **Harmless Demonstration:** All network traffic generation is strictly synthetic, harmless, and confined to RFC 5737 documentation subnets (`192.0.2.0/24`, `198.51.100.0/24`). No packets are transmitted to external networks, public IP addresses, or unauthorized hosts.
- **No Malicious Payloads:** The phishing training interface contains purely educational mockups utilizing RFC 2606 reserved domains (`.invalid`, `.example`). No credential harvesting mechanisms or malicious delivery payloads exist.
- **Localhost Binding:** Local testing servers and dashboards are bound strictly to `127.0.0.1` and are never exposed to external networks.
