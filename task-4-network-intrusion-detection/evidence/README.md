# Task 4: Detection & Execution Evidence

This directory contains verified execution logs, raw alert outputs, and diagnostic records confirming that **Suricata 7.0.10 RELEASE** was executed against synthetic network traffic and successfully applied all custom detection rules.

---

## 1. Environment & Engine Verification

- **Operating System:** Windows 11 Enterprise / Pro (64-bit AMD64)
- **Suricata Binary:** `C:\Users\Karan Yadan\AppData\Local\Suricata\suricata.exe`
- **Engine Version Output:**
  ```text
  Info: win32-service: Running as service: no
  This is Suricata version 7.0.10 RELEASE
  ```
- **Driver / Capture Status:**
  - **Offline PCAP Replay:** Fully functional using native 64-bit WinPcap/Npcap user-mode DLL libraries (`wpcap.dll`, `Packet.dll`).
  - **Live Adapter Capture:** Requires operator installation of the Npcap kernel-mode driver (`npcap-1.80.exe` in WinPcap-compatible mode). Documented in `docs/live_monitoring.md`.

---

## 2. Evidence Files Included

| File | Purpose | Description |
|------|---------|-------------|
| [`test_execution_log.txt`](test_execution_log.txt) | Complete CLI Pipeline Log | Full terminal output showing syntax check (`-T`), PCAP execution (`-r`), and rule matrix evaluation. |
| [`sample_fast.log`](sample_fast.log) | Suricata Fast Alert Log | One-line alert summaries generated natively by Suricata for all 7 triggered rules. |
| [`sample_eve.json`](sample_eve.json) | Extensible Event Format (EVE) | Complete structured JSON alert telemetry stream produced natively by Suricata. |

---

## 3. Triggered Alert Summary

The synthetic test PCAP (`data/lab_traffic.pcap`, 40 packets, 3,657 bytes) was passed to Suricata 7.0.10. All 7 detection rules fired as expected without producing false positives on baseline background traffic:

| SID | Priority / Severity | Classification | Signature Name | Protocols |
|:---:|:-------------------:|:---------------|:---------------|:---------:|
| **1000001** | Priority 3 (Low) | Misc activity | `CODEALPHA LAB - Unique Telemetry Lab Marker Detected` | TCP / HTTP (80) |
| **1000002** | Priority 2 (Medium) | Attempted Information Leak | `CODEALPHA LAB - Suspicious Reconnaissance User-Agent Header` | TCP / HTTP (80) |
| **1000003** | Priority 2 (Medium) | Attempted Information Leak | `CODEALPHA LAB - Reconnaissance TCP SYN Port Sweep Probe` | TCP (21, 22, 23, 25, 445) |
| **1000004** | Priority 2 (Medium) | Attempted Information Leak | `CODEALPHA LAB - Suspicious TCP XMAS Tree Scan Probe` | TCP (Flags: FPU) |
| **1000005** | Priority 2 (Medium) | Attempted Information Leak | `CODEALPHA LAB - Suspicious TCP NULL Scan Probe` | TCP (Flags: 0) |
| **1000006** | Priority 2 (Medium) | Potentially Bad Traffic | `CODEALPHA LAB - Suspicious DNS Query to Canary Domain` | UDP / DNS (53) |
| **1000007** | Priority 1 (High) | Attempted Administrator Privilege Gain | `CODEALPHA LAB - Potential Web Shell Command Execution Detected` | TCP / HTTP (80) |

---

## 4. How to Independently Reproduce Evidence

From the `task-4-network-intrusion-detection` directory, run:

```bash
# 1. Regenerate synthetic PCAP and run Suricata offline analysis
python scripts/run_offline_analysis.py

# 2. View human-readable terminal triage summary
python scripts/parse_eve.py logs/eve.json

# 3. Export structured summary to CSV or JSON
python scripts/parse_eve.py logs/eve.json --format csv -o logs/alerts_export.csv
python scripts/parse_eve.py logs/eve.json --format json -o logs/alerts_export.json

# 4. Run automated test suite
python tests/test_ids_pipeline.py
```
