#!/usr/bin/env python3
"""
Automated Offline Intrusion Detection Pipeline
CodeAlpha Cyber Security Internship - Task 4: Network Intrusion Detection System

Orchestrates the complete offline Suricata detection workflow:
1. Locates the real Suricata engine executable.
2. Generates the reproducible synthetic PCAP (if missing or refreshed).
3. Validates configuration and rule syntax (-T).
4. Executes Suricata against the synthetic PCAP (-r).
5. Parses generated logs (eve.json, fast.log).
6. Verifies that all expected lab detection rules triggered.
7. Generates a structured execution and audit report.
"""

import os
import sys
import shutil
import subprocess
import argparse
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Ensure import of local scripts
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))

from generate_lab_pcap import generate_pcap
from parse_eve import load_eve_events, extract_alert_record, summarize_alerts, format_text_report

DEFAULT_CONFIG_PATH = os.path.join(BASE_DIR, "config", "suricata.yaml")
DEFAULT_PCAP_PATH = os.path.join(BASE_DIR, "data", "lab_traffic.pcap")
DEFAULT_LOGS_DIR = os.path.join(BASE_DIR, "logs")

EXPECTED_RULE_SIDS = {
    1000001: "Unique Telemetry Lab Marker in HTTP GET",
    1000002: "Suspicious Reconnaissance User-Agent Header",
    1000003: "Reconnaissance TCP SYN Port Sweep Probe",
    1000004: "Suspicious TCP XMAS Tree Scan Probe",
    1000005: "Suspicious TCP NULL Scan Probe",
    1000006: "Suspicious DNS Query to Canary Domain",
    1000007: "Potential Web Shell Command Execution Detected"
}

def find_suricata_executable(custom_bin=None):
    """Discovers the Suricata engine executable across standard paths."""
    candidates = []
    if custom_bin:
        candidates.append(custom_bin)

    # Check local app data extracted path
    local_app_suricata = os.path.expandvars(r"%LOCALAPPDATA%\Suricata\suricata.exe")
    candidates.append(local_app_suricata)

    # Check standard Program Files installation
    candidates.append(r"C:\Program Files\Suricata\suricata.exe")
    candidates.append(r"C:\Program Files (x86)\Suricata\suricata.exe")
    candidates.append(r"C:\Suricata\suricata.exe")

    # Check PATH
    which_path = shutil.which("suricata.exe") or shutil.which("suricata")
    if which_path:
        candidates.append(which_path)

    for p in candidates:
        if p and os.path.isfile(p):
            return os.path.abspath(p)
    return None

def clean_log_directory(logs_dir):
    """Cleans existing log files to ensure test determinism."""
    os.makedirs(logs_dir, exist_ok=True)
    for fname in ["eve.json", "fast.log", "suricata.log"]:
        fpath = os.path.join(logs_dir, fname)
        if os.path.exists(fpath):
            try:
                os.remove(fpath)
            except OSError:
                pass

def run_pipeline(suricata_bin=None, pcap_path=DEFAULT_PCAP_PATH, config_path=DEFAULT_CONFIG_PATH, logs_dir=DEFAULT_LOGS_DIR, regenerate_pcap=False):
    print("=" * 80)
    print("SURICATA OFFLINE INTRUSION DETECTION PIPELINE")
    print("CodeAlpha Cyber Security Internship - Task 4")
    print("=" * 80)

    # 1. Locate Suricata
    exe_path = find_suricata_executable(suricata_bin)
    if not exe_path:
        print("[!] ERROR: Suricata executable not found.")
        print("    Please install Suricata or supply the binary path via --suricata-bin.")
        print("    Standard locations checked:")
        print(f"      - {os.path.expandvars(r'%LOCALAPPDATA%\\Suricata\\suricata.exe')}")
        print("      - C:\\Program Files\\Suricata\\suricata.exe")
        print("      - System PATH")
        return False

    print(f"[+] Found Suricata engine: {exe_path}")

    # 2. Query Version
    try:
        ver_res = subprocess.run([exe_path, "-V"], cwd=os.path.dirname(exe_path), capture_output=True, text=True)
        version_line = ver_res.stdout.strip() or "Suricata (Unknown Version)"
        print(f"[+] Engine Identification: {version_line}")
    except Exception as e:
        print(f"[!] Warning: Could not query version: {e}")

    # 3. Ensure PCAP exists
    if regenerate_pcap or not os.path.exists(pcap_path):
        print("\n[*] Generating synthetic lab PCAP traffic...")
        generate_pcap(pcap_path)
    else:
        print(f"\n[+] Using existing lab PCAP: {pcap_path} ({os.path.getsize(pcap_path)} bytes)")

    # 4. Clean Log Directory
    clean_log_directory(logs_dir)

    # 5. Validate Configuration & Rules (-T)
    print("\n[*] Validating configuration and detection rules (-T)...")
    test_cmd = [exe_path, "-T", "-c", config_path, "-l", logs_dir]
    test_proc = subprocess.run(test_cmd, cwd=BASE_DIR, capture_output=True, text=True)
    if test_proc.returncode != 0:
        print("[!] Configuration validation FAILED:")
        print(test_proc.stderr)
        return False
    print("[+] Configuration and rules syntax validated successfully.")

    # 6. Run Offline Analysis (-r)
    print(f"\n[*] Executing Suricata against PCAP (-r {os.path.basename(pcap_path)})...")
    run_cmd = [exe_path, "-c", config_path, "-r", pcap_path, "-l", logs_dir, "-k", "none"]
    start_time = time.time()
    run_proc = subprocess.run(run_cmd, cwd=BASE_DIR, capture_output=True, text=True)
    elapsed = time.time() - start_time

    if run_proc.returncode != 0:
        print(f"[!] Suricata execution failed with exit code {run_proc.returncode}:")
        print(run_proc.stderr)
        return False
    print(f"[+] PCAP analysis completed in {elapsed:.2f} seconds (Exit Code: 0).")

    # 7. Parse Generated Alerts
    eve_file = os.path.join(logs_dir, "eve.json")
    if not os.path.exists(eve_file):
        print(f"[!] Error: Expected EVE log file missing at {eve_file}")
        return False

    raw_events = load_eve_events(eve_file, event_filter="alert")
    alerts = [extract_alert_record(e) for e in raw_events]
    summary = summarize_alerts(alerts)

    print(f"[+] Extracted {len(alerts)} total alerts from {eve_file}.")

    # 8. Verify Expected Detection Rules
    print("\n" + "=" * 80)
    print("DETECTION RULE VERIFICATION MATRIX")
    print("=" * 80)
    print(f"{'SID':10} {'STATUS':10} {'RULE NAME / DESCRIPTION'}")
    print("-" * 80)

    all_passed = True
    triggered_sids = set(summary["unique_sids"])

    for sid, desc in EXPECTED_RULE_SIDS.items():
        if sid in triggered_sids:
            count = sum(1 for a in alerts if a["sid"] == sid)
            print(f"{sid:<10} {'TRIGGERED':10} ({count}x) {desc}")
        else:
            print(f"{sid:<10} {'MISSED':10} {desc}")
            all_passed = False

    print("=" * 80)

    # 9. Output Concise Report
    print("\n" + format_text_report(summary, alerts))

    if all_passed:
        print("\n[SUCCESS] ALL 7 EXPECTED DETECTION RULES TRIGGERED AND VERIFIED SUCCESSFULLY!")
    else:
        print("\n[!] WARNING: One or more expected rules did not trigger.")

    return all_passed

def main():
    parser = argparse.ArgumentParser(description="Run reproducible offline Suricata intrusion detection analysis.")
    parser.add_argument("--suricata-bin", help="Path to custom suricata executable")
    parser.add_argument("--pcap", default=DEFAULT_PCAP_PATH, help="Input PCAP file path")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to suricata.yaml")
    parser.add_argument("--logs", default=DEFAULT_LOGS_DIR, help="Output directory for logs")
    parser.add_argument("--regen-pcap", action="store_true", help="Force regeneration of synthetic PCAP")
    args = parser.parse_args()

    success = run_pipeline(
        suricata_bin=args.suricata_bin,
        pcap_path=args.pcap,
        config_path=args.config,
        logs_dir=args.logs,
        regenerate_pcap=args.regen_pcap
    )
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
