#!/usr/bin/env python3
"""
EVE JSON Parser & Alert Triage Utility
CodeAlpha Cyber Security Internship - Task 4: Network Intrusion Detection System

Parses Suricata's Extensible Event Format (EVE JSON) logs.
Provides:
- Comprehensive alert summaries (by signature, severity, source/dest, protocol)
- Search and filtering capabilities
- Export to JSON, CSV, or formatted human-readable reports
- Graceful handling of empty or missing log files
"""

import os
import sys
import json
import csv
import argparse
from datetime import datetime

DEFAULT_EVE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "logs", "eve.json"
)

SEVERITY_LABELS = {
    1: "High",
    2: "Medium",
    3: "Low",
    4: "Informational"
}

def load_eve_events(filepath=DEFAULT_EVE_PATH, event_filter="alert"):
    """Loads events from an eve.json file line-by-line."""
    if not os.path.exists(filepath):
        return []

    events = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if event_filter is None or data.get("event_type") == event_filter:
                    events.append(data)
            except json.JSONDecodeError:
                continue
    return events

def extract_alert_record(event):
    """Normalizes an EVE alert event into a clean dictionary."""
    alert_info = event.get("alert", {})
    severity_num = alert_info.get("severity", 3)
    severity_label = SEVERITY_LABELS.get(severity_num, f"Level {severity_num}")

    return {
        "timestamp": event.get("timestamp", ""),
        "sid": alert_info.get("signature_id", 0),
        "rev": alert_info.get("rev", 1),
        "signature": alert_info.get("signature", "Unknown Signature"),
        "category": alert_info.get("category", "Generic Activity"),
        "severity": severity_num,
        "severity_label": severity_label,
        "action": alert_info.get("action", "allowed"),
        "src_ip": event.get("src_ip", "0.0.0.0"),
        "src_port": event.get("src_port", "-"),
        "dest_ip": event.get("dest_ip", "0.0.0.0"),
        "dest_port": event.get("dest_port", "-"),
        "proto": event.get("proto", "UNKNOWN").upper(),
        "payload_snippet": event.get("payload_printable", "")[:120] if event.get("payload_printable") else "",
        "pcap_cnt": event.get("pcap_cnt", 0),
        "flow_id": event.get("flow_id", 0)
    }

def summarize_alerts(alerts):
    """Generates structured statistics from extracted alert records."""
    summary = {
        "total_alerts": len(alerts),
        "by_severity": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0},
        "by_signature": {},
        "by_src_ip": {},
        "by_dest_ip": {},
        "by_proto": {},
        "unique_sids": set()
    }

    for a in alerts:
        sev = a["severity_label"]
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

        sig = f"[{a['sid']}] {a['signature']}"
        summary["by_signature"][sig] = summary["by_signature"].get(sig, 0) + 1

        src = a["src_ip"]
        summary["by_src_ip"][src] = summary["by_src_ip"].get(src, 0) + 1

        dst = a["dest_ip"]
        summary["by_dest_ip"][dst] = summary["by_dest_ip"].get(dst, 0) + 1

        proto = a["proto"]
        summary["by_proto"][proto] = summary["by_proto"].get(proto, 0) + 1

        summary["unique_sids"].add(a["sid"])

    summary["unique_sids"] = sorted(list(summary["unique_sids"]))
    return summary

def format_text_report(summary, alerts):
    """Builds a formatted text report for console or file output."""
    lines = []
    lines.append("=" * 80)
    lines.append("SURICATA INTRUSION DETECTION SYSTEM - EVE ALERT TRIAGE REPORT")
    lines.append("CodeAlpha Cyber Security Internship - Task 4")
    lines.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 80)
    lines.append(f"Total Alert Events: {summary['total_alerts']}")
    lines.append(f"Unique Signatures Triggered: {len(summary['by_signature'])}")
    lines.append("")

    lines.append("--- SEVERITY BREAKDOWN ---")
    for sev, count in summary["by_severity"].items():
        if count > 0:
            lines.append(f"  * {sev:15}: {count:3} alert(s)")
    lines.append("")

    lines.append("--- TOP SIGNATURES TRIGGERED ---")
    for sig, count in sorted(summary["by_signature"].items(), key=lambda x: x[1], reverse=True):
        lines.append(f"  * ({count}x) {sig}")
    lines.append("")

    lines.append("--- PROTOCOL DISTRIBUTION ---")
    for proto, count in summary["by_proto"].items():
        lines.append(f"  * {proto:8}: {count} event(s)")
    lines.append("")

    lines.append("--- RECENT ALERT EVENTS TABLE ---")
    lines.append(f"{'TIMESTAMP':24} {'SEV':6} {'PROTO':6} {'SOURCE IP:PORT':23} {'DEST IP:PORT':23} {'SIGNATURE'}")
    lines.append("-" * 115)

    for a in alerts[:50]: # Show up to 50 alerts
        src = f"{a['src_ip']}:{a['src_port']}"
        dst = f"{a['dest_ip']}:{a['dest_port']}"
        ts = a["timestamp"][:19].replace("T", " ")
        lines.append(f"{ts:24} {a['severity_label']:6} {a['proto']:6} {src:23} {dst:23} [{a['sid']}] {a['signature'][:35]}")

    lines.append("=" * 80)
    return "\n".join(lines)

def export_csv(alerts, output_file):
    """Exports alert records to CSV format."""
    if not alerts:
        return
    keys = list(alerts[0].keys())
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(alerts)

def main():
    parser = argparse.ArgumentParser(description="Parse and triage Suricata EVE JSON alert logs.")
    parser.add_argument("-f", "--file", default=DEFAULT_EVE_PATH, help="Path to eve.json")
    parser.add_argument("--json", action="store_true", help="Output summary in JSON format")
    parser.add_argument("--csv", help="Export alerts to CSV file path")
    parser.add_argument("--sid", type=int, help="Filter alerts by specific Signature ID")
    parser.add_argument("--severity", choices=["High", "Medium", "Low", "Informational"], help="Filter by severity label")
    args = parser.parse_args()

    raw_events = load_eve_events(args.file, event_filter="alert")
    alerts = [extract_alert_record(e) for e in raw_events]

    # Apply filters
    if args.sid:
        alerts = [a for a in alerts if a["sid"] == args.sid]
    if args.severity:
        alerts = [a for a in alerts if a["severity_label"].lower() == args.severity.lower()]

    summary = summarize_alerts(alerts)

    if args.csv:
        export_csv(alerts, args.csv)
        print(f"[+] Exported {len(alerts)} alerts to CSV: {args.csv}")

    if args.json:
        output_data = {
            "summary": summary,
            "alerts": alerts
        }
        print(json.dumps(output_data, indent=2))
    else:
        report = format_text_report(summary, alerts)
        print(report)

if __name__ == "__main__":
    main()
