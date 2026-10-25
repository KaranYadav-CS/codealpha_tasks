#!/usr/bin/env python3
"""
Lightweight Local NIDS Dashboard Server
CodeAlpha Cyber Security Internship - Task 4: Network Intrusion Detection System

Runs an HTTP server strictly bound to 127.0.0.1 (localhost).
Serves the SOC Alert Triage Dashboard and provides JSON REST API endpoints
backed by real Suricata EVE logs (eve.json).
"""

import os
import sys
import json
import csv
import io
import subprocess
import argparse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))

from parse_eve import load_eve_events, extract_alert_record, summarize_alerts, format_text_report
from run_offline_analysis import find_suricata_executable, run_pipeline

STATIC_DIR = os.path.join(BASE_DIR, "dashboard", "static")
EVE_LOG_PATH = os.path.join(BASE_DIR, "logs", "eve.json")

class NIDSDashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def log_message(self, format, *args):
        # Quiet standard output logs for cleaner CLI experience
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            self.handle_api_status()
        elif path == "/api/alerts":
            self.handle_api_alerts(parsed.query)
        elif path == "/api/export":
            self.handle_api_export(parsed.query)
        else:
            # Fall back to serving static dashboard files
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/run-analysis":
            self.handle_api_run_analysis()
        else:
            self.send_error(404, "Endpoint Not Found")

    def handle_api_status(self):
        suricata_exe = find_suricata_executable()
        version_str = "Unavailable"
        if suricata_exe:
            try:
                res = subprocess.run([suricata_exe, "-V"], cwd=os.path.dirname(suricata_exe), capture_output=True, text=True)
                version_str = res.stdout.strip()
            except Exception:
                pass

        data = {
            "suricata_installed": bool(suricata_exe),
            "suricata_path": suricata_exe or "Not Found",
            "suricata_version": version_str,
            "eve_log_exists": os.path.exists(EVE_LOG_PATH),
            "eve_log_size": os.path.getsize(EVE_LOG_PATH) if os.path.exists(EVE_LOG_PATH) else 0,
            "offline_pcap_supported": True,
            "live_capture_supported": False, # Requires Npcap driver
            "live_capture_reason": "Live capture requires Npcap kernel driver installation with administrative approval."
        }
        self.send_json_response(data)

    def handle_api_alerts(self, query_string):
        params = parse_qs(query_string)
        severity_filter = params.get("severity", [None])[0]
        proto_filter = params.get("proto", [None])[0]
        search_query = params.get("q", [None])[0]

        if not os.path.exists(EVE_LOG_PATH) or os.path.getsize(EVE_LOG_PATH) == 0:
            self.send_json_response({
                "status": "empty",
                "message": "No alert logs found. Run offline analysis to generate engine alerts.",
                "total": 0,
                "summary": {"total_alerts": 0, "by_severity": {}, "by_signature": {}, "by_proto": {}},
                "alerts": []
            })
            return

        raw_events = load_eve_events(EVE_LOG_PATH, event_filter="alert")
        alerts = [extract_alert_record(e) for e in raw_events]

        # Apply in-memory filtering
        if severity_filter and severity_filter.lower() != "all":
            alerts = [a for a in alerts if a["severity_label"].lower() == severity_filter.lower()]
        if proto_filter and proto_filter.lower() != "all":
            alerts = [a for a in alerts if a["proto"].lower() == proto_filter.lower()]
        if search_query:
            q = search_query.lower()
            alerts = [a for a in alerts if (
                q in a["signature"].lower() or
                q in a["src_ip"].lower() or
                q in a["dest_ip"].lower() or
                q in str(a["sid"]) or
                q in a["payload_snippet"].lower()
            )]

        summary = summarize_alerts(alerts)
        self.send_json_response({
            "status": "ok",
            "total": len(alerts),
            "summary": summary,
            "alerts": alerts
        })

    def handle_api_export(self, query_string):
        params = parse_qs(query_string)
        fmt = params.get("format", ["json"])[0].lower()

        raw_events = load_eve_events(EVE_LOG_PATH, event_filter="alert")
        alerts = [extract_alert_record(e) for e in raw_events]
        summary = summarize_alerts(alerts)

        if fmt == "csv":
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="suricata_alerts_report.csv"')
            self.end_headers()

            if alerts:
                out = io.StringIO()
                writer = csv.DictWriter(out, fieldnames=list(alerts[0].keys()))
                writer.writeheader()
                writer.writerows(alerts)
                self.wfile.write(out.getvalue().encode("utf-8"))
            else:
                self.wfile.write(b"No alerts available\n")

        elif fmt == "text":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="suricata_alerts_report.txt"')
            self.end_headers()
            report_text = format_text_report(summary, alerts)
            self.wfile.write(report_text.encode("utf-8"))

        else: # Default json
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="suricata_alerts_report.json"')
            self.end_headers()
            self.wfile.write(json.dumps({"summary": summary, "alerts": alerts}, indent=2).encode("utf-8"))

    def handle_api_run_analysis(self):
        try:
            success = run_pipeline(regenerate_pcap=True)
            self.send_json_response({
                "status": "success" if success else "failed",
                "message": "Analysis pipeline executed successfully." if success else "Pipeline execution failed."
            })
        except Exception as e:
            self.send_json_response({"status": "error", "message": str(e)}, status=500)

    def send_json_response(self, data, status=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1")
        self.end_headers()
        self.wfile.write(body)

def start_server(host="127.0.0.1", port=8080):
    server = HTTPServer((host, port), NIDSDashboardHandler)
    print("=" * 70)
    print("SURICATA NIDS LOCAL DASHBOARD SERVER")
    print(f"Bound strictly to: http://{host}:{port}")
    print(f"Serving UI from:   {STATIC_DIR}")
    print(f"EVE Data Source:   {EVE_LOG_PATH}")
    print("=" * 70)
    print(f"[+] Open http://{host}:{port} in your browser to view alerts.")
    print("[*] Press Ctrl+C to stop the dashboard server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Dashboard server stopped.")
        server.server_close()

def main():
    parser = argparse.ArgumentParser(description="Start local Suricata NIDS alert dashboard server.")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default 127.0.0.1 for local security)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default 8080)")
    args = parser.parse_args()
    start_server(args.host, args.port)

if __name__ == "__main__":
    main()
