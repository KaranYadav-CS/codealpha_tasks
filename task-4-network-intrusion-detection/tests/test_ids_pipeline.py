#!/usr/bin/env python3
"""
Automated Unit & Integration Test Suite for NIDS Pipeline
CodeAlpha Cyber Security Internship - Task 4: Network Intrusion Detection System

Validates:
1. PCAP generation produces valid packets.
2. Suricata configuration and custom rules pass syntax checks (-T).
3. Suricata executes offline against the synthetic PCAP (-r).
4. EVE JSON output is generated and contains all 7 expected rule SIDs.
5. Eve parser handles missing/empty logs without unhandled exceptions.
6. Dashboard server endpoints (/api/status, /api/alerts, /api/export).
"""

import os
import sys
import unittest
import json
import subprocess
import tempfile
import urllib.request
import threading
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))
sys.path.insert(0, os.path.join(BASE_DIR, "dashboard"))

from generate_lab_pcap import generate_pcap
from parse_eve import load_eve_events, extract_alert_record, summarize_alerts
from run_offline_analysis import find_suricata_executable, run_pipeline
import server

class TestNIDSPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suricata_bin = find_suricata_executable()
        cls.data_dir = os.path.join(BASE_DIR, "data")
        cls.logs_dir = os.path.join(BASE_DIR, "logs")
        cls.config_path = os.path.join(BASE_DIR, "config", "suricata.yaml")
        cls.pcap_path = os.path.join(cls.data_dir, "lab_traffic.pcap")
        cls.eve_path = os.path.join(cls.logs_dir, "eve.json")

    def test_01_suricata_executable_discovered(self):
        """Verifies that the real Suricata binary is detected on the host."""
        self.assertIsNotNone(self.suricata_bin, "Suricata binary must be present.")
        self.assertTrue(os.path.isfile(self.suricata_bin), f"Suricata not found at {self.suricata_bin}")

        res = subprocess.run([self.suricata_bin, "-V"], cwd=os.path.dirname(self.suricata_bin), capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, "suricata -V must return exit code 0.")
        self.assertIn("Suricata version", res.stdout, "Version string must identify Suricata.")

    def test_02_pcap_generation(self):
        """Verifies that generate_lab_pcap creates a valid, non-empty PCAP."""
        temp_pcap = os.path.join(tempfile.gettempdir(), "test_generated_lab.pcap")
        if os.path.exists(temp_pcap):
            os.remove(temp_pcap)

        out = generate_pcap(temp_pcap)
        self.assertTrue(os.path.exists(out), "Generated PCAP file must exist.")
        self.assertGreater(os.path.getsize(out), 1000, "PCAP file must be greater than 1KB.")
        os.remove(temp_pcap)

    def test_03_suricata_configuration_validation(self):
        """Verifies that Suricata validates the configuration and loads all 7 rules (-T)."""
        cmd = [self.suricata_bin, "-T", "-c", self.config_path, "-l", self.logs_dir]
        proc = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"Config test failed with error: {proc.stderr}")
        self.assertIn("7 rules successfully loaded", proc.stdout)

    def test_04_offline_analysis_and_rule_triggers(self):
        """Executes full offline detection and verifies SIDs 1000001 - 1000007."""
        success = run_pipeline(
            suricata_bin=self.suricata_bin,
            pcap_path=self.pcap_path,
            config_path=self.config_path,
            logs_dir=self.logs_dir,
            regenerate_pcap=False
        )
        self.assertTrue(success, "All expected detection rules must trigger.")

        # Inspect eve.json
        self.assertTrue(os.path.exists(self.eve_path), "eve.json must exist after analysis.")
        raw_events = load_eve_events(self.eve_path, event_filter="alert")
        alerts = [extract_alert_record(e) for e in raw_events]
        summary = summarize_alerts(alerts)

        self.assertGreaterEqual(summary["total_alerts"], 7, "At least 7 alert events must be recorded.")
        expected_sids = {1000001, 1000002, 1000003, 1000004, 1000005, 1000006, 1000007}
        actual_sids = set(summary["unique_sids"])
        self.assertTrue(expected_sids.issubset(actual_sids), f"Missing SIDs: {expected_sids - actual_sids}")

    def test_05_eve_parser_missing_and_empty_log_handling(self):
        """Verifies eve parser gracefully handles non-existent or empty log files."""
        # Non-existent file
        non_existent = os.path.join(tempfile.gettempdir(), "non_existent_eve.json")
        events = load_eve_events(non_existent)
        self.assertEqual(events, [], "Non-existent log must return empty list.")

        # Empty file
        empty_file = os.path.join(tempfile.gettempdir(), "empty_eve.json")
        with open(empty_file, "w") as f:
            f.write("")
        events_empty = load_eve_events(empty_file)
        self.assertEqual(events_empty, [], "Empty log must return empty list.")
        os.remove(empty_file)

    def test_06_dashboard_api_endpoints(self):
        """Verifies local dashboard HTTP server API endpoints (/api/status, /api/alerts, /api/export)."""
        test_port = 8899
        httpd = server.HTTPServer(("127.0.0.1", test_port), server.NIDSDashboardHandler)
        srv_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        srv_thread.start()
        time.sleep(0.5)

        try:
            # 1. /api/status
            with urllib.request.urlopen(f"http://127.0.0.1:{test_port}/api/status") as resp:
                self.assertEqual(resp.status, 200)
                status_data = json.loads(resp.read().decode())
                self.assertTrue(status_data["suricata_installed"])
                self.assertTrue(status_data["offline_pcap_supported"])

            # 2. /api/alerts
            with urllib.request.urlopen(f"http://127.0.0.1:{test_port}/api/alerts") as resp:
                self.assertEqual(resp.status, 200)
                alerts_data = json.loads(resp.read().decode())
                self.assertEqual(alerts_data["status"], "ok")
                self.assertGreaterEqual(alerts_data["total"], 7)

            # 3. /api/export?format=json
            with urllib.request.urlopen(f"http://127.0.0.1:{test_port}/api/export?format=json") as resp:
                self.assertEqual(resp.status, 200)
                export_data = json.loads(resp.read().decode())
                self.assertIn("summary", export_data)
                self.assertIn("alerts", export_data)

            # 4. /api/export?format=csv
            with urllib.request.urlopen(f"http://127.0.0.1:{test_port}/api/export?format=csv") as resp:
                self.assertEqual(resp.status, 200)
                csv_text = resp.read().decode()
                self.assertIn("signature", csv_text)
                self.assertIn("1000001", csv_text)

        finally:
            httpd.shutdown()
            httpd.server_close()

if __name__ == "__main__":
    unittest.main()
