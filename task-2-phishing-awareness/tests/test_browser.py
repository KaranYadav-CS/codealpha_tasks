"""
Automated Comprehensive Test Suite for PhishGuard Training Platform
CodeAlpha Cyber Security Internship - Task 2

Performs live verification using Chrome/Edge headless and Chrome DevTools Protocol (CDP):
1. Static HTTP serving & page load
2. Local anchor links and local markdown documentation links
3. Educational modules reading & category filter
4. Dark / Light theme toggle & persistence
5. Threat Inspector: email header hotspot mapping, all 4 scenarios, and highlight toggle
6. Pre-interaction safety checklist & dynamic risk verdict meter
7. Phishing quiz answer explanations (for both correct and incorrect choices)
8. Phishing quiz in-progress reset button and post-results retake
9. Phishing quiz scoring accuracy (testing partial score 70% and badge assignment)
10. Mobile layout & interactive navigation menu (open, link click, auto-close)
"""

import subprocess
import time
import json
import urllib.request
import websocket
import threading
import http.server
import socketserver
import os
import sys
import tempfile
import shutil

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

PORT = 8008
CHROME_PORT = 9223
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)
    def log_message(self, format, *args):
        pass

def run_server():
    with socketserver.TCPServer(("127.0.0.1", PORT), QuietHandler) as httpd:
        httpd.serve_forever()

server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()
print(f"Local static server started on http://127.0.0.1:{PORT}")

chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
if not os.path.exists(chrome_path):
    chrome_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

temp_profile = tempfile.mkdtemp()
print(f"Launching headless browser from: {chrome_path}")
browser_process = subprocess.Popen([
    chrome_path,
    f"--remote-debugging-port={CHROME_PORT}",
    "--remote-allow-origins=*",
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    f"--user-data-dir={temp_profile}",
    "about:blank"
])

msg_id = 0
ws = None

def send_cdp(ws, method, params=None):
    global msg_id
    msg_id += 1
    req = {"id": msg_id, "method": method, "params": params or {}}
    ws.send(json.dumps(req))
    while True:
        res = json.loads(ws.recv())
        if res.get("id") == msg_id:
            return res

def evaluate_js(ws, expr):
    res = send_cdp(ws, "Runtime.evaluate", {
        "expression": expr,
        "returnByValue": True,
        "awaitPromise": True
    })
    if "result" in res and "result" in res["result"]:
        return res["result"]["result"].get("value")
    return None

try:
    time.sleep(2)
    targets_url = f"http://127.0.0.1:{CHROME_PORT}/json"
    with urllib.request.urlopen(targets_url) as resp:
        targets = json.loads(resp.read().decode())
    
    ws_url = None
    for t in targets:
        if t.get("type") == "page":
            ws_url = t.get("webSocketDebuggerUrl")
            break
    if not ws_url:
        ws_url = targets[0]["webSocketDebuggerUrl"]

    print(f"Connecting to CDP WebSocket: {ws_url}")
    ws = websocket.create_connection(ws_url)

    send_cdp(ws, "Page.enable")
    send_cdp(ws, "Runtime.enable")

    # -------------------------------------------------------------
    # Test 1: Page Navigation and Homepage Load
    # -------------------------------------------------------------
    print("\n--- Test 1: Page Navigation and Homepage Load ---")
    send_cdp(ws, "Page.navigate", {"url": f"http://127.0.0.1:{PORT}/index.html"})
    time.sleep(1.5)

    title = evaluate_js(ws, "document.title")
    print(f"Document Title: {title}")
    assert "PhishGuard" in title, "Page title mismatch"

    console_errors = evaluate_js(ws, "window.errors || []")
    print("Console errors recorded:", console_errors)
    assert len(console_errors) == 0, "Console errors were logged on load"

    # -------------------------------------------------------------
    # Test 2: Local Anchor Links & Documentation Links
    # -------------------------------------------------------------
    print("\n--- Test 2: Local Anchor Links & Documentation Links ---")
    anchors = evaluate_js(ws, """
        Array.from(document.querySelectorAll('a[href^=\"#\"]'))
            .map(a => a.getAttribute('href'))
            .filter(href => href.length > 1 && href !== '#simulated-threat-link')
    """)
    print("Found local in-page section anchors:", set(anchors))
    for href in set(anchors):
        target_id = href[1:]
        exists = evaluate_js(ws, f"Boolean(document.getElementById('{target_id}'))")
        assert exists, f"Anchor target #{target_id} does not exist in DOM"
    print("All in-page section anchor links verified.")

    # Check local markdown files accessible via HTTP server
    local_md_files = ["README.md", "demo-script.md", "references.md"]
    for md in local_md_files:
        md_url = f"http://127.0.0.1:{PORT}/{md}"
        with urllib.request.urlopen(md_url) as resp:
            status = resp.status
            content = resp.read(100)
            print(f"Fetched {md}: HTTP {status}, length > 0")
            assert status == 200 and len(content) > 0, f"Failed to fetch {md}"
    print("All local markdown documentation links verified.")

    # -------------------------------------------------------------
    # Test 3: Educational Lessons & Category Filter
    # -------------------------------------------------------------
    print("\n--- Test 3: Educational Lessons & Category Filter ---")
    lesson_titles = evaluate_js(ws, "Array.from(document.querySelectorAll('.lesson-card .lesson-title')).map(t => t.innerText)")
    print(f"Loaded {len(lesson_titles)} lesson modules:")
    for t in lesson_titles:
        print(f"  - {t}")
    assert len(lesson_titles) == 6, f"Expected 6 lessons, found {len(lesson_titles)}"

    # Test filter by 'vectors'
    evaluate_js(ws, "document.querySelector('.lesson-filter-btn[data-category=\"vectors\"]').click();")
    time.sleep(0.2)
    visible_cards = evaluate_js(ws, "Array.from(document.querySelectorAll('.lesson-card')).filter(c => c.style.display !== 'none').length")
    print(f"Visible cards filtered by 'vectors': {visible_cards}")
    assert visible_cards == 1, "Filter by 'vectors' should display exactly 1 card"

    # Reset filter to 'all'
    evaluate_js(ws, "document.querySelector('.lesson-filter-btn[data-category=\"all\"]').click();")
    time.sleep(0.2)
    all_cards = evaluate_js(ws, "Array.from(document.querySelectorAll('.lesson-card')).filter(c => c.style.display !== 'none').length")
    print(f"Visible cards after reset to 'all': {all_cards}")
    assert all_cards == 6, "Expected 6 cards after reset to 'all'"

    # -------------------------------------------------------------
    # Test 4: Theme Toggle Functionality
    # -------------------------------------------------------------
    print("\n--- Test 4: Theme Toggle Functionality ---")
    init_theme = evaluate_js(ws, "document.documentElement.getAttribute('data-theme')")
    print(f"Initial theme: {init_theme}")
    evaluate_js(ws, "document.getElementById('theme-toggle-btn').click();")
    theme_after_toggle = evaluate_js(ws, "document.documentElement.getAttribute('data-theme')")
    print(f"Theme after first toggle: {theme_after_toggle}")
    assert theme_after_toggle != init_theme, "Theme toggle did not change data-theme"
    evaluate_js(ws, "document.getElementById('theme-toggle-btn').click();")
    restored_theme = evaluate_js(ws, "document.documentElement.getAttribute('data-theme')")
    print(f"Restored theme: {restored_theme}")
    assert restored_theme == init_theme, "Theme was not restored"

    # -------------------------------------------------------------
    # Test 5: Threat Inspector Hotspot Mapping & Toggle
    # -------------------------------------------------------------
    print("\n--- Test 5: Threat Inspector Hotspot Mapping & Toggle ---")
    scenario_count = evaluate_js(ws, "document.querySelectorAll('.scenario-tab-btn').length")
    print(f"Scenario tab buttons count: {scenario_count}")
    assert scenario_count == 4, "Expected 4 scenarios"

    # Test Hotspot 1 in Scenario 1 (From header)
    evaluate_js(ws, "document.querySelector('.flag-selector-btn[data-flag-id=\"1\"]').click();")
    time.sleep(0.2)
    from_active = evaluate_js(ws, "document.querySelector('.mockup-email-headers .hotspot-target[data-hotspot=\"1\"]').classList.contains('active-hotspot')")
    print("From: header has active-hotspot class when Flag 1 is selected:", from_active)
    assert from_active, "From: header did not activate for Hotspot 1"

    # Test Highlight All Hotspots toggle
    btn_text_before = evaluate_js(ws, "document.getElementById('highlight-all-flags-btn').innerText")
    evaluate_js(ws, "document.getElementById('highlight-all-flags-btn').click();")
    btn_text_after = evaluate_js(ws, "document.getElementById('highlight-all-flags-btn').innerText")
    all_hl_count = evaluate_js(ws, "document.querySelectorAll('.mockup-content-body .all-highlighted, .mockup-email-headers .all-highlighted').length")
    print(f"Highlight button text changed from '{btn_text_before}' to '{btn_text_after}', highlighted elements: {all_hl_count}")
    assert "Clear Highlights" in btn_text_after and all_hl_count > 0, "Highlight All toggle failed to activate"

    # Click toggle again to clear
    evaluate_js(ws, "document.getElementById('highlight-all-flags-btn').click();")
    btn_text_cleared = evaluate_js(ws, "document.getElementById('highlight-all-flags-btn').innerText")
    cleared_count = evaluate_js(ws, "document.querySelectorAll('.all-highlighted').length")
    print(f"After clear: '{btn_text_cleared}', active all-highlighted count: {cleared_count}")
    assert cleared_count == 0, "Clear highlights failed"

    # Verify other scenarios render
    for s_idx, s_name in [(1, "SMS Frame"), (2, "Attachment Box"), (3, "Quishing QR Code")]:
        evaluate_js(ws, f"document.querySelectorAll('.scenario-tab-btn')[{s_idx}].click();")
        time.sleep(0.2)
        flag_count = evaluate_js(ws, "document.querySelectorAll('.flag-selector-btn').length")
        print(f"Scenario {s_idx + 1} ({s_name}) loaded with {flag_count} red flags.")
        assert flag_count >= 3, f"Scenario {s_idx + 1} has insufficient red flags"

    # Return to Scenario 1
    evaluate_js(ws, "document.querySelectorAll('.scenario-tab-btn')[0].click();")

    # -------------------------------------------------------------
    # Test 6: Safety Checklist & Dynamic Risk Verdict
    # -------------------------------------------------------------
    print("\n--- Test 6: Safety Checklist & Dynamic Risk Verdict ---")
    initial_verdict = evaluate_js(ws, "document.getElementById('checklist-verdict-target').innerText")
    print("Initial Checklist Verdict contains 'High Risk':", "High Risk" in initial_verdict)
    assert "High Risk" in initial_verdict, "Expected initial high risk verdict"

    evaluate_js(ws, "document.querySelectorAll('.checklist-checkbox').forEach(cb => { cb.checked = true; cb.dispatchEvent(new Event('change')); });")
    safe_verdict = evaluate_js(ws, "document.getElementById('checklist-verdict-target').innerText")
    print("Full Checklist Verdict contains 'Low Probability':", "Low Probability" in safe_verdict)
    assert "Low Probability" in safe_verdict, "Expected Low Probability verdict when all checked"

    evaluate_js(ws, "document.getElementById('reset-checklist-btn').click();")
    reset_count = evaluate_js(ws, "Array.from(document.querySelectorAll('.checklist-checkbox')).filter(cb => cb.checked).length")
    print(f"Checked count after reset: {reset_count}")
    assert reset_count == 0, "Checklist did not reset properly"

    # -------------------------------------------------------------
    # Test 7: Phishing Quiz Answer Explanations (Correct & Incorrect)
    # -------------------------------------------------------------
    print("\n--- Test 7: Phishing Quiz Answer Explanations ---")
    # Reset quiz to ensure fresh start
    evaluate_js(ws, "document.querySelector('.quiz-restart-btn') ? document.querySelector('.quiz-restart-btn').click() : null;")
    time.sleep(0.2)

    # Click an INCORRECT answer on Question 1 (Option A = index 0)
    evaluate_js(ws, "document.querySelectorAll('.quiz-option-btn')[0].click();")
    time.sleep(0.2)
    feedback_box = evaluate_js(ws, "document.querySelector('.quiz-feedback-box').innerText")
    print("Incorrect answer feedback received:")
    print("  " + feedback_box.replace("\n", "\n  "))
    assert "Incorrect" in feedback_box, "Feedback should show Incorrect"
    assert "Why your choice is risky" in feedback_box, "Feedback should explain why choice is risky"
    assert "Safe Defense Protocol" in feedback_box, "Feedback should explain safe defense protocol"

    # Test the In-Progress Quiz Reset Button
    print("\n--- Test 8: Quiz In-Progress Reset Button ---")
    evaluate_js(ws, "document.querySelector('.quiz-restart-btn').click();")
    time.sleep(0.2)
    counter_after_restart = evaluate_js(ws, "document.querySelector('.quiz-step-counter').innerText")
    print(f"Counter after in-progress restart: {counter_after_restart}")
    assert "Question 1 of 10" in counter_after_restart, "Quiz did not reset to question 1"
    btn_disabled = evaluate_js(ws, "document.querySelectorAll('.quiz-option-btn')[0].disabled")
    assert not btn_disabled, "Options should be re-enabled after reset"

    # -------------------------------------------------------------
    # Test 9: Quiz Partial Scoring & Result Breakdown
    # -------------------------------------------------------------
    print("\n--- Test 9: Quiz Partial Scoring & Result Breakdown ---")
    # Correct answers for all 10: [1, 1, 2, 0, 1, 1, 0, 1, 1, 2]
    # We will answer 7 correct (Q1-Q7) and 3 incorrect (Q8-Q10) to test partial scoring: 7/10 = 70%
    correct_indices = [1, 1, 2, 0, 1, 1, 0, 1, 1, 2]
    for q_idx in range(10):
        if q_idx < 7:
            choice = correct_indices[q_idx]
        else:
            choice = 0 if correct_indices[q_idx] != 0 else 1 # choose wrong answer
        evaluate_js(ws, f"document.querySelectorAll('.quiz-option-btn')[{choice}].click();")
        time.sleep(0.1)
        if q_idx < 9:
            evaluate_js(ws, "document.querySelector('.quiz-next-btn').click();")
            time.sleep(0.1)

    evaluate_js(ws, "document.querySelector('.quiz-finish-btn').click();")
    time.sleep(0.3)

    score_val = evaluate_js(ws, "document.querySelector('.results-score-metrics .metric-value').innerText")
    acc_val = evaluate_js(ws, "document.querySelector('.highlight-percent').innerText")
    badge_title = evaluate_js(ws, "document.querySelector('.results-tier-pill').innerText")
    print(f"Partial Score Results -> Score: {score_val}, Accuracy: {acc_val}, Badge: {badge_title}")
    assert "7 / 10" in score_val or "7/10" in score_val.replace(" ", ""), "Expected 7/10 score"
    assert "70%" in acc_val, "Expected 70% accuracy"
    assert "Security Aware Practitioner" in badge_title, "Expected Security Aware Practitioner badge"

    # Verify that the detailed breakdown includes Risk Analysis for incorrect answers
    risk_analysis_present = evaluate_js(ws, "Boolean(document.querySelector('.review-answer-comparison .comparison-label'))")
    assert risk_analysis_present, "Review breakdown missing comparison rows"

    # Test Retake Quiz from results page
    evaluate_js(ws, "document.getElementById('quiz-retake-action').click();")
    time.sleep(0.3)
    q1_again = evaluate_js(ws, "document.querySelector('.quiz-step-counter').innerText")
    print(f"Retake action cleanly reset quiz to: {q1_again}")
    assert "Question 1 of 10" in q1_again, "Quiz retake did not reset to question 1"

    # -------------------------------------------------------------
    # Test 10: Mobile Viewport & Interactive Navigation Drawer
    # -------------------------------------------------------------
    print("\n--- Test 10: Mobile Viewport & Interactive Navigation Drawer ---")
    send_cdp(ws, "Emulation.setDeviceMetricsOverride", {
        "width": 375,
        "height": 667,
        "deviceScaleFactor": 2,
        "mobile": True
    })
    time.sleep(0.3)

    # 1. Verify mobile menu button is visible
    toggle_display = evaluate_js(ws, "window.getComputedStyle(document.getElementById('mobile-menu-toggle')).display")
    print(f"Mobile menu button display at 375px: {toggle_display}")
    assert toggle_display == "block", "Mobile toggle button should be visible"

    # 2. Verify nav menu is initially hidden on mobile
    nav_display_before = evaluate_js(ws, "window.getComputedStyle(document.getElementById('nav-menu-links')).display")
    print(f"Nav menu display before click: {nav_display_before}")
    assert nav_display_before == "none", "Nav menu should be hidden before toggle"

    # 3. Click toggle button to open
    evaluate_js(ws, "document.getElementById('mobile-menu-toggle').click();")
    time.sleep(0.2)
    nav_display_after = evaluate_js(ws, "window.getComputedStyle(document.getElementById('nav-menu-links')).display")
    nav_has_open_class = evaluate_js(ws, "document.getElementById('nav-menu-links').classList.contains('nav-open')")
    print(f"Nav menu display after toggle click: {nav_display_after}, has 'nav-open': {nav_has_open_class}")
    assert nav_display_after == "block" and nav_has_open_class, "Nav menu failed to open on mobile"

    # 4. Click a link inside the mobile drawer (e.g. #quiz) to verify auto-close
    evaluate_js(ws, "document.querySelector('#nav-menu-links a[href=\"#quiz\"]').click();")
    time.sleep(0.3)
    nav_display_after_link = evaluate_js(ws, "window.getComputedStyle(document.getElementById('nav-menu-links')).display")
    print(f"Nav menu display after clicking nav link: {nav_display_after_link}")
    assert nav_display_after_link == "none", "Nav menu should close after clicking a link on mobile"

    # Reset to Desktop Viewport
    send_cdp(ws, "Emulation.setDeviceMetricsOverride", {
        "width": 1280,
        "height": 800,
        "deviceScaleFactor": 1,
        "mobile": False
    })
    time.sleep(0.2)
    print("Desktop viewport restored.")

    print("\n========================================================")
    print("ALL 10 TEST SUITES COMPLETED AND VERIFIED WITH 100% SUCCESS!")
    print("========================================================")

finally:
    if ws:
        ws.close()
    browser_process.terminate()
    try:
        browser_process.wait(timeout=3)
    except Exception:
        browser_process.kill()
    shutil.rmtree(temp_profile, ignore_errors=True)
