# PhishGuard: Interactive Phishing Awareness & Threat Defense Simulator
**CodeAlpha Cyber Security Internship — Task 2: Phishing Awareness Training**

---

## 📌 Project Overview

**PhishGuard** is an interactive, modern, client-side cybersecurity awareness training platform designed to educate individuals and corporate employees on how to detect, analyze, and defend against phishing attacks.

Rather than presenting static text, PhishGuard simulates realistic attack vectors—including email credential harvesting, mobile SMS phishing (smishing), spear-phishing with weaponized macro attachments, and malicious QR codes (quishing). Learners can interactively inspect red flags on visual mockups, test real-time message indicators with a pre-interaction safety checklist, take a 10-question evaluation quiz with immediate feedback and scoring, and review step-by-step incident response procedures.

The project is built entirely using vanilla **HTML5, CSS3, and modern JavaScript**, running completely offline with zero external dependencies, API keys, databases, or tracking scripts. All threat examples adhere to **RFC 2606** and **RFC 6761** using reserved/fictional domains to guarantee total safety.

---

## 🎯 Educational Objectives

* **Demystify Phishing Vectors:** Explain the lifecycle of modern attacks from reconnaissance to credential harvesting and lateral network traversal.
* **Cultivate Instinctive Threat Discernment:** Train users to identify subtle red flags such as display name spoofing, typosquatted lookalike domains, deceptive hyperlinks, and macro-enabled files.
* **Deconstruct Social Engineering Psychology:** Expose how cybercriminals weaponize cognitive triggers including urgency, fear, authority, and curiosity.
* **Empower Rapid Incident Mitigation:** Provide clear, actionable containment protocols to stop active compromise within the first 5 minutes.
* **Standardized Knowledge Validation:** Measure user proficiency through an interactive 10-scenario quiz featuring performance tier badges and actionable takeaways.

---

## 💻 Technologies Used

* **HTML5:** Semantic architecture (`<header>`, `<nav>`, `<main>`, `<section>`, `<article>`, `<footer>`), ARIA accessibility landmarks, and accessible forms.
* **CSS3:** Custom cyber-defense design system with CSS custom properties (variables), responsive CSS Grid and Flexbox layouts, dark/light theme switching, custom status indicators, and `@media (prefers-reduced-motion)` compliance.
* **Vanilla JavaScript (ES6+):** Pure client-side logic for the quiz engine, interactive hotspot inspector, dynamic score and badge calculation, and real-time risk assessment calculator.
* **No External Dependencies:** Zero third-party JavaScript libraries, frameworks, or web fonts required. Instant offline execution.

---

## 🚀 Key Features

### 1. Professional Cybersecurity Education Interface
* Clean, responsive layout designed for desktop (1920x1080, 1440x900), tablet (768px), and mobile (375px+).
* Cyber defense aesthetic with deep navy slate palette, glowing status indicators, and one-click Dark/Light mode toggle.
* Accessible keyboard navigation with skip-to-content links and `:focus-visible` states.

### 2. Comprehensive 6-Module Curriculum
* **Module 01: What is Phishing & Lifecycle:** Detailed 5-stage attack lifecycle (Reconnaissance, Weaponization, Delivery, Exploitation, Action on Objectives).
* **Module 02: Attack Vectors & Variants:** Email phishing (Mass, Spear, Whaling/BEC), Smishing (SMS), Vishing (Voice), and Quishing (QR Codes).
* **Module 03: Anatomy of Warning Signs (Red Flags):** Sender display name deception, typosquatting, IDN homographs, deceptive anchor text, and weaponized attachments.
* **Module 04: Social Engineering Psychology:** Cialdini's persuasion principles (Authority, Urgency, Scarcity, Fear, Greed, Curiosity).
* **Module 05: Technical Verification Protocols:** Why the HTTPS padlock does NOT guarantee safety, SPF/DKIM/DMARC email authentication fundamentals, URL parsing, and Out-of-Band (OOB) validation.
* **Module 06: Incident Response & Remediation:** Containment steps, network isolation, credential rotation, and session token revocation.
* Category filter bar to quickly navigate between curriculum modules.

### 3. Realistic Interactive Threat Inspector (4 Scenarios)
* **Scenario 1 (Email): Urgent Microsoft 365 Account Suspension:** Dissects display name spoofing, generic greeting, false countdown urgency, and deceptive link redirecting to `http://portal-auth-credential.invalid`.
* **Scenario 2 (SMS / Smishing): Banking Fraud Alert:** Realistically rendered in an iPhone messenger frame. Dissects unverified toll-free numbers, high-panic dollar amounts, lookalike banking domains, and call deflection tactics.
* **Scenario 3 (Spear Phishing / Attachment): Overdue Vendor Invoice:** Dissects typosquatted domain (`acme-supliers.test` with one 'p'), legal intimidation, unsolicited bank wire changes, and a dangerous `.xlsm` macro attachment.
* **Scenario 4 (Quishing): Breakroom MFA Upgrade Poster:** Dissects authority pretexting, QR code URL masking, and deliberate shifting of the attack to unmanaged personal devices.
* **Clickable Hotspots:** Users click highlighted elements inside the mockups to reveal severity ratings, threat actor mechanisms, and defensive verification protocols.

### 4. Interactive Phishing Quiz Engine (10 Scenarios)
* 10 deep, scenario-driven multiple-choice questions covering sender spoofing, lookalike domains, smishing, quishing, macro attachments, HTTPS fallacies, CEO fraud, incident response, out-of-band verification, and email authentication standards.
* Instant visual feedback (green for correct, red for incorrect).
* Detailed educational explanations for **every** answer choice, explaining both why the correct answer is safe and why other options are dangerous.
* Progress bar and question counter.
* Dynamic final performance score with percentage and competency tier badges:
  * **90% - 100%:** Elite Cyber Defender (Gold)
  * **70% - 89%:** Security Aware Practitioner (Silver)
  * **< 70%:** Vulnerable to Exploitation / Retraining Advised (Bronze)
* Full question breakdown for post-quiz revision.
* One-click "Retake Quiz & Reset" button.

### 5. Interactive Pre-Interaction Safety Checklist & Risk Meter
* A 6-point interactive verification checklist to evaluate any suspicious message before clicking links or downloading files.
* Real-time dynamic risk meter that recalculates safety status:
  * **6/6 Verified:** Low Risk (Still perform Out-of-Band verification for sensitive tasks)
  * **4-5/6 Verified:** Moderate Risk (Exercise caution; do not click links)
  * **< 4/6 Verified:** Critical Threat Alert (High probability of phishing; isolate and report)

### 6. Emergency Incident Response Runbook
* Step-by-step containment instructions:
  1. *Isolate & Disconnect* (Unplug Ethernet/turn off Wi-Fi without shutting down to preserve RAM evidence).
  2. *Rotate Credentials* (Change password from a separate, clean device).
  3. *Revoke Active Sessions* (Invalidate OAuth tokens and active cookies).
  4. *Notify Security/IT* (Submit raw `.eml` email with full headers).
  5. *Report to Authorities* (FTC ReportFraud, CISA, credit bureaus).

---

## 📂 Folder Structure

```
task-2-phishing-awareness/
├── index.html               # Main interactive application
├── css/
│   └── styles.css           # Custom cyber-defense stylesheet (dark/light theme, responsive, accessible)
├── js/
│   ├── app.js               # Application controller, theme toggle, checklist & risk meter logic
│   ├── quiz.js              # 10-question evaluation quiz engine, scoring, detailed feedback
│   └── scenarios.js         # Interactive threat simulator data, hotspots, and red flag analyses
├── assets/
│   └── icons/               # Directory for icon assets
├── README.md                # Project documentation and setup guide
├── demo-script.md           # Professional video demonstration script
└── references.md            # Reputable cybersecurity references and academic citations
```

---

## 💻 How to Run the Website Locally

Since the project uses vanilla HTML, CSS, and JavaScript without external build tools, you can run it in multiple simple ways:

### Method 1: Using Python (Recommended)
Open a terminal in the repository root or task folder:
```powershell
cd "c:\Desktop\code alpha\task-2-phishing-awareness"
python -m http.server 8000
```
Then open your browser and navigate to:
```
http://localhost:8000
```

### Method 2: Using Node.js `npx serve` or `http-server`
```powershell
cd "c:\Desktop\code alpha\task-2-phishing-awareness"
npx serve .
```

### Method 3: Direct Browser File Opening
You can also open the file directly in any modern browser (Google Chrome, Microsoft Edge, Firefox, Brave):
* Right-click `task-2-phishing-awareness/index.html` → **Open with** → **Google Chrome** (or Microsoft Edge).

---

## 🧪 How to Test the Project Features

### 1. Test Threat Inspector
1. Navigate to the **Threat Inspector** section or click "Launch Threat Inspector" in the hero banner.
2. Click through the scenario tabs:
   * *Scenario 1: M365 Email*
   * *Scenario 2: Banking SMS*
   * *Scenario 3: Vendor Invoice Attachment*
   * *Scenario 4: Quishing Breakroom Poster*
3. Click on the numbered red flags in the right sidebar or directly click on the highlighted elements inside the mockup.
4. Verify that the deep-dive analysis card updates with the element details, mechanism explanation, and defensive protocol.
5. Click "✨ Highlight All Hotspots" to inspect all danger zones simultaneously.

### 2. Test Interactive Phishing Quiz
1. Scroll to the **Interactive Phishing Defense Quiz** section.
2. Question 1 displays a realistic scenario. Select an option (e.g., Option B).
3. Observe immediate visual feedback (green highlight for correct answer, red for incorrect) and read the detailed explanation box.
4. Click **Next Question →** to progress through all 10 questions.
5. On Question 10, click **Finish & View Results 🏆**.
6. Verify that:
   * The total score (e.g., 9/10) is displayed correctly.
   * The accuracy percentage (e.g., 90%) is computed accurately.
   * The correct performance tier pill is shown (*Elite Cyber Defender*, *Security Aware Practitioner*, or *Vulnerable*).
   * The full question review list shows your selected answer vs. the correct answer with key takeaways.
7. Click **🔄 Retake Quiz & Reset** to verify the quiz completely resets to Question 1 with a clean state.

### 3. Test Safety Checklist & Risk Calculator
1. Scroll to the **Interactive Verification Checklist** section.
2. Initially, 0 of 6 items are checked, displaying **Critical Threat Alert (High Risk)**.
3. Check 4 or 5 boxes: the meter advances and the status switches to **Moderate Risk (Warning Signs Present)**.
4. Check all 6 boxes: the meter reaches 100% and displays **Low Probability of Phishing (Still Verify)**.
5. Click **Reset Checklist** to verify all checkboxes uncheck and the indicator returns to its baseline.

### 6. Test Dark / Light Mode Toggle
1. Click the **Light Mode / Dark Mode** button in the top navigation bar.
2. Verify that the color palette smoothly transitions between the cyber-dark slate theme and the clean high-contrast light theme.
3. Refresh the page to verify your theme selection is preserved via `localStorage`.

---

## 📸 Screenshots & Evidence to Capture for Submission

When submitting for your CodeAlpha internship batch or sharing on LinkedIn/GitHub, capture the following screenshots:

1. **Homepage & Hero Section:** Capturing the brand title, live cybersecurity statistics, and clean navigation bar.
2. **Interactive Threat Inspector (Email Scenario):** Showing the Microsoft 365 mockup with an active red flag hotspot selected and the deep-dive analysis card visible.
3. **Interactive Threat Inspector (SMS Scenario):** Showing the smartphone messenger mockup with the banking smishing threat.
4. **Interactive Quiz in Action:** Showing an active scenario question with immediate feedback and explanation displayed.
5. **Quiz Completion & Performance Summary:** Showing your final score, percentage, performance tier badge, and question review list.
6. **Safety Checklist & Risk Meter:** Showing the interactive checklist with the real-time verdict card.
7. **Emergency Incident Response Runbook:** Showing the 5-step containment protocol.

---

## 🔒 Security & Safe Simulation Guarantee

* **No Real Credential Harvesting:** The site does not submit credentials anywhere; buttons and links are strictly simulated.
* **Reserved Domains Only:** All domain names use reserved top-level and second-level domains (`.test`, `.invalid`, `.example`, `example.com`) per **RFC 2606** and **RFC 6761**.
* **Zero Tracking / No Analytics:** No external tracking scripts, advertising trackers, or external CDNs are loaded.
* **Offline Capable:** Runs entirely client-side without an internet connection.

---

## ⚠️ Limitations & Future Enhancements

* **Client-Side Storage:** Quiz history is preserved within the active session. Future versions could integrate `IndexedDB` or a local export feature to generate downloadable PDF training certificates.
* **Email Client Emulation:** Currently emulates standard webmail and mobile messaging layouts; future iterations could include additional desktop client skins (e.g., Thunderbird, Apple Mail).

---

## 📚 References & Official Guidance

* **CISA (Cybersecurity & Infrastructure Security Agency):** [Recognize and Report Phishing](https://www.cisa.gov/secure-our-world/recognize-and-report-phishing)
* **FTC (Federal Trade Commission):** [How to Recognize and Avoid Phishing Scams](https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams)
* **NIST (National Institute of Standards & Technology):** [SP 800-61 Rev. 2: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
* **APWG (Anti-Phishing Working Group):** [Phishing Activity Trends Reports](https://apwg.org/trendsreports/)
* For full academic citations and protocol standards, see [`references.md`](references.md).
