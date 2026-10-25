# Reputable Cybersecurity References & Educational Citations

This document compiles authoritative, official, and industry-standard cybersecurity resources utilized in the research, instructional design, and validation of the **Phishing Awareness Training & Defense Simulator** (CodeAlpha Cyber Security Internship Task 2).

All instructional materials across the lessons, threat simulations, interactive checklist, and knowledge evaluations are carefully paraphrased and aligned with these institutional standards.

---

## 1. Official Government & Regulatory Authorities

### Cybersecurity and Infrastructure Security Agency (CISA)
* **Title:** Secure Our World: Recognize and Report Phishing
* **URL:** [https://www.cisa.gov/secure-our-world/recognize-and-report-phishing](https://www.cisa.gov/secure-our-world/recognize-and-report-phishing)
* **Key Topics Leveraged:**
  * The core four cyber hygiene pillars: recognizing phishing, using strong/unique passwords, enabling Multi-Factor Authentication (MFA), and updating software promptly.
  * Identification of urgent language, unexpected financial requests, and deceptive sender domains.
  * Actionable guidance on reporting phishing to workplace IT and to national reporting coordinators.

### Federal Trade Commission (FTC)
* **Title:** How to Recognize and Avoid Phishing Scams
* **URL:** [https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams](https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams)
* **Key Topics Leveraged:**
  * Consumer protection mechanisms against email and SMS (smishing) lures.
  * Common pretexting narratives (fake invoices, problem with payment information, unexpected government subsidies or refunds).
  * Post-incident credit monitoring, account freezes, and reporting procedures via [ReportFraud.ftc.gov](https://reportfraud.ftc.gov).

### National Institute of Standards and Technology (NIST)
* **Title:** NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide
* **URL:** [https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
* **Key Topics Leveraged:**
  * Incident response lifecycle: Preparation, Detection & Analysis, Containment, Eradication & Recovery, and Post-Incident Activity.
  * Protocol for isolating compromised endpoints from the local network without erasing volatile RAM artifacts.

---

## 2. Non-Profit & Global Threat Intelligence Coalitions

### Anti-Phishing Working Group (APWG)
* **Title:** Phishing Activity Trends Reports & Counter-Phishing Best Practices
* **URL:** [https://apwg.org/trendsreports/](https://apwg.org/trendsreports/)
* **Key Topics Leveraged:**
  * Statistical evolution of phishing tactics: surge in mobile smishing, malicious QR codes (quishing), and the widespread weaponization of free SSL/TLS certificates by threat actors.
  * Reporting portal standard: reporting deceptive sites and raw phishing emails to [reportphishing@apwg.org](mailto:reportphishing@apwg.org).

### SANS Institute
* **Title:** SANS Security Awareness: Phishing & Social Engineering Architecture
* **URL:** [https://www.sans.org/security-awareness-training/resources/](https://www.sans.org/security-awareness-training/resources/)
* **Key Topics Leveraged:**
  * Human-risk management and cognitive bias exploitation (fear, urgency, authority, scarcity, curiosity).
  * Out-of-band (OOB) authentication principles for high-risk corporate and financial transactions.

---

## 3. Technical Standards & Protocol Specifications

### Internet Engineering Task Force (IETF) - Email Authentication
* **RFC 7208:** Sender Policy Framework (SPF) for Authorizing Use of Domains in Email
  * [https://www.rfc-editor.org/rfc/rfc7208](https://www.rfc-editor.org/rfc/rfc7208)
* **RFC 6376:** DomainKeys Identified Mail (DKIM) Signatures
  * [https://www.rfc-editor.org/rfc/rfc6376](https://www.rfc-editor.org/rfc/rfc6376)
* **RFC 7489:** Domain-based Message Authentication, Reporting, and Conformance (DMARC)
  * [https://www.rfc-editor.org/rfc/rfc7489](https://www.rfc-editor.org/rfc/rfc7489)
* **Key Topics Leveraged:**
  * Technical distinction between envelope sender (`Return-Path`) and header sender (`From:`).
  * Why authentication frameworks alone cannot stop attacks originating from newly registered lookalike domains or compromised third-party accounts.

---

## 4. Educational Methodology & Safe Simulation Standards

To adhere to responsible cybersecurity disclosure and academic safety standards:
1. **No Live Attack Infrastructure:** No actual phishing templates, malicious scripts, credential collectors, or external tracking mechanisms are included.
2. **Reserved Example Domains:** In compliance with **RFC 2606** and **RFC 6761**, all domain names in examples use reserved domains (`example.com`, `.test`, `.invalid`, `.example`) or fictional organizational names.
3. **Paraphrased Guidance:** Educational principles are synthesized into original instructional modules, clear architectural diagrams, and interactive scenario walk-throughs to maximize learner retention.
