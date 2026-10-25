/**
 * PhishGuard Security Training - Interactive Threat Inspector Scenarios
 * CodeAlpha Cyber Security Internship - Task 2
 * 
 * Harmless educational scenarios using reserved/fictional domains (RFC 2606).
 */

const SCENARIOS_DATA = [
  {
    id: "scenario-m365",
    title: "Scenario 1: Urgent Microsoft 365 Account Suspension",
    badge: "Email Phishing / Credential Harvester",
    vector: "Email",
    difficulty: "Common / Medium",
    target: "Corporate Employees",
    summary: "A deceptive email masquerading as a corporate IT Helpdesk warning of imminent account deactivation unless credentials are confirmed.",
    senderDisplay: "IT Global Support Desk",
    senderAddress: "security-alert@m365-tenant-portal-validate.invalid",
    recipient: "alex.hunter@example-corp.test",
    date: "Today, 08:42 AM",
    subject: "URGENT ACTION REQUIRED: Microsoft 365 Password Expires in 3 Hours",
    previewText: "Your corporate single sign-on access will be revoked today unless verified...",
    bodyHtml: `
      <div class="email-mockup-wrapper">
        <div class="email-warning-banner hotspot-target" data-hotspot="4">
          <span class="warning-icon">⚠️</span>
          <span><strong>High Priority Alert:</strong> Your account password for alex.hunter@example-corp.test expires today at 12:00 PM. Access to Outlook, Teams, and SharePoint will be terminated.</span>
        </div>
        <p class="hotspot-target" data-hotspot="2">Dear Valued Employee,</p>
        <p>Our automated security monitoring system detected that your corporate single sign-on password has reached its maximum security lifecycle (90 days). Due to corporate policy compliance, you must verify your identity immediately.</p>
        <p>To retain your existing password and prevent account suspension, click the security verification link below immediately:</p>
        <div class="email-cta-box hotspot-target" data-hotspot="3">
          <a href="#simulated-threat-link" class="simulated-cta-btn" onclick="return false;">
            Keep My Current Password &amp; Re-Authenticate Now
          </a>
          <span class="destination-tooltip">Real destination: <code>http://portal-auth-credential.invalid/m365-login</code></span>
        </div>
        <p class="hotspot-target" data-hotspot="4">Failure to authenticate within 3 hours will require an in-person IT appointment and manager escalation.</p>
        <div class="email-mockup-footer hotspot-target" data-hotspot="5">
          <p>© 2026 Microsoft Enterprise Cloud Security Division. All rights reserved.<br>
          Message ID: MS-AUTH-98234-SEC | Confidential Internal Notification</p>
        </div>
      </div>
    `,
    redFlags: [
      {
        id: 1,
        title: "Sender Display Name Spoofing & Domain Mismatch",
        element: "Sender: security-alert@m365-tenant-portal-validate.invalid",
        category: "Sender Verification",
        severity: "Critical",
        explanation: "The display name claims to be 'IT Global Support Desk', but the actual email address is on an unrecognized external domain ('m365-tenant-portal-validate.invalid'). Internal IT communications will always originate from your organization's verified domain (e.g., '@example-corp.test') or authorized tenant domain.",
        defense: "Always inspect the actual email address inside the angle brackets, not just the display name. Check the domain extension and query your internal IT team through verified internal channels."
      },
      {
        id: 2,
        title: "Generic, Impersonal Salutation",
        element: "Greeting: 'Dear Valued Employee'",
        category: "Content Analysis",
        severity: "Medium",
        explanation: "Legitimate corporate systems and IT administrators know your full name and employee ID. Cybercriminals use generic greetings like 'Valued Employee' or 'Dear Customer' when launching automated mass-phishing campaigns to thousands of recipients.",
        defense: "Treat any supposedly internal communication that fails to address you properly by your official organizational name with high suspicion."
      },
      {
        id: 3,
        title: "Deceptive Hyperlink & Credential Harvester Destination",
        element: "CTA Button Destination: http://portal-auth-credential.invalid/m365-login",
        category: "URL Inspection",
        severity: "Critical",
        explanation: "While the button text promises to maintain your password, the underlying hyperlink redirects to an external, unauthorized domain using an insecure HTTP protocol. Clicking this button would lead to a fake clone of the Microsoft login page designed to capture your username, password, and session MFA token.",
        defense: "Always hover over links without clicking to preview the full URL in the browser status bar. Ensure the domain matches the true service (e.g., 'login.microsoftonline.com'). Never enter credentials on an unverified domain."
      },
      {
        id: 4,
        title: "Artificial Urgency & Coercive Deadline",
        element: "Threat: 'Expires in 3 hours / In-person IT appointment'",
        category: "Psychological Trigger",
        severity: "High",
        explanation: "Attackers manufacture strict, unrealistic time limits (3 hours) combined with the threat of professional friction (account lock, manager escalation). This psychological tactic forces victims to bypass critical thinking and act impulsively.",
        defense: "Pause when feeling rushed. Genuine IT password expirations provide days or weeks of advance notification with standard self-service portal prompts, not panic-inducing countdowns."
      },
      {
        id: 5,
        title: "Fake Official Badges & Copyright Mimicry",
        element: "Footer: 'Microsoft Enterprise Cloud Security Division'",
        category: "Visual Deception",
        severity: "Low",
        explanation: "Phishers frequently copy official logos, legal disclaimers, and fake tracking IDs ('MS-AUTH-98234-SEC') at the bottom of emails to create a false sense of legitimacy and technical authority.",
        defense: "Legal footers and logos can be freely copied by anyone with basic HTML knowledge. Never rely on logos or copyright notices to validate authenticity."
      }
    ]
  },
  {
    id: "scenario-smishing",
    title: "Scenario 2: Banking Fraud Alert (SMS Phishing / Smishing)",
    badge: "Smishing / Mobile Attack",
    vector: "SMS",
    difficulty: "High / Deceptive",
    target: "Mobile Users",
    summary: "An urgent mobile text message simulating a bank fraud alert regarding an unauthorized wire transfer, designed to exploit panic.",
    senderDisplay: "+1 (800) 555-0199 (Unregistered Shortcode)",
    senderAddress: "SMS Gateway",
    recipient: "Mobile Device (+1-555-0144)",
    date: "Today, 14:15",
    subject: "Apex Union Bank Fraud Alert",
    previewText: "URGENT: Suspicious wire transfer of $2,450.00 attempted...",
    bodyHtml: `
      <div class="sms-phone-frame">
        <div class="sms-phone-notch"></div>
        <div class="sms-phone-header">
          <span class="sms-back-arrow">‹</span>
          <div class="sms-contact-info hotspot-target" data-hotspot="1">
            <span class="sms-avatar">🏦</span>
            <span class="sms-name">Apex Union Bank Alert</span>
            <span class="sms-number">+1 (800) 555-0199</span>
          </div>
          <span class="sms-info-btn">ⓘ</span>
        </div>
        <div class="sms-chat-area">
          <div class="sms-timestamp">Today 2:15 PM</div>
          <div class="sms-bubble incoming">
            <p class="hotspot-target" data-hotspot="2"><strong>[APEX BANK FRAUD DEPT]</strong> Urgent Alert: A transfer of <strong>$2,450.00</strong> to 'CryptoBridge Int.' was initiated from your checking account.</p>
            <p class="hotspot-target" data-hotspot="3">If this was NOT you, immediately cancel this transaction to prevent fund release: <span class="sms-link">https://apex-security-review.test/tx984</span></p>
            <p class="hotspot-target" data-hotspot="4">DO NOT call customer service as lines are congested. Link expires in 10 minutes to protect your funds.</p>
          </div>
        </div>
      </div>
    `,
    redFlags: [
      {
        id: 1,
        title: "Unverified Sender Number & Spoofed Shortcode",
        element: "Sender: +1 (800) 555-0199",
        category: "Sender Verification",
        severity: "High",
        explanation: "Banks communicate security alerts using registered, verified 5- or 6-digit commercial shortcodes (e.g., 22751), not generic random toll-free numbers or unlisted cell numbers.",
        defense: "Never trust the caller ID or SMS sender header. Phone numbers can be easily spoofed via VoIP services."
      },
      {
        id: 2,
        title: "High-Emotion Financial Panic Pretext",
        element: "Message: 'Transfer of $2,450.00 to CryptoBridge Int.'",
        category: "Psychological Trigger",
        severity: "Critical",
        explanation: "Using high-dollar transactions and frightening keywords like 'Crypto' triggers immediate financial alarm. The emotional panic induces the victim to click before analyzing the situation.",
        defense: "Step back and breathe. Financial alerts should prompt you to open your official banking app directly—never click links in text messages."
      },
      {
        id: 3,
        title: "Deceptive Lookalike Domain in Text Message",
        element: "URL: https://apex-security-review.test/tx984",
        category: "URL Inspection",
        severity: "Critical",
        explanation: "The link looks convincing because it contains the bank's name, but the domain is actually 'apex-security-review.test', which is completely distinct from the bank's genuine domain (e.g., 'apexbank.example'). Cybercriminals register domain names containing legitimate brand names separated by hyphens.",
        defense: "Inspect the root domain. Remember that 'brand-security.com' is NOT 'brand.com'. Better yet, follow the universal banking rule: never tap links sent via text."
      },
      {
        id: 4,
        title: "Deliberate Isolation Tactics & Call Deflection",
        element: "Warning: 'DO NOT call customer service...'",
        category: "Social Engineering",
        severity: "High",
        explanation: "The attacker explicitly discourages the victim from calling official bank support, claiming lines are 'congested'. This isolates the target and prevents the real bank from immediately debunking the scam.",
        defense: "Any message instructing you NOT to contact official customer support is almost certainly malicious. Always call the number stamped on the back of your physical debit or credit card."
      }
    ]
  },
  {
    id: "scenario-invoice",
    title: "Scenario 3: Vendor Invoice with Weaponized Macro Attachment",
    badge: "Spear Phishing / Malware Delivery",
    vector: "Email Attachment",
    difficulty: "Advanced / Targeted",
    target: "Finance & Operations",
    summary: "A targeted spear-phishing attack posing as a known supplier, delivering a weaponized macro-enabled spreadsheet disguised as an overdue invoice.",
    senderDisplay: "Accounts Receivable - Acme Industrial Supplies",
    senderAddress: "billing@acme-supliers.test",
    recipient: "accounts.payable@example-corp.test",
    date: "Yesterday, 16:50 PM",
    subject: "FINAL LEGAL NOTICE: Overdue Remittance for Invoice #INV-84192",
    previewText: "Your payment of $14,820.00 is 45 days past due. Attached collection documentation...",
    bodyHtml: `
      <div class="email-mockup-wrapper">
        <p>Attention Accounts Payable Team,</p>
        <p class="hotspot-target" data-hotspot="2">Despite multiple previous notifications, invoice <strong>#INV-84192</strong> in the amount of <strong>$14,820.00</strong> remains unpaid. If payment confirmation is not received by 5:00 PM tomorrow, this account will be transferred to our third-party legal collections agency, resulting in immediate credit rating penalties and interest charges.</p>
        <p class="hotspot-target" data-hotspot="3">Please review the itemized breakdown and updated wire instructions in the attached financial statement:</p>
        <div class="attachment-box hotspot-target" data-hotspot="4">
          <div class="attachment-icon">📊</div>
          <div class="attachment-details">
            <span class="attachment-name">Overdue_Invoice_INV-84192.xlsm</span>
            <span class="attachment-meta">Microsoft Excel Macro-Enabled Worksheet | 1.8 MB</span>
          </div>
          <button class="attachment-download-btn" onclick="return false;">Inspect Attachment</button>
        </div>
        <p class="hotspot-target" data-hotspot="5"><em>Note: If you have trouble viewing calculations, please click 'Enable Content' or 'Enable Macros' in the yellow Microsoft Excel notification bar at the top of your document.</em></p>
        <p>Sincerely,<br>
        <strong>Karen Mitchell</strong><br>
        Senior Controller, Acme Industrial Supplies</p>
      </div>
    `,
    redFlags: [
      {
        id: 1,
        title: "Typosquatted Lookalike Domain (Missing Letter)",
        element: "Sender: billing@acme-supliers.test (Missing 'p' in suppliers)",
        category: "Sender Verification",
        severity: "Critical",
        explanation: "The legitimate company domain is 'acme-suppliers.com'. The sender's address uses 'acme-supliers.test' with a single 'p'—a classic typosquatting technique designed to slip past hurried human eyes.",
        defense: "Carefully spell-check domain names in transactional emails. Create internal email security rules that flag incoming external mail mimicking approved vendor names."
      },
      {
        id: 2,
        title: "Legal Intimidation & Aggressive Escalation",
        element: "Threat: 'Third-party legal collections agency / Credit penalty'",
        category: "Social Engineering",
        severity: "High",
        explanation: "Threatening legal action and credit destruction creates anxiety. Finance workers are conditioned to avoid company liabilities, making them eager to resolve the issue quickly.",
        defense: "Cross-reference unexpected invoice numbers with your organization's internal Enterprise Resource Planning (ERP) or procurement database before interacting with the sender."
      },
      {
        id: 3,
        title: "Unsolicited Wire Instruction Modification",
        element: "Content: 'Updated wire instructions in attached file'",
        category: "Business Email Compromise (BEC)",
        severity: "Critical",
        explanation: "A frequent objective in supply-chain attacks is tricking companies into sending payments to fraudulent bank accounts controlled by attackers by claiming 'updated remittance instructions'.",
        defense: "Establish strict mandatory two-person authorization policies for vendor banking changes. Never update bank details without verbal out-of-band confirmation via a known, pre-established phone number."
      },
      {
        id: 4,
        title: "Dangerous Weaponized File Extension (.xlsm)",
        element: "Attachment: Overdue_Invoice_INV-84192.xlsm",
        category: "Malware Analysis",
        severity: "Critical",
        explanation: "The file uses the '.xlsm' extension (Excel Macro-Enabled Spreadsheet). Invoices should almost always be static PDF documents. Macro-enabled office files frequently harbor Visual Basic for Applications (VBA) malware designed to download ransomware or trojans.",
        defense: "Never open macro-enabled attachments (.xlsm, .docm) from outside your organization. Ensure corporate security policies block incoming macros by default."
      },
      {
        id: 5,
        title: "Instruction to Bypass Security Safeguards ('Enable Macros')",
        element: "Instruction: 'Click Enable Content or Enable Macros'",
        category: "Social Engineering",
        severity: "Critical",
        explanation: "Modern versions of Microsoft Office disable macros from the internet by default. The attacker explicitly coaches the user to disable these security protections under the guise of 'viewing calculations'.",
        defense: "Treat any document requesting you to click 'Enable Content' or 'Enable Editing' to view an invoice as an active malware execution attempt."
      }
    ]
  },
  {
    id: "scenario-quishing",
    title: "Scenario 4: Malicious Office QR Code Flyer (Quishing)",
    badge: "Quishing / Physical-to-Digital",
    vector: "QR Code",
    difficulty: "Emerging Threat",
    target: "Hybrid / Workplace Users",
    summary: "A deceptive poster affixed in a corporate breakroom or sent as a flyer, urging staff to scan a QR code with their mobile devices to complete mandatory MFA enrollment.",
    senderDisplay: "Corporate Information Security Office",
    senderAddress: "Physical Flyer / PDF Notice",
    recipient: "All Enterprise Personnel",
    date: "Current Campaign",
    subject: "Mandatory Multi-Factor Authentication Migration",
    previewText: "Scan the QR code with your mobile smartphone camera to pair your security token...",
    bodyHtml: `
      <div class="quishing-poster-frame">
        <div class="poster-header hotspot-target" data-hotspot="1">
          <div class="poster-badge">ENTERPRISE IT SECURITY NOTICE</div>
          <h3>MANDATORY TWO-FACTOR AUTHENTICATION UPGRADE</h3>
          <p class="poster-subtitle">Cyber Defense Compliance Update 2026.4</p>
        </div>
        <div class="poster-body">
          <p class="hotspot-target" data-hotspot="2">In response to recent cybersecurity threats, all corporate personnel must enroll their mobile devices into the new Enterprise Authenticator system before Friday 5:00 PM.</p>
          <div class="poster-qr-container hotspot-target" data-hotspot="3">
            <div class="simulated-qr-box">
              <svg class="qr-svg" viewBox="0 0 100 100" width="120" height="120" aria-label="Simulated QR Code">
                <rect width="100" height="100" fill="#ffffff" />
                <rect x="10" y="10" width="25" height="25" fill="#000000" />
                <rect x="15" y="15" width="15" height="15" fill="#ffffff" />
                <rect x="18" y="18" width="9" height="9" fill="#000000" />
                <rect x="65" y="10" width="25" height="25" fill="#000000" />
                <rect x="70" y="15" width="15" height="15" fill="#ffffff" />
                <rect x="73" y="18" width="9" height="9" fill="#000000" />
                <rect x="10" y="65" width="25" height="25" fill="#000000" />
                <rect x="15" y="70" width="15" height="15" fill="#ffffff" />
                <rect x="18" y="73" width="9" height="9" fill="#000000" />
                <!-- Pattern elements -->
                <rect x="40" y="15" width="8" height="8" fill="#000000" />
                <rect x="42" y="30" width="6" height="6" fill="#000000" />
                <rect x="52" y="20" width="6" height="6" fill="#000000" />
                <rect x="25" y="42" width="6" height="6" fill="#000000" />
                <rect x="45" y="45" width="10" height="10" fill="#000000" />
                <rect x="62" y="42" width="8" height="8" fill="#000000" />
                <rect x="80" y="45" width="8" height="8" fill="#000000" />
                <rect x="42" y="62" width="6" height="6" fill="#000000" />
                <rect x="55" y="70" width="8" height="8" fill="#000000" />
                <rect x="70" y="65" width="6" height="6" fill="#000000" />
                <rect x="80" y="75" width="8" height="8" fill="#000000" />
              </svg>
              <div class="qr-scan-badge">SCAN TO ENROLL</div>
            </div>
            <div class="qr-instruction">
              <ol>
                <li>Open your smartphone camera.</li>
                <li>Point at the QR code above.</li>
                <li>Tap the link and enter your corporate email &amp; network password.</li>
              </ol>
              <div class="hidden-url-reveal">
                <strong>Encoded Destination:</strong> <code>https://auth-enrollment-portal.test/sso-register</code>
              </div>
            </div>
          </div>
          <div class="poster-footer hotspot-target" data-hotspot="4">
            <p>Non-compliance will result in temporary suspension of VPN and campus Wi-Fi privileges.</p>
          </div>
        </div>
      </div>
    `,
    redFlags: [
      {
        id: 1,
        title: "Impersonation of Corporate Authority & Compliance Pretext",
        element: "Banner: 'Enterprise IT Security Notice / Mandatory MFA Upgrade'",
        category: "Authority Pretexting",
        severity: "High",
        explanation: "Threat actors exploit ongoing corporate security initiatives (such as MFA rollouts) because employees naturally expect them and comply without second thought.",
        defense: "Legitimate IT policy changes are communicated through official internal intranet portals, team standups, and authenticated administrative channels—not anonymous flyers or unsolicited PDFs."
      },
      {
        id: 2,
        title: "Shifting the Attack to Unmanaged Personal Devices",
        element: "Instruction: 'Scan with your smartphone camera'",
        category: "Bypassing Security Controls",
        severity: "Critical",
        explanation: "Corporate laptops usually have Endpoint Detection & Response (EDR), DNS filtering, and enterprise firewalls. By directing you to scan a QR code on your personal smartphone, attackers bypass enterprise network controls and target a device with fewer defenses.",
        defense: "Never use your personal mobile device to scan unknown QR codes relating to enterprise authentication or business credentials."
      },
      {
        id: 3,
        title: "Inability to Visually Inspect the URL Before Scanning",
        element: "QR Code masking destination: 'auth-enrollment-portal.test'",
        category: "Quishing Architecture",
        severity: "Critical",
        explanation: "Unlike text hyperlinks, QR codes cannot be read or verified by human eyes. Furthermore, QR codes embedded in email images frequently bypass traditional email text analysis engines and spam filters.",
        defense: "When a QR code is scanned, modern phone cameras display a preview of the destination URL. Scrutinize the domain carefully before tapping. If it asks for login credentials, stop immediately."
      },
      {
        id: 4,
        title: "Coercive Penalty (Loss of Access Privileges)",
        element: "Warning: 'Suspension of VPN and campus Wi-Fi privileges'",
        category: "Psychological Trigger",
        severity: "Medium",
        explanation: "Threatening to cut off essential work tools creates anxiety about job performance, forcing employees to take immediate action rather than verifying the request.",
        defense: "Verify through your company's documented IT Helpdesk ticketing system or by speaking directly with an IT staff member."
      }
    ]
  }
];

if (typeof module !== "undefined" && module.exports) {
  module.exports = { SCENARIOS_DATA };
}
