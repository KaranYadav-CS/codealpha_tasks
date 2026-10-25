/**
 * PhishGuard Security Training - Interactive Phishing Quiz Engine
 * CodeAlpha Cyber Security Internship - Task 2
 * 
 * 10 Comprehensive, Scenario-Based Cybersecurity Questions
 * Features:
 * - Immediate interactive feedback
 * - Deep educational explanations for all answer choices
 * - Dynamic score calculation, percentage, performance tiers
 * - Full retry and review capabilities
 * - Fully accessible keyboard navigation and mobile-responsive layout
 */

const QUIZ_QUESTIONS = [
  {
    id: 1,
    category: "Sender Verification",
    question: "You receive an email where the sender display name shows 'Microsoft Account Security', but the full email address is 'alert-notification@security-update-portal365.invalid'. What does this indicate?",
    scenario: "An email states: 'Suspicious activity detected on your account. Click to secure your credentials.' The sender header appears as: Microsoft Account Security <alert-notification@security-update-portal365.invalid>.",
    options: [
      {
        text: "The email is legitimate because Microsoft uses specialized security subdomains for automated security dispatches.",
        correct: false,
        explanation: "Incorrect. Major cloud providers send official account notifications exclusively from their primary verified domains (such as @accountprotection.microsoft.com). Attackers configure friendly display names to disguise arbitrary lookalike domains."
      },
      {
        text: "It is a display name spoofing attack; the actual sender is an unauthorized external domain.",
        correct: true,
        explanation: "Correct! The display name can be configured to say whatever the sender wants. The critical detail is the actual domain after the '@' symbol. Here, 'security-update-portal365.invalid' is not an official Microsoft domain."
      },
      {
        text: "The email is authenticated because it has a valid security keyword ('security-update') in the address.",
        correct: false,
        explanation: "Incorrect. Anyone can register a domain containing words like 'security', 'support', 'update', or 'login'. Including security keywords is a deliberate psychological trick used by cybercriminals."
      },
      {
        text: "You can safely click the link as long as your browser displays an HTTPS padlock when opening the page.",
        correct: false,
        explanation: "Incorrect. An HTTPS padlock only means data in transit is encrypted; it does not verify that the website owner is reputable. Phishers use free SSL/TLS certificates on the vast majority of modern credential-harvesting pages."
      }
    ]
  },
  {
    id: 2,
    category: "URL & Domain Analysis",
    question: "Which of the following URLs is the legitimate portal for 'SecureBank' (whose official website is 'securebank.example')?",
    scenario: "You are evaluating several links received across different notifications. Which one actually points to the legitimate organization?",
    options: [
      {
        text: "https://securebank.example.portal-verification.test/login",
        correct: false,
        explanation: "Incorrect. In this URL, 'securebank.example' is merely a subdomain prefix. The actual registered domain (effective Second-Level Domain + Top-Level Domain) is 'portal-verification.test', controlled by an attacker."
      },
      {
        text: "https://login.securebank.example/account/dashboard",
        correct: true,
        explanation: "Correct! The base root domain is 'securebank.example', and 'login' is a valid subdomain created by the legitimate domain owner. Browsing to this URL keeps you on the official organization's domain."
      },
      {
        text: "https://securebank-account-security.example.test/reset",
        correct: false,
        explanation: "Incorrect. Hyphenating brand names with words like 'account' or 'security' creates an entirely different root domain ('example.test'), registered by third parties to mimic official brands."
      },
      {
        text: "http://securebank.example@attacker-relay.invalid/auth",
        correct: false,
        explanation: "Incorrect. This URL exploits the HTTP Basic Authentication syntax ('user@host'). Everything before the '@' is treated as a username, while the browser navigates directly to 'attacker-relay.invalid'."
      }
    ]
  },
  {
    id: 3,
    category: "Smishing (SMS Phishing)",
    question: "You receive an SMS: 'Courier Alert: Your parcel #US-84920 has a pending customs fee of $2.50. Pay within 12 hours to avoid return: https://track-parcel-fee.test/pay'. What is the safest course of action?",
    scenario: "You recently placed an online order and were expecting a delivery, making this text message seem plausible at first glance.",
    options: [
      {
        text: "Tap the link and pay the small $2.50 fee because it is negligible and ensures your parcel will not be returned.",
        correct: false,
        explanation: "Incorrect. The nominal $2.50 fee is a lure. The real goal is to capture your full credit card number, expiration date, CVV, and billing address on the fake payment form."
      },
      {
        text: "Reply 'STOP' or 'UNSUBSCRIBE' to the SMS to remove your phone number from their list.",
        correct: false,
        explanation: "Incorrect. Replying to an unsolicited scam message confirms to the attacker that your phone number is active and monitored, which leads to increased spam and targeted attacks."
      },
      {
        text: "Do not tap the link. Check the official delivery provider's app or website directly using the tracking number from your original purchase receipt.",
        correct: true,
        explanation: "Correct! Always verify package statuses through the merchant's original order confirmation or the courier's official app/site. Never click tracking or payment links sent via unexpected SMS."
      },
      {
        text: "Forward the SMS to all your colleagues to warn them before verifying whether it is real.",
        correct: false,
        explanation: "Incorrect. Forwarding unverified messages can spread panic or accidental clicks. You should report the message to your cellular carrier's spam reporting service (such as 7726 / SPAM) or your organization's security team."
      }
    ]
  },
  {
    id: 4,
    category: "Quishing (QR Code Phishing)",
    question: "Why do cybercriminals increasingly use QR codes in phishing emails and physical flyers (a tactic known as 'Quishing')?",
    scenario: "A printable notice in an employee cafeteria claims: 'Scan this QR code with your personal smartphone to access the new corporate cafeteria loyalty program and discount portal.'",
    options: [
      {
        text: "QR codes automatically bypass standard email text analysis filters and prevent victims from easily previewing the full URL before scanning.",
        correct: true,
        explanation: "Correct! QR codes hide the malicious destination URL inside an image, which frequently evades traditional email text and link scanners. Furthermore, it shifts the attack to mobile devices that often lack enterprise endpoint defenses."
      },
      {
        text: "QR codes contain hardware-level exploits that immediately infect smartphone operating systems without requiring any user interaction.",
        correct: false,
        explanation: "Incorrect. Standard QR codes are simply visual encodings of text or URLs. They do not magically execute arbitrary binary code without user interaction; they rely on social engineering to trick the user into navigating to a malicious site or entering credentials."
      },
      {
        text: "QR codes cannot be scanned by modern mobile devices unless the user installs a special hacking application.",
        correct: false,
        explanation: "Incorrect. Almost all modern smartphones have native QR code scanners built directly into their default camera apps, making them extremely frictionless for victims to scan."
      },
      {
        text: "QR codes are only dangerous when printed on paper, never when transmitted inside an email.",
        correct: false,
        explanation: "Incorrect. Attackers frequently attach PNG/PDF files with QR codes to emails specifically to bypass Secure Email Gateways (SEGs) that parse text hyperlinks."
      }
    ]
  },
  {
    id: 5,
    category: "Malicious Attachments",
    question: "You receive an email from an external vendor containing an invoice named 'Q3_Reconciliation_Invoice.xlsm'. When opened, a yellow banner reads: 'Macros have been disabled. Enable Content'. What should you do?",
    scenario: "The email claims: 'Please enable macros immediately to calculate discounted payment terms.'",
    options: [
      {
        text: "Click 'Enable Content' because Microsoft Excel macros are required to calculate accounting numbers and formulas in spreadsheets.",
        correct: false,
        explanation: "Incorrect. Standard Excel formulas (such as SUM, VLOOKUP, XLOOKUP) work without macros. Macros run executable Visual Basic for Applications (VBA) code, which can download and execute ransomware, trojans, or infostealers."
      },
      {
        text: "Do NOT click 'Enable Content'. Invoices should not require macros. Close the document and report it to your IT security team.",
        correct: true,
        explanation: "Correct! Standard invoices should be static PDF documents. Any external financial document demanding that you enable macros or content is almost certainly an active malware dropper attempt."
      },
      {
        text: "Save the file to your desktop, rename the extension from .xlsm to .xlsx, and re-open it to make it safe.",
        correct: false,
        explanation: "Incorrect. Renaming the extension does not neutralize embedded malicious payloads and may corrupt the file structure while leaving your system vulnerable."
      },
      {
        text: "Forward the email with the attachment to your personal Gmail account to see if Google's antivirus flags it.",
        correct: false,
        explanation: "Incorrect. Forwarding potentially malicious corporate emails to personal accounts violates corporate data security policies and risks infecting your personal computer or cloud storage."
      }
    ]
  },
  {
    id: 6,
    category: "The HTTPS Myth",
    question: "True or False: If a website's URL starts with 'https://' and displays a secure padlock icon in the browser address bar, the website is verified as authentic and safe to enter your passwords.",
    scenario: "A user lands on 'https://login-mybank-support-auth.invalid' and notices the browser displays a valid padlock icon.",
    options: [
      {
        text: "True: The padlock is issued by Certificate Authorities only after conducting thorough identity and criminal background checks on the domain owner.",
        correct: false,
        explanation: "Incorrect. Most SSL/TLS certificates issued today are Domain Validated (DV) certificates (such as those from automated free providers like Let's Encrypt). They only verify that the requester controls DNS for that domain name—not that the owner is legitimate or trustworthy."
      },
      {
        text: "False: The HTTPS padlock only verifies that traffic between your browser and the website is encrypted; over 80% of phishing sites use valid SSL certificates.",
        correct: true,
        explanation: "Correct! HTTPS provides confidentiality (encryption in transit), not authenticity of identity. Cybercriminals easily generate free SSL certificates so their phishing sites look professional and avoid browser warnings."
      },
      {
        text: "True: Web browsers automatically block any phishing website that attempts to use HTTPS encryption.",
        correct: false,
        explanation: "Incorrect. Web browsers do not automatically block HTTPS sites. While tools like Google Safe Browsing and Microsoft SmartScreen flag known phishing sites, newly launched zero-hour phishing domains often go undetected for hours."
      },
      {
        text: "False: HTTPS was deprecated in 2024 and replaced by HTTP/3, so padlocks are no longer relevant to security.",
        correct: false,
        explanation: "Incorrect. HTTPS remains the foundational transport layer security protocol on the modern web and works across HTTP/1.1, HTTP/2, and HTTP/3."
      }
    ]
  },
  {
    id: 7,
    category: "Social Engineering & Psychology",
    question: "An urgent email from your company's Chief Executive Officer (CEO) arrives during lunch: 'I am in a closed-door board meeting and cannot talk on the phone. Need you to purchase five $200 Apple gift cards for a client presentation immediately. Send the redemption codes to my personal email right now.' What attack vector is this?",
    scenario: "The email header shows: CEO Name <exec-board-emergency-mail@mail.invalid>. The tone is direct, commanding, and insists on bypassing standard procurement channels.",
    options: [
      {
        text: "Whaling / Business Email Compromise (BEC) utilizing authority and artificial urgency to exploit social compliance.",
        correct: true,
        explanation: "Correct! Whaling / Executive BEC attacks impersonate high-ranking corporate leaders, exploiting organizational hierarchy, fear of insubordination, and manufactured urgency to push employees into purchasing untraceable gift cards or wiring funds."
      },
      {
        text: "Distributed Denial of Service (DDoS) attack targeting corporate gift card servers.",
        correct: false,
        explanation: "Incorrect. DDoS is an infrastructure attack that floods network bandwidth or servers to cause service outages. It has nothing to do with social engineering gift card scams."
      },
      {
        text: "Legitimate executive emergency request because CEOs frequently purchase client gifts through staff via gift card codes.",
        correct: false,
        explanation: "Incorrect. Legitimate executives and corporations have established accounts payable and procurement procedures. Requesting gift cards or unverified wire transfers via email is a universal indicator of fraud."
      },
      {
        text: "Ransomware infection requiring immediate gift card ransom payment.",
        correct: false,
        explanation: "Incorrect. Ransomware encrypts local hard drive files and displays a system-wide ransom note demanding cryptocurrency, not employee gift card errands."
      }
    ]
  },
  {
    id: 8,
    category: "Incident Response",
    question: "You realize you accidentally clicked a link in a suspicious email and typed your corporate username and password into a fake login screen before realizing it was a phishing site. What is your FIRST and most urgent step?",
    scenario: "You pressed 'Submit' on the fake form five seconds ago. You feel panicked. How should you react?",
    options: [
      {
        text: "Shut down and power off your computer immediately, leave the office, and wait until tomorrow morning to see if anything happened.",
        correct: false,
        explanation: "Incorrect. Powering down can destroy volatile RAM evidence needed by digital forensic analysts, and waiting allows the threat actor time to leverage your credentials to compromise internal systems."
      },
      {
        text: "Immediately change your password from a known safe device, disconnect your workstation from the network, and immediately report the incident to your IT/Security Operations team.",
        correct: true,
        explanation: "Correct! Speed is critical. Changing your password immediately invalidates the stolen credential, disconnecting from the network prevents lateral spread or data exfiltration, and notifying IT allows defenders to revoke active session tokens and review audit logs."
      },
      {
        text: "Delete the phishing email from your inbox and trash folder so nobody in the company finds out you made a mistake.",
        correct: false,
        explanation: "Incorrect. Hiding the mistake leaves the attacker inside corporate systems. Furthermore, deleting the email destroys vital forensic headers (such as sender IP, server relays, and campaign markers) that IT security needs to protect other staff."
      },
      {
        text: "Email the attacker to ask them politely to delete your credentials from their database.",
        correct: false,
        explanation: "Incorrect. Threat actors are criminal syndicates or adversaries; contacting them provides zero protection and flags you as a vulnerable target for further exploitation."
      }
    ]
  },
  {
    id: 9,
    category: "Verification Protocols",
    question: "What is 'Out-of-Band (OOB) Verification', and why is it considered the gold standard for verifying suspicious requests?",
    scenario: "A vendor sends an email requesting an urgent wire transfer to a new bank account due to an 'auditing transition'.",
    options: [
      {
        text: "Replying directly to the suspicious email and asking the sender to confirm their identity with a security passphrase.",
        correct: false,
        explanation: "Incorrect. If the sender's email account has been compromised or spoofed, you are simply communicating directly with the attacker, who will gladly confirm their own fraudulent request."
      },
      {
        text: "Validating the request using an independent, pre-established communication channel (such as a known verified phone number or in-person meeting), completely separate from the message received.",
        correct: true,
        explanation: "Correct! Out-of-band verification ensures you bypass the potentially compromised digital channel. By calling the vendor on a verified, pre-existing phone number from their original contract, you verify the transaction through a trusted path."
      },
      {
        text: "Running the email text through an automated AI grammar checker to see if the sentence structure is correct.",
        correct: false,
        explanation: "Incorrect. Modern cybercriminals regularly utilize generative AI tools to draft flawless, grammatically perfect emails in any language."
      },
      {
        text: "Checking if the sender's domain has an active LinkedIn page with more than 500 connections.",
        correct: false,
        explanation: "Incorrect. Social media profiles can easily be fabricated or cloned using synthetic identities and automated connection bots."
      }
    ]
  },
  {
    id: 10,
    category: "Email Authentication Architecture",
    question: "How do SPF, DKIM, and DMARC protocols protect organizations against email spoofing?",
    scenario: "An organization configures DNS records to protect its public brand from being impersonated by scammers sending fake invoices.",
    options: [
      {
        text: "They encrypt the body of every email so that unauthorized interceptors cannot read the message contents in transit.",
        correct: false,
        explanation: "Incorrect. Message body encryption is handled by protocols like S/MIME, PGP, or TLS. SPF, DKIM, and DMARC handle domain authentication and spoofing prevention, not body encryption."
      },
      {
        text: "They completely prevent employees from ever clicking malicious links or visiting newly registered domains.",
        correct: false,
        explanation: "Incorrect. Email authentication protocols operate at the mail server DNS level to authenticate the sender's identity. They have no control over user click behavior or web browsing."
      },
      {
        text: "SPF lists authorized sending IP addresses, DKIM provides cryptographic digital signatures to verify message integrity, and DMARC specifies how receiving mail servers should handle messages that fail these checks.",
        correct: true,
        explanation: "Correct! SPF (RFC 7208) authorizes IP addresses for a domain, DKIM (RFC 6376) cryptographically signs messages, and DMARC (RFC 7489) ties them together and dictates enforcement policies (none, quarantine, reject)."
      },
      {
        text: "They automatically delete any email sent from a smartphone or tablet.",
        correct: false,
        explanation: "Incorrect. Email authentication is completely device-agnostic; it evaluates sending mail transfer agents (MTAs) and domain records."
      }
    ]
  }
];

class PhishQuizEngine {
  constructor(questions, containerId) {
    this.questions = questions;
    this.container = typeof document !== "undefined" ? document.getElementById(containerId) : null;
    this.currentIndex = 0;
    this.userAnswers = {}; // questionId -> selectedOptionIndex
    this.isSubmitted = false;
  }

  init() {
    this.currentIndex = 0;
    this.userAnswers = {};
    this.isSubmitted = false;
    this.render();
  }

  render() {
    if (!this.container) return;

    if (this.isSubmitted) {
      this.renderResults();
      return;
    }

    const q = this.questions[this.currentIndex];
    const total = this.questions.length;
    const progressPercent = Math.round(((this.currentIndex) / total) * 100);
    const selectedOption = this.userAnswers[q.id];
    const isAnswered = selectedOption !== undefined;

    this.container.innerHTML = `
      <div class="quiz-card-wrapper" role="region" aria-label="Phishing Awareness Evaluation Quiz">
        <div class="quiz-header">
          <div class="quiz-progress-info">
            <span class="quiz-step-counter">Question <strong>${this.currentIndex + 1}</strong> of ${total}</span>
            <span class="quiz-category-badge">${q.category}</span>
          </div>
          <div class="quiz-progress-bar-bg" role="progressbar" aria-valuenow="${progressPercent}" aria-valuemin="0" aria-valuemax="100">
            <div class="quiz-progress-bar-fill" style="width: ${progressPercent}%;"></div>
          </div>
        </div>

        <div class="quiz-body">
          <div class="quiz-scenario-box">
            <span class="scenario-tag">SCENARIO</span>
            <p class="scenario-text">${q.scenario}</p>
          </div>
          <h3 class="quiz-question-title">${q.question}</h3>

          <div class="quiz-options-list" role="radiogroup" aria-label="${q.question}">
            ${q.options.map((opt, idx) => {
              const isSelected = selectedOption === idx;
              let stateClass = "";
              let feedbackIcon = "";

              if (isAnswered) {
                if (opt.correct) {
                  stateClass = "option-correct";
                  feedbackIcon = `<span class="option-badge-icon check" aria-label="Correct Option">✓</span>`;
                } else if (isSelected && !opt.correct) {
                  stateClass = "option-incorrect";
                  feedbackIcon = `<span class="option-badge-icon cross" aria-label="Incorrect Choice">✗</span>`;
                } else {
                  stateClass = "option-neutral-disabled";
                }
              }

              return `
                <button 
                  type="button" 
                  class="quiz-option-btn ${isSelected ? 'selected' : ''} ${stateClass}" 
                  data-option-index="${idx}"
                  ${isAnswered ? 'disabled' : ''}
                  aria-pressed="${isSelected}"
                >
                  <span class="option-key">${String.fromCharCode(65 + idx)}</span>
                  <span class="option-text">${opt.text}</span>
                  ${feedbackIcon}
                </button>
              `;
            }).join("")}
          </div>

          ${isAnswered ? `
            <div class="quiz-feedback-box ${q.options[selectedOption].correct ? 'feedback-success' : 'feedback-danger'}" role="alert">
              <div class="feedback-title">
                ${q.options[selectedOption].correct 
                  ? '<strong>✓ Correct!</strong> Well done.' 
                  : '<strong>✗ Incorrect Choice.</strong> Review the security analysis below:'}
              </div>
              <div class="feedback-explanation">
                ${q.options[selectedOption].correct ? `
                  <p>${q.options[selectedOption].explanation}</p>
                ` : `
                  <p><strong>Why your choice is risky:</strong> ${q.options[selectedOption].explanation}</p>
                  <p style="margin-top: 0.6rem; padding-top: 0.6rem; border-top: 1px dashed rgba(239, 68, 68, 0.4);">
                    <strong>Safe Defense Protocol:</strong> ${q.options.find(o => o.correct).explanation}
                  </p>
                `}
              </div>
            </div>
          ` : ''}
        </div>

        <div class="quiz-footer">
          <div class="quiz-nav-left">
            <button 
              type="button" 
              class="btn-secondary quiz-prev-btn" 
              ${this.currentIndex === 0 ? 'disabled' : ''}
              aria-label="Previous question"
            >
              ← Previous
            </button>
            <button 
              type="button" 
              class="btn-sm btn-subtle quiz-restart-btn" 
              title="Reset quiz back to Question 1"
              style="margin-left: 0.5rem;"
            >
              ↻ Reset Quiz
            </button>
          </div>
          <div class="quiz-nav-right">
            ${isAnswered ? `
              ${this.currentIndex < total - 1 ? `
                <button type="button" class="btn-primary quiz-next-btn">
                  Next Question →
                </button>
              ` : `
                <button type="button" class="btn-primary btn-success-highlight quiz-finish-btn">
                  Finish &amp; View Results 🏆
                </button>
              `}
            ` : `
              <span class="quiz-hint-text">Select an option above to continue</span>
            `}
          </div>
        </div>
      </div>
    `;

    this.bindEvents();
  }

  bindEvents() {
    const optionButtons = this.container.querySelectorAll(".quiz-option-btn");
    optionButtons.forEach(btn => {
      btn.addEventListener("click", () => {
        const optIndex = parseInt(btn.getAttribute("data-option-index"), 10);
        this.selectAnswer(optIndex);
      });
    });

    const prevBtn = this.container.querySelector(".quiz-prev-btn");
    if (prevBtn) {
      prevBtn.addEventListener("click", () => {
        if (this.currentIndex > 0) {
          this.currentIndex--;
          this.render();
        }
      });
    }

    const restartBtn = this.container.querySelector(".quiz-restart-btn");
    if (restartBtn) {
      restartBtn.addEventListener("click", () => {
        this.init();
      });
    }

    const nextBtn = this.container.querySelector(".quiz-next-btn");
    if (nextBtn) {
      nextBtn.addEventListener("click", () => {
        if (this.currentIndex < this.questions.length - 1) {
          this.currentIndex++;
          this.render();
        }
      });
    }

    const finishBtn = this.container.querySelector(".quiz-finish-btn");
    if (finishBtn) {
      finishBtn.addEventListener("click", () => {
        this.isSubmitted = true;
        this.render();
      });
    }
  }

  selectAnswer(index) {
    const currentQ = this.questions[this.currentIndex];
    if (this.userAnswers[currentQ.id] !== undefined) return; // already answered
    this.userAnswers[currentQ.id] = index;
    this.render();
  }

  calculateScore() {
    let correctCount = 0;
    this.questions.forEach(q => {
      const userChoice = this.userAnswers[q.id];
      if (userChoice !== undefined && q.options[userChoice] && q.options[userChoice].correct) {
        correctCount++;
      }
    });
    const percentage = Math.round((correctCount / this.questions.length) * 100);
    return { correctCount, total: this.questions.length, percentage };
  }

  getPerformanceBadge(percentage) {
    if (percentage >= 90) {
      return {
        title: "Elite Cyber Defender",
        colorClass: "badge-gold",
        message: "Outstanding! You demonstrate advanced threat discernment across complex email, SMS, and QR social engineering vectors.",
        icon: "🛡️"
      };
    } else if (percentage >= 70) {
      return {
        title: "Security Aware Practitioner",
        colorClass: "badge-silver",
        message: "Great effort! You possess solid foundational cyber defense awareness. Review the explanations below to master the subtle edge cases.",
        icon: "⚔️"
      };
    } else {
      return {
        title: "Vulnerable to Exploitation (Retraining Advised)",
        colorClass: "badge-bronze",
        message: "Caution: You fell for several realistic social engineering lures. Review the lesson modules and retake the quiz to sharpen your vigilance.",
        icon: "⚠️"
      };
    }
  }

  renderResults() {
    const { correctCount, total, percentage } = this.calculateScore();
    const badge = this.getPerformanceBadge(percentage);

    this.container.innerHTML = `
      <div class="quiz-results-card" role="region" aria-label="Quiz Results and Performance Summary">
        <div class="results-hero-header">
          <div class="results-badge-icon">${badge.icon}</div>
          <h3 class="results-title">Evaluation Complete</h3>
          <div class="results-tier-pill ${badge.colorClass}">${badge.title}</div>
          <p class="results-description">${badge.message}</p>
        </div>

        <div class="results-score-metrics">
          <div class="metric-box">
            <span class="metric-label">Total Score</span>
            <span class="metric-value"><strong>${correctCount}</strong> / ${total}</span>
          </div>
          <div class="metric-box">
            <span class="metric-label">Accuracy Rate</span>
            <span class="metric-value highlight-percent"><strong>${percentage}%</strong></span>
          </div>
          <div class="metric-box">
            <span class="metric-label">Completion Status</span>
            <span class="metric-value status-passed">${percentage >= 70 ? 'PASSED ✓' : 'NEEDS REVIEW ↻'}</span>
          </div>
        </div>

        <div class="results-actions">
          <button type="button" class="btn-primary retake-quiz-btn" id="quiz-retake-action">
            🔄 Retake Quiz &amp; Reset
          </button>
          <a href="#lessons" class="btn-secondary">
            📚 Review Lessons
          </a>
        </div>

        <div class="results-detailed-review">
          <h4 class="review-section-heading">Detailed Question Breakdown &amp; Explanations</h4>
          <div class="review-questions-list">
            ${this.questions.map((q, idx) => {
              const userChoice = this.userAnswers[q.id];
              const isCorrect = userChoice !== undefined && q.options[userChoice] && q.options[userChoice].correct;
              const selectedOptionObj = userChoice !== undefined ? q.options[userChoice] : null;
              const correctOptionObj = q.options.find(o => o.correct);

              return `
                <div class="review-item ${isCorrect ? 'review-correct' : 'review-incorrect'}">
                  <div class="review-item-header">
                    <span class="review-status-indicator">${isCorrect ? '✓ CORRECT' : '✗ INCORRECT'}</span>
                    <span class="review-item-number">Question ${idx + 1}: ${q.category}</span>
                  </div>
                  <p class="review-question-text"><strong>Q:</strong> ${q.question}</p>
                  
                  <div class="review-answer-comparison">
                    <div class="comparison-row">
                      <span class="comparison-label">Your Response:</span>
                      <span class="comparison-value ${isCorrect ? 'text-correct' : 'text-danger'}">
                        ${selectedOptionObj ? selectedOptionObj.text : 'No answer'}
                      </span>
                    </div>
                    ${!isCorrect && selectedOptionObj ? `
                      <div class="comparison-row">
                        <span class="comparison-label">Risk Analysis:</span>
                        <span class="comparison-value text-danger" style="font-weight: normal;">
                          ${selectedOptionObj.explanation}
                        </span>
                      </div>
                    ` : ''}
                    ${!isCorrect ? `
                      <div class="comparison-row">
                        <span class="comparison-label">Correct Response:</span>
                        <span class="comparison-value text-correct">
                          ${correctOptionObj.text}
                        </span>
                      </div>
                    ` : ''}
                  </div>

                  <div class="review-explanation-callout">
                    <strong>Key Security Takeaway:</strong> ${correctOptionObj.explanation}
                  </div>
                </div>
              `;
            }).join("")}
          </div>
        </div>
      </div>
    `;

    const retakeBtn = this.container.querySelector("#quiz-retake-action");
    if (retakeBtn) {
      retakeBtn.addEventListener("click", () => {
        this.init();
        const quizSection = document.getElementById("quiz");
        if (quizSection) {
          quizSection.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      });
    }
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { QUIZ_QUESTIONS, PhishQuizEngine };
}
