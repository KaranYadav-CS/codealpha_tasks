/**
 * PhishGuard Security Training - Main Application Controller
 * CodeAlpha Cyber Security Internship - Task 2
 * 
 * Manages:
 * - Threat Inspector simulator & Red Flag hotspots
 * - Interactive Pre-Interaction Safety Checklist & Risk Calculator
 * - Incident Response Runbook
 * - Dark/Light Theme Switching
 * - Mobile Navigation & Smooth Anchor Scrolling
 * - Lesson Filter Categories
 */

document.addEventListener("DOMContentLoaded", () => {
  initThemeToggle();
  initMobileNav();
  initThreatInspector();
  initSafetyChecklist();
  initLessonFilter();
  initQuiz();
});

/* ==========================================================================
   1. Theme Management (Dark / Light with System Preference Fallback)
   ========================================================================== */
function initThemeToggle() {
  const themeToggleBtn = document.getElementById("theme-toggle-btn");
  const themeIcon = document.getElementById("theme-toggle-icon");
  const themeText = document.getElementById("theme-toggle-text");

  // Retrieve saved preference or default to dark (standard cybersecurity palette)
  const savedTheme = localStorage.getItem("phishguard_theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
  updateThemeUI(savedTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", () => {
      const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
      const newTheme = currentTheme === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", newTheme);
      localStorage.setItem("phishguard_theme", newTheme);
      updateThemeUI(newTheme);
    });
  }

  function updateThemeUI(theme) {
    if (!themeIcon || !themeText) return;
    if (theme === "light") {
      themeIcon.textContent = "🌙";
      themeText.textContent = "Dark Mode";
      themeToggleBtn.setAttribute("aria-label", "Switch to Dark Mode");
    } else {
      themeIcon.textContent = "☀️";
      themeText.textContent = "Light Mode";
      themeToggleBtn.setAttribute("aria-label", "Switch to Light Mode");
    }
  }
}

/* ==========================================================================
   2. Mobile Navigation & Accessible Focus
   ========================================================================== */
function initMobileNav() {
  const menuToggle = document.getElementById("mobile-menu-toggle");
  const navLinks = document.getElementById("nav-menu-links");

  if (!menuToggle || !navLinks) return;

  menuToggle.addEventListener("click", () => {
    const isExpanded = menuToggle.getAttribute("aria-expanded") === "true";
    menuToggle.setAttribute("aria-expanded", !isExpanded);
    navLinks.classList.toggle("nav-open");
  });

  // Close nav when link clicked
  navLinks.querySelectorAll("a").forEach(link => {
    link.addEventListener("click", () => {
      menuToggle.setAttribute("aria-expanded", "false");
      navLinks.classList.remove("nav-open");
    });
  });
}

/* ==========================================================================
   3. Interactive Threat Inspector (Scenarios Engine)
   ========================================================================== */
let currentScenarioIndex = 0;
let activeHotspotId = null;

function initThreatInspector() {
  const scenarioSelector = document.getElementById("scenario-tabs-container");
  const mockupContainer = document.getElementById("scenario-mockup-target");
  const flagsListContainer = document.getElementById("red-flags-list-target");
  const analysisTarget = document.getElementById("red-flag-analysis-target");

  if (!mockupContainer || !SCENARIOS_DATA || SCENARIOS_DATA.length === 0) return;

  // Render Scenario Tab Buttons
  if (scenarioSelector) {
    scenarioSelector.innerHTML = SCENARIOS_DATA.map((sc, idx) => `
      <button 
        type="button" 
        class="scenario-tab-btn ${idx === currentScenarioIndex ? 'active' : ''}" 
        data-scenario-idx="${idx}"
        role="tab"
        aria-selected="${idx === currentScenarioIndex}"
      >
        <span class="tab-vector-icon">${getVectorIcon(sc.vector)}</span>
        <span class="tab-label">${sc.title.split(":")[0]}</span>
      </button>
    `).join("");

    scenarioSelector.querySelectorAll(".scenario-tab-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const idx = parseInt(btn.getAttribute("data-scenario-idx"), 10);
        switchScenario(idx);
      });
    });
  }

  renderCurrentScenario();

  function switchScenario(index) {
    currentScenarioIndex = index;
    activeHotspotId = 1; // Default to first hotspot for immediate education
    if (scenarioSelector) {
      scenarioSelector.querySelectorAll(".scenario-tab-btn").forEach((btn, idx) => {
        const isCurrent = idx === index;
        btn.classList.toggle("active", isCurrent);
        btn.setAttribute("aria-selected", isCurrent);
      });
    }
    renderCurrentScenario();
  }

  function renderCurrentScenario() {
    const scenario = SCENARIOS_DATA[currentScenarioIndex];
    if (!scenario) return;

    // Header metadata
    const metaContainer = document.getElementById("scenario-meta-header");
    if (metaContainer) {
      metaContainer.innerHTML = `
        <div class="scenario-badge-row">
          <span class="badge-tag badge-cyan">${scenario.badge}</span>
          <span class="badge-tag badge-dark">Target: ${scenario.target}</span>
          <span class="badge-tag badge-warning">Vector: ${scenario.vector}</span>
        </div>
        <h3 class="scenario-main-title">${scenario.title}</h3>
        <p class="scenario-summary-desc">${scenario.summary}</p>
      `;
    }

    // Render Visual Mockup
    mockupContainer.innerHTML = `
      <div class="mockup-frame-outer">
        <div class="mockup-window-bar">
          <div class="window-dots">
            <span class="dot dot-red"></span>
            <span class="dot dot-yellow"></span>
            <span class="dot dot-green"></span>
          </div>
          <span class="window-title">${scenario.vector === 'SMS' ? 'Mobile Messenger View' : 'Secure Mail Client - Threat Inspection View'}</span>
          <div class="window-watermark">HARMLESS SIMULATION</div>
        </div>
        ${scenario.vector !== 'SMS' && scenario.vector !== 'QR Code' ? `
          <div class="mockup-email-headers">
            <div class="hotspot-target" data-hotspot="1" title="Click to inspect sender address">
              <strong>From:</strong> ${escapeHtml(scenario.senderDisplay)} &lt;<code>${escapeHtml(scenario.senderAddress)}</code>&gt;
              ${scenario.id === 'scenario-invoice' ? '<span class="tag-danger" style="margin-left: 0.5rem;">[Typosquatting Detected]</span>' : ''}
            </div>
            <div><strong>To:</strong> <code>${escapeHtml(scenario.recipient)}</code></div>
            <div><strong>Date:</strong> ${escapeHtml(scenario.date)}</div>
            <div><strong>Subject:</strong> <span class="subject-highlight">${escapeHtml(scenario.subject)}</span></div>
          </div>
        ` : ''}
        <div class="mockup-content-body">
          ${scenario.bodyHtml}
        </div>
      </div>
    `;

    // Render Red Flags Sidebar
    renderRedFlagsSidebar(scenario);

    // Bind Hotspot Clicks inside Mockup
    mockupContainer.querySelectorAll(".hotspot-target").forEach(el => {
      el.addEventListener("click", () => {
        const flagId = parseInt(el.getAttribute("data-hotspot"), 10);
        selectHotspot(flagId);
      });
    });

    // Default select first hotspot
    if (scenario.redFlags.length > 0 && !activeHotspotId) {
      activeHotspotId = scenario.redFlags[0].id;
    }
    selectHotspot(activeHotspotId || 1);
  }

  function renderRedFlagsSidebar(scenario) {
    if (!flagsListContainer) return;

    flagsListContainer.innerHTML = `
      <div class="flags-sidebar-header">
        <span class="flags-count">Detected Red Flags: <strong>${scenario.redFlags.length}</strong></span>
        <button type="button" class="btn-sm btn-subtle" id="highlight-all-flags-btn">
          ✨ Highlight All Hotspots
        </button>
      </div>
      <div class="flags-button-group" role="tablist">
        ${scenario.redFlags.map(flag => `
          <button 
            type="button" 
            class="flag-selector-btn ${flag.id === activeHotspotId ? 'active-flag' : ''}" 
            data-flag-id="${flag.id}"
            role="tab"
            aria-selected="${flag.id === activeHotspotId}"
          >
            <span class="flag-number">${flag.id}</span>
            <div class="flag-meta-col">
              <span class="flag-title-text">${flag.title}</span>
              <span class="flag-severity-pill severity-${flag.severity.toLowerCase()}">${flag.severity}</span>
            </div>
          </button>
        `).join("")}
      </div>
    `;

    flagsListContainer.querySelectorAll(".flag-selector-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const id = parseInt(btn.getAttribute("data-flag-id"), 10);
        selectHotspot(id);
      });
    });

    let isAllHighlighted = false;
    const highlightAllBtn = flagsListContainer.querySelector("#highlight-all-flags-btn");
    if (highlightAllBtn) {
      highlightAllBtn.addEventListener("click", () => {
        isAllHighlighted = !isAllHighlighted;
        mockupContainer.querySelectorAll(".hotspot-target").forEach(el => {
          el.classList.toggle("all-highlighted", isAllHighlighted);
        });
        highlightAllBtn.textContent = isAllHighlighted ? "✖ Clear Highlights" : "✨ Highlight All Hotspots";
      });
    }
  }

  function selectHotspot(flagId) {
    activeHotspotId = flagId;
    const scenario = SCENARIOS_DATA[currentScenarioIndex];
    if (!scenario) return;

    const flag = scenario.redFlags.find(f => f.id === flagId) || scenario.redFlags[0];

    // Update Flag Buttons styling
    if (flagsListContainer) {
      flagsListContainer.querySelectorAll(".flag-selector-btn").forEach(btn => {
        const isCurrent = parseInt(btn.getAttribute("data-flag-id"), 10) === flagId;
        btn.classList.toggle("active-flag", isCurrent);
        btn.setAttribute("aria-selected", isCurrent);
      });
    }

    // Update Mockup Hotspots styling
    mockupContainer.querySelectorAll(".hotspot-target").forEach(el => {
      const match = parseInt(el.getAttribute("data-hotspot"), 10) === flagId;
      el.classList.toggle("active-hotspot", match);
      if (match) {
        el.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    });

    // Render Analysis Detail Card
    if (analysisTarget && flag) {
      analysisTarget.innerHTML = `
        <div class="analysis-card ${flag.severity.toLowerCase()}-card" role="region" aria-label="Red Flag Deep Dive Analysis">
          <div class="analysis-top">
            <span class="analysis-flag-id">Hotspot #${flag.id}</span>
            <span class="analysis-category-pill">${flag.category}</span>
            <span class="analysis-severity-tag severity-${flag.severity.toLowerCase()}">${flag.severity} Severity</span>
          </div>
          <h4 class="analysis-heading">${flag.title}</h4>
          
          <div class="analysis-snippet-box">
            <span class="snippet-label">Suspicious Element in Message:</span>
            <code class="snippet-code">${escapeHtml(flag.element)}</code>
          </div>

          <div class="analysis-section">
            <h5 class="analysis-subhead">🚨 Why This is a Warning Sign</h5>
            <p class="analysis-body-text">${flag.explanation}</p>
          </div>

          <div class="analysis-section defense-callout">
            <h5 class="analysis-subhead">🛡️ Defensive Verification Protocol</h5>
            <p class="analysis-defense-text">${flag.defense}</p>
          </div>
        </div>
      `;
    }
  }

  function getVectorIcon(vector) {
    switch (vector) {
      case "Email": return "✉️";
      case "SMS": return "💬";
      case "Email Attachment": return "📎";
      case "QR Code": return "📷";
      default: return "⚠️";
    }
  }
}

/* ==========================================================================
   4. Practical Safety Checklist & Real-Time Threat Score Calculator
   ========================================================================== */
function initSafetyChecklist() {
  const checkboxes = document.querySelectorAll(".checklist-checkbox");
  const verdictContainer = document.getElementById("checklist-verdict-target");
  const resetBtn = document.getElementById("reset-checklist-btn");
  const progressFill = document.getElementById("checklist-meter-fill");
  const counterText = document.getElementById("checklist-counter-text");

  if (!checkboxes || checkboxes.length === 0) return;

  checkboxes.forEach(cb => {
    cb.addEventListener("change", evaluateChecklist);
  });

  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      checkboxes.forEach(cb => cb.checked = false);
      evaluateChecklist();
    });
  }

  evaluateChecklist(); // Initial evaluation

  function evaluateChecklist() {
    let checkedCount = 0;
    checkboxes.forEach(cb => {
      if (cb.checked) checkedCount++;
    });

    const total = checkboxes.length;
    const percent = Math.round((checkedCount / total) * 100);

    if (progressFill) {
      progressFill.style.width = `${percent}%`;
    }
    if (counterText) {
      counterText.innerHTML = `<strong>${checkedCount}</strong> of ${total} verification steps satisfied`;
    }

    if (!verdictContainer) return;

    if (checkedCount === total) {
      verdictContainer.className = "checklist-verdict-card verdict-safe";
      verdictContainer.innerHTML = `
        <div class="verdict-icon">🛡️</div>
        <div class="verdict-content">
          <h4>Low Probability of Phishing (Still Verify)</h4>
          <p>All core security criteria were verified. However, if this message requests unusual actions, wire transfers, or sensitive data, always perform an <strong>Out-of-Band (OOB)</strong> verbal verification via a known pre-existing phone number before taking action.</p>
        </div>
      `;
    } else if (checkedCount >= 4) {
      verdictContainer.className = "checklist-verdict-card verdict-caution";
      verdictContainer.innerHTML = `
        <div class="verdict-icon">⚠️</div>
        <div class="verdict-content">
          <h4>Moderate Risk: Warning Signs Present</h4>
          <p>One or more critical safety indicators could not be verified. <strong>Do NOT click any hyperlinks or open attachments.</strong> Verify the sender's identity through an independent, trusted channel (official company directory or known customer service number).</p>
        </div>
      `;
    } else {
      verdictContainer.className = "checklist-verdict-card verdict-danger";
      verdictContainer.innerHTML = `
        <div class="verdict-icon">🚨</div>
        <div class="verdict-content">
          <h4>High Risk: Multiple Phishing Indicators Detected!</h4>
          <p>This message displays classic social engineering hallmarks (domain mismatch, urgency, unverified links, or suspicious attachments). <strong>Treat this message as an active attack.</strong> Do not reply, do not click links, isolate the message, and report it immediately to your IT/Security Operations team.</p>
        </div>
      `;
    }
  }
}

/* ==========================================================================
   5. Lesson Filter Categories
   ========================================================================== */
function initLessonFilter() {
  const filterPills = document.querySelectorAll(".lesson-filter-btn");
  const lessonCards = document.querySelectorAll(".lesson-card");

  if (!filterPills.length || !lessonCards.length) return;

  filterPills.forEach(pill => {
    pill.addEventListener("click", () => {
      const category = pill.getAttribute("data-category");

      filterPills.forEach(p => p.classList.remove("active"));
      pill.classList.add("active");

      lessonCards.forEach(card => {
        const cardCategory = card.getAttribute("data-lesson-category");
        if (category === "all" || cardCategory === category) {
          card.style.display = "flex";
        } else {
          card.style.display = "none";
        }
      });
    });
  });
}

/* ==========================================================================
   6. Quiz Initialization
   ========================================================================== */
function initQuiz() {
  if (typeof QUIZ_QUESTIONS !== "undefined" && typeof PhishQuizEngine !== "undefined") {
    const quizInstance = new PhishQuizEngine(QUIZ_QUESTIONS, "quiz-engine-target");
    quizInstance.init();
  }
}

/* ==========================================================================
   Utility Helpers
   ========================================================================== */
function escapeHtml(text) {
  if (!text) return "";
  const map = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  };
  return text.toString().replace(/[&<>"']/g, m => map[m]);
}
