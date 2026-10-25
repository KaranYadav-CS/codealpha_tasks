/**
 * Suricata NIDS Dashboard - Client Application Controller
 * CodeAlpha Cyber Security Internship - Task 4
 */

let allAlerts = [];
let currentFilteredAlerts = [];

document.addEventListener("DOMContentLoaded", () => {
  initDashboard();
});

async function initDashboard() {
  bindEventListeners();
  await checkEngineStatus();
  await loadAlerts();
}

function bindEventListeners() {
  const refreshBtn = document.getElementById("refresh-alerts-btn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => loadAlerts());
  }

  const runBtn = document.getElementById("run-analysis-btn");
  if (runBtn) {
    runBtn.addEventListener("click", () => triggerOfflineAnalysis());
  }

  const emptyRunBtn = document.getElementById("empty-run-btn");
  if (emptyRunBtn) {
    emptyRunBtn.addEventListener("click", () => triggerOfflineAnalysis());
  }

  const exportBtn = document.getElementById("export-btn");
  const exportMenu = document.getElementById("export-menu");
  if (exportBtn && exportMenu) {
    exportBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      exportMenu.style.display = exportMenu.style.display === "none" ? "flex" : "none";
    });

    document.addEventListener("click", () => {
      exportMenu.style.display = "none";
    });
  }

  // Search & Filter listeners
  const searchInput = document.getElementById("search-input");
  if (searchInput) {
    searchInput.addEventListener("input", applyFilters);
  }

  const sevFilter = document.getElementById("severity-filter");
  if (sevFilter) {
    sevFilter.addEventListener("change", applyFilters);
  }

  const protoFilter = document.getElementById("proto-filter");
  if (protoFilter) {
    protoFilter.addEventListener("change", applyFilters);
  }

  const clearBtn = document.getElementById("clear-filters-btn");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      if (searchInput) searchInput.value = "";
      if (sevFilter) sevFilter.value = "all";
      if (protoFilter) protoFilter.value = "all";
      applyFilters();
    });
  }

  // Modal close handlers
  const modal = document.getElementById("event-modal");
  const closeBtn = document.getElementById("modal-close-btn");
  if (modal && closeBtn) {
    closeBtn.addEventListener("click", () => modal.style.display = "none");
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.style.display = "none";
    });
  }
}

async function checkEngineStatus() {
  const textEl = document.getElementById("engine-status-text");
  const pillEl = document.getElementById("engine-status-pill");
  const engineValEl = document.getElementById("pipeline-engine-val");

  try {
    const res = await fetch("/api/status");
    const data = await res.json();

    if (data.suricata_installed) {
      if (textEl) textEl.textContent = `Suricata Engine Active (${data.suricata_version.split("\n")[0]})`;
      if (engineValEl) engineValEl.textContent = data.suricata_version.replace("Info: win32-service: Running as service: no", "").trim();
    } else {
      if (textEl) textEl.textContent = "Suricata Engine Not Detected";
      if (pillEl) pillEl.style.borderColor = "#ef4444";
    }
  } catch (err) {
    if (textEl) textEl.textContent = "Status Check Failed";
  }
}

async function loadAlerts() {
  const tbody = document.getElementById("alerts-tbody");
  const emptyState = document.getElementById("empty-state");
  const table = document.getElementById("alerts-table");

  try {
    const res = await fetch("/api/alerts");
    const data = await res.json();

    if (data.status === "empty" || !data.alerts || data.alerts.length === 0) {
      allAlerts = [];
      currentFilteredAlerts = [];
      updateMetrics({ total_alerts: 0, by_severity: {}, by_signature: {}, unique_sids: [] });
      if (table) table.style.display = "none";
      if (emptyState) emptyState.style.display = "block";
      updateCountTag(0, 0);
      renderBreakdown({});
      return;
    }

    allAlerts = data.alerts;
    currentFilteredAlerts = [...allAlerts];

    if (table) table.style.display = "table";
    if (emptyState) emptyState.style.display = "none";

    updateMetrics(data.summary);
    renderTable(currentFilteredAlerts);
    renderBreakdown(data.summary.by_signature);
  } catch (err) {
    console.error("Failed to fetch alerts:", err);
  }
}

function updateMetrics(summary) {
  const totalEl = document.getElementById("metric-total");
  const highEl = document.getElementById("metric-high");
  const medEl = document.getElementById("metric-medium");
  const lowEl = document.getElementById("metric-low");
  const sigEl = document.getElementById("metric-signatures");

  if (totalEl) totalEl.textContent = summary.total_alerts || 0;
  if (highEl) highEl.textContent = (summary.by_severity && summary.by_severity["High"]) || 0;
  if (medEl) medEl.textContent = (summary.by_severity && summary.by_severity["Medium"]) || 0;
  if (lowEl) lowEl.textContent = (summary.by_severity && summary.by_severity["Low"]) || 0;
  if (sigEl) sigEl.textContent = (summary.by_signature && Object.keys(summary.by_signature).length) || 0;
}

function applyFilters() {
  const searchInput = document.getElementById("search-input");
  const sevFilter = document.getElementById("severity-filter");
  const protoFilter = document.getElementById("proto-filter");

  const query = searchInput ? searchInput.value.trim().toLowerCase() : "";
  const selectedSev = sevFilter ? sevFilter.value : "all";
  const selectedProto = protoFilter ? protoFilter.value : "all";

  currentFilteredAlerts = allAlerts.filter(a => {
    // Severity filter
    if (selectedSev !== "all" && a.severity_label.toLowerCase() !== selectedSev.toLowerCase()) {
      return false;
    }
    // Proto filter
    if (selectedProto !== "all" && a.proto.toLowerCase() !== selectedProto.toLowerCase()) {
      return false;
    }
    // Search query
    if (query) {
      const match = a.signature.toLowerCase().includes(query) ||
                    a.src_ip.toLowerCase().includes(query) ||
                    a.dest_ip.toLowerCase().includes(query) ||
                    a.sid.toString().includes(query) ||
                    (a.category && a.category.toLowerCase().includes(query)) ||
                    (a.payload_snippet && a.payload_snippet.toLowerCase().includes(query));
      if (!match) return false;
    }
    return true;
  });

  renderTable(currentFilteredAlerts);
}

function renderTable(alerts) {
  const tbody = document.getElementById("alerts-tbody");
  if (!tbody) return;

  updateCountTag(alerts.length, allAlerts.length);

  if (alerts.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 2rem; color: var(--text-muted);">
          No alerts match the active search and filter criteria.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = alerts.map((a, idx) => {
    const sevClass = a.severity === 1 ? "sev-high" : a.severity === 2 ? "sev-medium" : "sev-low";
    const tsShort = a.timestamp.slice(0, 19).replace("T", " ");

    return `
      <tr>
        <td class="timestamp-cell">${escapeHtml(tsShort)}</td>
        <td><span class="sev-badge ${sevClass}">${escapeHtml(a.severity_label)}</span></td>
        <td><span class="proto-badge">${escapeHtml(a.proto)}</span></td>
        <td class="ip-cell">${escapeHtml(a.src_ip)}<span style="color:var(--text-muted)">:${a.src_port}</span></td>
        <td class="ip-cell">${escapeHtml(a.dest_ip)}<span style="color:var(--text-muted)">:${a.dest_port}</span></td>
        <td>
          <div class="sig-cell">
            <span class="sid-pill">SID:${a.sid}</span>
            <span class="sig-title">${escapeHtml(a.signature)}</span>
          </div>
        </td>
        <td>
          <button type="button" class="btn btn-sm btn-subtle" onclick="openAlertModal(${idx})">
            Inspect 🔍
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

function updateCountTag(shown, total) {
  const tag = document.getElementById("displayed-count-tag");
  if (tag) tag.textContent = `Showing ${shown} of ${total} alerts`;
}

function renderBreakdown(sigCounts) {
  const listEl = document.getElementById("signatures-breakdown-list");
  if (!listEl) return;

  const entries = Object.entries(sigCounts || {});
  if (entries.length === 0) {
    listEl.innerHTML = `<li style="color: var(--text-muted); font-size: 0.85rem;">No signatures logged.</li>`;
    return;
  }

  entries.sort((a, b) => b[1] - a[1]);
  listEl.innerHTML = entries.map(([sig, count]) => `
    <li class="breakdown-item">
      <span class="breakdown-sig-name" title="${escapeHtml(sig)}">${escapeHtml(sig)}</span>
      <span class="breakdown-count">${count}x</span>
    </li>
  `).join("");
}

function openAlertModal(index) {
  const alert = currentFilteredAlerts[index];
  if (!alert) return;

  const modal = document.getElementById("event-modal");
  const modalBody = document.getElementById("modal-body");
  if (!modal || !modalBody) return;

  const sevClass = alert.severity === 1 ? "sev-high" : alert.severity === 2 ? "sev-medium" : "sev-low";

  modalBody.innerHTML = `
    <div style="display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.5rem;">
      <span class="sev-badge ${sevClass}">${escapeHtml(alert.severity_label)} Severity</span>
      <span class="sid-pill">SID: ${alert.sid} (rev:${alert.rev})</span>
      <span class="proto-badge">${escapeHtml(alert.proto)}</span>
    </div>

    <h4 style="font-size: 1.15rem; font-weight: 700; margin-bottom: 0.5rem;">
      ${escapeHtml(alert.signature)}
    </h4>

    <div style="background-color: var(--bg-surface); padding: 0.85rem; border-radius: var(--radius-sm); font-size: 0.85rem;">
      <div><strong>Classification:</strong> ${escapeHtml(alert.category)}</div>
      <div><strong>Timestamp:</strong> <code>${escapeHtml(alert.timestamp)}</code></div>
      <div><strong>Connection:</strong> <code>${escapeHtml(alert.src_ip)}:${alert.src_port}</code> ➔ <code>${escapeHtml(alert.dest_ip)}:${alert.dest_port}</code></div>
      <div><strong>Flow ID:</strong> <code>${alert.flow_id}</code> | <strong>Packet #:</strong> <code>${alert.pcap_cnt}</code></div>
    </div>

    ${alert.payload_snippet ? `
      <div>
        <label style="font-size: 0.8rem; font-weight: 700; color: var(--text-secondary); text-transform: uppercase;">
          Inspected Payload Snippet:
        </label>
        <pre class="raw-json-block" style="color: #fca5a5;">${escapeHtml(alert.payload_snippet)}</pre>
      </div>
    ` : ''}

    <div>
      <label style="font-size: 0.8rem; font-weight: 700; color: var(--text-secondary); text-transform: uppercase;">
        Triage &amp; Playbook Guidance:
      </label>
      <div class="playbook-callout">
        ${getPlaybookRecommendation(alert.sid, alert.category)}
      </div>
    </div>

    <div>
      <label style="font-size: 0.8rem; font-weight: 700; color: var(--text-secondary); text-transform: uppercase;">
        Raw Alert Object:
      </label>
      <pre class="raw-json-block">${escapeHtml(JSON.stringify(alert, null, 2))}</pre>
    </div>
  `;

  modal.style.display = "flex";
}

function getPlaybookRecommendation(sid, category) {
  switch (sid) {
    case 1000001:
      return "<strong>Telemetry / Test Marker:</strong> Verify whether this was part of an authorized automated QA test or pipeline probe. If unexpected, review requesting host process table.";
    case 1000002:
      return "<strong>Scanner User-Agent:</strong> Inspect web server access logs for rapid requests or directory enumeration. Correlate with firewall logs for possible IP blocking.";
    case 1000003:
    case 1000004:
    case 1000005:
      return "<strong>Reconnaissance Port Sweep (SYN/XMAS/NULL):</strong> Correlate with edge firewall drops. Determine if the source IP is an internal compromised host or external scanning appliance.";
    case 1000006:
      return "<strong>Canary DNS Lookup:</strong> Inspect endpoint DNS resolver logs and process tree to identify which local application queried the canary domain.";
    case 1000007:
      return "<strong>Potential Web Shell Execution (CRITICAL):</strong> Immediately isolate destination web server. Audit web root for recently modified PHP/ASP/JSP files and check auth logs.";
    default:
      return `<strong>${escapeHtml(category)}:</strong> Follow standard SOC triage procedures. Preserve PCAP artifacts and check host endpoint telemetry.`;
  }
}

async function triggerOfflineAnalysis() {
  const runBtn = document.getElementById("run-analysis-btn");
  const emptyRunBtn = document.getElementById("empty-run-btn");

  const originalText = runBtn ? runBtn.textContent : "Run Offline Analysis";
  if (runBtn) {
    runBtn.disabled = true;
    runBtn.textContent = "⏳ Executing Suricata Pipeline...";
  }
  if (emptyRunBtn) {
    emptyRunBtn.disabled = true;
    emptyRunBtn.textContent = "⏳ Executing...";
  }

  try {
    const res = await fetch("/api/run-analysis", { method: "POST" });
    const data = await res.json();
    if (data.status === "success") {
      await loadAlerts();
    } else {
      alert("Analysis failed: " + data.message);
    }
  } catch (err) {
    alert("Error executing analysis: " + err.message);
  } finally {
    if (runBtn) {
      runBtn.disabled = false;
      runBtn.textContent = originalText;
    }
    if (emptyRunBtn) {
      emptyRunBtn.disabled = false;
      emptyRunBtn.textContent = "▶ Generate Lab Traffic & Run Analysis";
    }
  }
}

function escapeHtml(text) {
  if (text === null || text === undefined) return "";
  return text.toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
