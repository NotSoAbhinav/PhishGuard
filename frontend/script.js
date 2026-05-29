// PhishGuard Analytics & ML Controller

// API Base and Key placeholders (replaced during build via replace_api_url.py)
let API_BASE = "__API_BASE__";
let API_KEY = "__API_KEY__";

// Dev Fallbacks for local offline execution
if (API_BASE.startsWith("__") || !API_BASE) {
  API_BASE = "http://127.0.0.1:5000";
}
if (API_KEY.startsWith("__") || !API_KEY) {
  API_KEY = "default-dev-key";
}

// Global Dashboard State
let currentScan = null;
let sensitivityThreshold = 50;
let sessionCounts = { safe: 0, phishing: 0 };
let threatChartInstance = null;
let isInspectorExpanded = false;

// 1. Initialize Dashboard on Load
document.addEventListener("DOMContentLoaded", () => {
  initChart();
  verifyApiHealth();
  updateThresholdDisplay(50);
});

// 2. Verify API Health and Fetch Version / Metrics
async function verifyApiHealth() {
  const statusIndicator = document.getElementById("statusIndicator");
  const modelVerBadge = document.getElementById("modelVerBadge");

  try {
    const res = await fetch(`${API_BASE}/`, {
      method: "GET",
      headers: { "X-API-Key": API_KEY }
    });

    if (res.ok) {
      const data = await res.json();
      statusIndicator.className = "status-indicator online";
      statusIndicator.querySelector(".status-text").innerText = "API Online";
      modelVerBadge.innerText = `v${data.model_version}`;
      
      // Load general statistics and history feed
      fetchGlobalStats();
      fetchHistory();
    } else {
      throw new Error("API responded with error");
    }
  } catch (error) {
    console.error("API Connection Error:", error);
    statusIndicator.className = "status-indicator offline";
    statusIndicator.querySelector(".status-text").innerText = "API Offline (Cold Start)";
    showToast("API server is offline or spinning up. Please wait...", "⚠️", 5000);
  }
}

// 3. Fetch Global Stats
async function fetchGlobalStats() {
  try {
    const res = await fetch(`${API_BASE}/stats`, {
      method: "GET",
      headers: {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
      }
    });

    if (res.ok) {
      const stats = await res.json();
      document.getElementById("statTotalScans").innerText = stats.total_scans;
      document.getElementById("statThreatRate").innerText = `${stats.threat_rate}%`;
      document.getElementById("statCacheHits").innerText = `${stats.cache_hit_rate}%`;
      document.getElementById("statAccuracy").innerText = `${stats.cv_accuracy}%`;
      document.getElementById("modelVerBadge").innerText = `v${stats.model_version}`;
    }
  } catch (err) {
    console.error("Failed to load global statistics:", err);
  }
}

// 4. Initialize Chart.js Doughnut Chart
function initChart() {
  const ctx = document.getElementById("threatChart");
  if (!ctx) return;

  threatChartInstance = new Chart(ctx.getContext("2d"), {
    type: "doughnut",
    data: {
      labels: ["Safe Links", "Threats"],
      datasets: [{
        data: [0, 0],
        backgroundColor: [
          "rgba(16, 185, 129, 0.15)", // Green glow
          "rgba(239, 68, 68, 0.15)"   // Red glow
        ],
        borderColor: [
          "#10b981", // Emerald
          "#ef4444"  // Rose
        ],
        borderWidth: 1.5,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "#e2e8f0",
            font: { family: "'Outfit', sans-serif", size: 12 },
            boxWidth: 12,
            padding: 15
          }
        },
        tooltip: {
          backgroundColor: "rgba(15, 23, 42, 0.9)",
          titleFont: { family: "'Outfit', sans-serif" },
          bodyFont: { family: "'Outfit', sans-serif" },
          borderWidth: 1,
          borderColor: "rgba(255, 255, 255, 0.1)"
        }
      },
      cutout: "75%"
    }
  });
}

// Update local session chart distribution
function updateChartDistribution() {
  if (threatChartInstance) {
    threatChartInstance.data.datasets[0].data = [sessionCounts.safe, sessionCounts.phishing];
    threatChartInstance.update();
  }
}

// 5. Analyze URL Handler
async function analyzeURL() {
  const urlInput = document.getElementById("urlInput");
  const scanButton = document.getElementById("scanButton");
  const btnSpinner = document.getElementById("btnSpinner");
  const validationError = document.getElementById("validationError");
  const url = urlInput.value.trim();

  // Reset validation state
  validationError.classList.add("hidden");
  validationError.innerText = "";

  if (!url) {
    validationError.innerText = "Please enter a target URL to scan.";
    validationError.classList.remove("hidden");
    return;
  }

  // URL Scheme check
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    validationError.innerText = "Please enter a valid URL including scheme (e.g. https://google.com).";
    validationError.classList.remove("hidden");
    return;
  }

  // Loading state
  scanButton.disabled = true;
  btnSpinner.classList.remove("hidden");

  // Show radial gauge in auditing state during API request
  const gaugePlaceholder = document.getElementById("gaugePlaceholder");
  const gaugeSection = document.getElementById("gaugeSection");
  const radialGauge = document.querySelector(".radial-gauge");
  const riskPercent = document.getElementById("riskPercent");
  const riskLevel = document.getElementById("riskLevel");

  if (gaugePlaceholder && gaugeSection && radialGauge && riskPercent && riskLevel) {
    gaugePlaceholder.classList.add("hidden");
    gaugeSection.classList.remove("hidden");
    radialGauge.classList.add("scanning");
    riskPercent.innerText = "---";
    riskLevel.innerText = "AUDITING";
    riskLevel.style.color = "var(--primary)";
  }

  try {
    const response = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      const errData = await response.json();
      throw new Error(errData.error || "Analysis failed");
    }

    const data = await response.json();
    currentScan = data;

    // Trigger UI updates
    renderScanResult();

    // Check if result is cached to trigger notification
    if (data.cached) {
      showToast("Result loaded from local cache", "⚡");
    } else {
      showToast("Analysis complete. Threat profile updated.", "🛡️");
    }

    // Refresh metrics counters and history
    fetchGlobalStats();
    fetchHistory();

  } catch (error) {
    console.error("Analysis failed:", error);
    showToast(error.message || "Failed to contact API backend.", "❌");
    validationError.innerText = error.message || "Failed to contact API backend.";
    validationError.classList.remove("hidden");
    
    // Restore placeholder if there's no previous scan result
    if (!currentScan && gaugePlaceholder && gaugeSection) {
      gaugePlaceholder.classList.remove("hidden");
      gaugeSection.classList.add("hidden");
    }
  } finally {
    scanButton.disabled = false;
    btnSpinner.classList.add("hidden");
    const radialGauge = document.querySelector(".radial-gauge");
    if (radialGauge) {
      radialGauge.classList.remove("scanning");
    }
  }
}

// 6. Draw Dashboard Scan Result Indicators
function renderScanResult() {
  if (!currentScan) return;

  const gaugePlaceholder = document.getElementById("gaugePlaceholder");
  const gaugeSection = document.getElementById("gaugeSection");
  const riskPercent = document.getElementById("riskPercent");
  const riskLevel = document.getElementById("riskLevel");
  const gaugeMeter = document.getElementById("gaugeMeter");
  const classBadge = document.getElementById("classBadge");
  const badgeIcon = document.getElementById("badgeIcon");
  const badgeText = document.getElementById("badgeText");
  const confidenceVal = document.getElementById("confidenceVal");
  
  // Scanned Host URL display
  const parsedUrl = new URL(currentScan.url);
  document.getElementById("scannedUrlCode").innerText = parsedUrl.hostname || currentScan.url;
  document.getElementById("urlDisplaySection").classList.remove("hidden");
  document.getElementById("insightsPlaceholder").classList.add("hidden");

  // Show radial gauge
  gaugePlaceholder.classList.add("hidden");
  gaugeSection.classList.remove("hidden");

  // Animate Gauge percentage
  const score = currentScan.risk_score;
  riskPercent.innerText = `${score}%`;

  // Circle circumference is 314.16 (Radius = 50)
  const offset = 314.16 - (314.16 * score) / 100;
  gaugeMeter.style.strokeDashoffset = offset;

  // Determine classification based on slider threshold
  const classification = score >= sensitivityThreshold ? "phishing" : "safe";

  // Stylize Gauge colors and labels based on score relative to threshold
  if (classification === "phishing") {
    riskMeterColor("#ef4444"); // Red
    riskLevel.innerText = "CRITICAL";
    riskLevel.style.color = "#ef4444";
    classBadge.className = "classification-badge phish-badge";
    badgeIcon.innerText = "❌";
    badgeText.innerText = "Phishing threat";
  } else if (score > sensitivityThreshold - 15) {
    riskMeterColor("#f59e0b"); // Orange/Warning
    riskLevel.innerText = "SUSPICIOUS";
    riskLevel.style.color = "#f59e0b";
    classBadge.className = "classification-badge susp-badge";
    badgeIcon.innerText = "⚠️";
    badgeText.innerText = "Suspicious Link";
  } else {
    riskMeterColor("#10b981"); // Green
    riskLevel.innerText = "SECURE";
    riskLevel.style.color = "#10b981";
    classBadge.className = "classification-badge safe-badge";
    badgeIcon.innerText = "✅";
    badgeText.innerText = "Safe Link";
  }

  // Set AI Confidence level
  confidenceVal.innerText = currentScan.confidence;
  confidenceVal.className = currentScan.confidence.toLowerCase();

  // Populate Insights list
  populateHeuristics(currentScan.reasons, classification);

  // Populate Feature Table
  populateFeaturesTable(currentScan.features_breakdown);
}

function riskMeterColor(colorCode) {
  const gaugeMeter = document.getElementById("gaugeMeter");
  gaugeMeter.style.stroke = colorCode;
  // Apply visual shadow filter dynamically
  gaugeMeter.style.filter = `drop-shadow(0 0 6px ${colorCode})`;
}

// 7. Update Threshold Display and Trigger Recalculation
function updateSensitivity(val) {
  sensitivityThreshold = parseInt(val);
  updateThresholdDisplay(sensitivityThreshold);

  // Re-run classification locally without calling API
  if (currentScan) {
    renderScanResult();
    showToast(`Threshold updated to ${sensitivityThreshold}%`, "⚙️", 1500);
  }
}

function updateThresholdDisplay(val) {
  document.getElementById("thresholdVal").innerText = `${val}%`;

  const desc = document.getElementById("thresholdDesc");
  const dot = document.getElementById("policyDot");

  if (!desc || !dot) return;

  if (val >= 20 && val < 40) {
    desc.innerText = "Strict Mode: Flags minor anomalies. High security footprint, but increases the probability of false alarms.";
    dot.style.background = "#ef4444"; // Red
    dot.style.boxShadow = "0 0 10px #ef4444";
  } else if (val >= 40 && val <= 65) {
    desc.innerText = "Balanced Mode: Standard corporate filter. Optimal trade-off between threat detection and false alarm accuracy.";
    dot.style.background = "#3b82f6"; // Blue
    dot.style.boxShadow = "0 0 10px rgba(59, 130, 246, 0.8)";
  } else {
    desc.innerText = "Permissive Mode: Flags only high-confidence threats. Minimal false alarms, but may miss stealthy or obfuscated links.";
    dot.style.background = "#f59e0b"; // Orange/Yellow
    dot.style.boxShadow = "0 0 10px #f59e0b";
  }
}

// 8. Populate Heuristic Audit Cards
function populateHeuristics(reasons, classification) {
  const container = document.getElementById("insightsContainer");
  container.innerHTML = "";
  container.classList.remove("hidden");

  if (!reasons || reasons.length === 0) {
    container.innerHTML = `
      <div class="insight-card info">
        <span class="insight-icon">ℹ️</span>
        <div class="insight-details">
          <h4>No Threats Found</h4>
          <p>This URL matches no common phishing heuristics or heuristics parameters.</p>
        </div>
      </div>
    `;
    return;
  }

  reasons.forEach(reason => {
    const severity = reason.severity.toLowerCase(); // critical, warning, info
    const div = document.createElement("div");
    div.className = `insight-card ${severity}`;

    let icon = "ℹ️";
    if (severity === "critical") icon = "🚨";
    else if (severity === "warning") icon = "⚠️";

    div.innerHTML = `
      <span class="insight-icon">${icon}</span>
      <div class="insight-details">
        <h4>${reason.severity.toUpperCase()} ALERT</h4>
        <p>${reason.message}</p>
      </div>
    `;
    container.appendChild(div);
  });
}

// 9. Populate Features Table
function populateFeaturesTable(breakdown) {
  const tableBody = document.getElementById("featuresTableBody");
  const placeholder = document.getElementById("inspectorTablePlaceholder");
  const table = document.getElementById("featuresTable");

  tableBody.innerHTML = "";
  placeholder.classList.add("hidden");
  table.classList.remove("hidden");

  breakdown.forEach(feature => {
    const row = document.createElement("tr");

    let statusClass = "badge-safe";
    if (feature.status === "Critical") statusClass = "badge-danger";
    else if (feature.status === "Warning") statusClass = "badge-warning";
    else if (feature.status === "Info") statusClass = "badge-info";

    row.innerHTML = `
      <td>${feature.name}</td>
      <td class="raw-value">${feature.value}</td>
      <td><span class="table-badge ${statusClass}">${feature.status}</span></td>
    `;
    tableBody.appendChild(row);
  });
}

// 10. Toggle Features Table expand/collapse
function toggleInspectorTable() {
  const wrapper = document.getElementById("inspectorTableWrapper");
  const arrow = document.getElementById("inspectorToggleArrow");
  
  isInspectorExpanded = !isInspectorExpanded;
  if (isInspectorExpanded) {
    wrapper.classList.remove("collapsed");
    arrow.style.transform = "rotate(180deg)";
  } else {
    wrapper.classList.add("collapsed");
    arrow.style.transform = "rotate(0deg)";
  }
}

// 11. Interactive Feedback submission
function showFeedbackCorrectionModal() {
  if (!currentScan) return;
  const modal = document.getElementById("feedbackModal");
  document.getElementById("modalUrlText").innerText = currentScan.url;
  modal.classList.remove("hidden");
}

function closeFeedbackCorrectionModal() {
  document.getElementById("feedbackModal").classList.add("hidden");
}

async function submitFeedback(label) {
  if (!currentScan) return;
  
  // Close correction modal if open
  closeFeedbackCorrectionModal();

  showToast("Submitting feedback and evolving the model...", "🧠");

  try {
    const response = await fetch(`${API_BASE}/feedback`, {
      method: "POST",
      headers: {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        url: currentScan.url,
        label: label
      })
    });

    if (response.ok) {
      const result = await response.json();
      showToast(`Feedback recorded! Retraining to version ${result.target_version}...`, "🔄", 4500);

      // Brief delay to allow training to complete, then reload stats
      setTimeout(() => {
        verifyApiHealth();
      }, 2500);

    } else {
      throw new Error("Failed to record feedback");
    }
  } catch (err) {
    console.error(err);
    showToast("Failed to submit feedback. Check API key/logs.", "❌");
  }
}

// 12. History Feeds (Synced from Server)
let sessionHistory = [];

async function fetchHistory() {
  try {
    const res = await fetch(`${API_BASE}/history`, {
      method: "GET",
      headers: { 
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
      }
    });

    if (res.ok) {
      const data = await res.json();
      // Map backend history (contains array of { url, result, risk_score })
      sessionHistory = data.map(item => ({
        url: item.url,
        result: item.result,
        risk_score: item.risk_score,
        timestamp: "Recent"
      })).reverse(); // Reverse so latest scans are at the top

      // Rebuild counts
      sessionCounts = { safe: 0, phishing: 0 };
      sessionHistory.forEach(item => {
        if (item.result === "phishing") sessionCounts.phishing++;
        else sessionCounts.safe++;
      });

      updateChartDistribution();
      renderHistoryList();
    }
  } catch (err) {
    console.error("Failed to fetch history:", err);
  }
}

function renderHistoryList() {
  const list = document.getElementById("historyList");
  const countBadge = document.getElementById("historyCount");

  list.innerHTML = "";
  countBadge.innerText = `${sessionHistory.length} Scans Cached`;

  if (sessionHistory.length === 0) {
    list.innerHTML = `<div class="history-empty">No URLs analyzed in this session yet.</div>`;
    return;
  }

  sessionHistory.forEach(item => {
    const div = document.createElement("div");
    div.className = "history-item";

    const isPhish = item.result === "phishing";
    const statusClass = isPhish ? "danger" : "success";
    const statusText = isPhish ? "Phishing" : "Safe";

    // Hostname extract
    let host = item.url;
    try {
      host = new URL(item.url).hostname;
    } catch(e) {}

    div.innerHTML = `
      <div class="history-info">
        <span class="history-url" title="${item.url}">${host}</span>
        <span class="history-time">${item.timestamp}</span>
      </div>
      <div class="history-badge-area">
        <span class="history-badge ${statusClass}">${statusText}</span>
        <span class="history-score">${item.risk_score}%</span>
      </div>
    `;

    // Make row clickable to reload details
    div.addEventListener("click", () => {
      document.getElementById("urlInput").value = item.url;
      analyzeURL();
    });

    list.appendChild(div);
  });
}

// 13. Custom Slide-in Toast Banner Notification
function showToast(message, icon = "✨", duration = 3500) {
  const toast = document.getElementById("toastNotification");
  const toastIcon = document.getElementById("toastIcon");
  const toastMsg = document.getElementById("toastMessage");

  if (!toast || !toastIcon || !toastMsg) return;

  toastIcon.innerText = icon;
  toastMsg.innerText = message;

  // Clear hidden state and active class
  toast.classList.remove("hidden");
  toast.classList.add("visible");

  // Automatic slide out
  setTimeout(() => {
    toast.classList.remove("visible");
    toast.classList.add("hidden");
  }, duration);
}