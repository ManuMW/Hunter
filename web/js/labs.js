/**
 * Hunter Security Labs - Interactive Engine
 * Inspired by Elastic Security Labs (https://www.elastic.co/security-labs)
 * Two core responsibilities:
 * 1. Accept SHA-256 hash submissions
 * 2. Present clean threat intelligence reports
 */

let currentCategory = "ALL";
let isAnalyzing = false;
let activePollingInterval = null;

// Configurable Detonation Host API URL (local dev or cloud VM via tunnel)
const API_BASE_URL = window.HUNTER_API_URL || (
    window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
        ? "http://localhost:8000"
        : ""
);

document.addEventListener("DOMContentLoaded", () => {
    initFilters();
    initHashInput();
    renderReports();
});

// Category filtering
function initFilters() {
    const filterButtons = document.querySelectorAll("#categoryFilters .filter-pill");
    filterButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            filterButtons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentCategory = btn.getAttribute("data-category");
            renderReports();
        });
    });
}

// Hash input field behaviors
function initHashInput() {
    const input = document.getElementById("quickHashInput");
    const btnClear = document.getElementById("btnClearHash");

    if (!input) return;

    input.addEventListener("input", () => {
        if (btnClear) {
            btnClear.style.display = input.value.trim().length > 0 ? "block" : "none";
        }
    });

    input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            handleHashSubmit();
        }
    });
}

function clearHashInput() {
    const input = document.getElementById("quickHashInput");
    const btnClear = document.getElementById("btnClearHash");
    if (input) {
        input.value = "";
        input.focus();
    }
    if (btnClear) {
        btnClear.style.display = "none";
    }
}

function fillSample(hash) {
    const input = document.getElementById("quickHashInput");
    const btnClear = document.getElementById("btnClearHash");
    if (input) {
        input.value = hash;
    }
    if (btnClear) {
        btnClear.style.display = "block";
    }
    handleHashSubmit();
}

// Render reports list
function renderReports() {
    const grid = document.getElementById("reportsGrid");
    if (!grid) return;

    if (typeof THREAT_REPORTS === "undefined" || !Array.isArray(THREAT_REPORTS)) {
        grid.innerHTML = `<p style="grid-column: 1 / -1; text-align: center; color: var(--text-muted); padding: 40px;">No reports available.</p>`;
        return;
    }

    const filtered = THREAT_REPORTS.filter(report => {
        if (currentCategory === "ALL") return true;
        return (report.category && report.category.toUpperCase() === currentCategory) ||
               (report.tags && report.tags.some(t => t.toUpperCase() === currentCategory));
    });

    if (filtered.length === 0) {
        grid.innerHTML = `
            <div style="grid-column: 1 / -1; text-align: center; padding: 40px 20px; color: var(--text-muted);">
                <p style="font-weight: 600; color: var(--text-title); margin-bottom: 4px;">No threat reports found in this category</p>
                <p style="font-size: 13px;">Select another category or view all reports.</p>
            </div>
        `;
        return;
    }

    grid.innerHTML = filtered.map(report => {
        const hash = report.sha256 || "";
        const shortHash = hash.length > 16 
            ? hash.substring(0, 10) + "..." + hash.substring(hash.length - 8)
            : hash;

        return `
            <article class="report-card" onclick="openReportModal('${report.id}')">
                <div class="card-tag-row">
                    <span class="card-pill">${escapeHtml(report.family || report.category || "THREAT")}</span>
                    <span class="card-date">${escapeHtml(report.date || "")}</span>
                </div>
                <h3 class="card-title">${escapeHtml(report.title)}</h3>
                <p class="card-summary">${escapeHtml((report.summary || "").substring(0, 150))}...</p>
                <div class="card-hash-row" onclick="event.stopPropagation()">
                    <span class="hash-text" title="${escapeHtml(hash)}">${shortHash}</span>
                    <button class="btn-copy" title="Copy SHA-256" onclick="copyToClipboard('${escapeHtml(hash)}', 'SHA-256 copied!')">📋</button>
                </div>
                <div class="card-cta">
                    <span>View Threat Report</span>
                    <span>&rarr;</span>
                </div>
            </article>
        `;
    }).join("");
}

// 1. Accepting Hash: Handle submission
async function handleHashSubmit() {
    if (isAnalyzing) return;

    const input = document.getElementById("quickHashInput");
    const hash = input ? input.value.trim().toLowerCase() : "";

    if (!hash) {
        showToast("Please enter a SHA-256 hash");
        if (input) input.focus();
        return;
    }

    if (!/^[a-f0-9]{64}$/.test(hash)) {
        showToast("Invalid format. Please enter a 64-character SHA-256 hex string.");
        if (input) input.focus();
        return;
    }

    // Check if report already exists in the catalog
    const existing = (typeof THREAT_REPORTS !== "undefined" && Array.isArray(THREAT_REPORTS))
        ? THREAT_REPORTS.find(r => r.sha256.toLowerCase() === hash || r.id.toLowerCase() === hash)
        : null;

    if (existing) {
        openReportModal(existing.id);
        return;
    }

    // Check if Detonation Host API endpoint is configured
    if (!API_BASE_URL) {
        showCloudQueueModal(hash, true);
        return;
    }

    // Submit live to Detonation Host API with dynamic real-time polling
    await submitToDetonationApi(hash);
}

async function submitToDetonationApi(hash) {
    isAnalyzing = true;
    const btnAnalyze = document.getElementById("btnAnalyze");
    if (btnAnalyze) {
        btnAnalyze.disabled = true;
        btnAnalyze.textContent = "Connecting...";
    }

    showDynamicProgressModal(hash);

    try {
        const response = await fetch(`${API_BASE_URL}/api/submit-hash`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ sha256: hash })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.detail || `Server returned HTTP ${response.status}`);
        }

        const data = await response.json();

        // If report was already cached on server
        if (data.status === "cached" && data.report_url) {
            await fetchAndDisplayReport(hash);
            return;
        }

        if (data.task_id) {
            updateStepState("step-1", "done");
            updateStepState("step-2", "active");
            startTaskPolling(data.task_id, hash);
        } else {
            throw new Error(data.message || "Invalid response from Detonation API");
        }

    } catch (err) {
        console.warn("Detonation API unreachable or error:", err);
        closeStatusModal();
        showCloudQueueModal(hash, true, err.message);
    } finally {
        if (btnAnalyze) {
            btnAnalyze.disabled = false;
            btnAnalyze.textContent = "Analyze Hash";
        }
        isAnalyzing = false;
    }
}

function startTaskPolling(taskId, hash) {
    if (activePollingInterval) {
        clearInterval(activePollingInterval);
    }

    const poll = async () => {
        try {
            const res = await fetch(`${API_BASE_URL}/api/tasks/${taskId}`);
            if (!res.ok) return;

            const task = await res.json();
            handleTaskStateUpdate(task, hash);

            if (task.status === "completed" || task.status === "failed") {
                clearInterval(activePollingInterval);
                activePollingInterval = null;
            }
        } catch (e) {
            console.error("Task polling error:", e);
        }
    };

    activePollingInterval = setInterval(poll, 2000);
    poll(); // Run initial poll immediately
}

function handleTaskStateUpdate(task, hash) {
    const statusText = document.getElementById("statusHashDisplay");
    if (statusText) {
        statusText.textContent = `Task ID: ${task.task_id.substring(0, 8)}... | Status: ${task.status.toUpperCase()}`;
    }

    if (task.status === "queued") {
        updateStepState("step-1", "active");
    } else if (task.status === "detonating") {
        updateStepState("step-1", "done");
        updateStepState("step-2", "active");
    } else if (task.status === "extracting_artifacts") {
        updateStepState("step-1", "done");
        updateStepState("step-2", "done");
        updateStepState("step-3", "active");
    } else if (task.status === "analyzing" || task.status === "generating_report") {
        updateStepState("step-1", "done");
        updateStepState("step-2", "done");
        updateStepState("step-3", "done");
        updateStepState("step-4", "active");
    } else if (task.status === "completed") {
        updateStepState("step-1", "done");
        updateStepState("step-2", "done");
        updateStepState("step-3", "done");
        updateStepState("step-4", "done");

        setTimeout(async () => {
            closeStatusModal();
            await fetchAndDisplayReport(hash);
            showToast("Detonation and analysis complete!");
        }, 800);
    } else if (task.status === "failed") {
        clearInterval(activePollingInterval);
        activePollingInterval = null;
        alert(`Analysis failed on Detonation Host: ${task.error || "Unknown error"}`);
        closeStatusModal();
    }
}

function updateStepState(stepId, state) {
    const el = document.getElementById(stepId);
    if (!el) return;
    el.className = `status-step ${state}`;
}

async function fetchAndDisplayReport(hash) {
    try {
        const res = await fetch(`${API_BASE_URL}/api/reports/${hash}?format=json`);
        if (res.ok) {
            const reportData = await res.json();
            if (reportData && !THREAT_REPORTS.some(r => r.sha256 === hash)) {
                THREAT_REPORTS.unshift(reportData);
                renderReports();
            }
            openReportModal(hash);
            return;
        }
    } catch (e) {
        console.error("Failed to fetch generated report JSON:", e);
    }
    openReportModal(hash);
}

function showDynamicProgressModal(hash) {
    const statusModal = document.getElementById("statusModalBackdrop");
    const hashDisplay = document.getElementById("statusHashDisplay");
    if (hashDisplay) {
        hashDisplay.textContent = `Connecting to Detonation Host for ${hash.substring(0, 16)}...`;
    }

    const stepIds = ["step-1", "step-2", "step-3", "step-4"];
    stepIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.className = "status-step";
    });
    updateStepState("step-1", "active");

    if (statusModal) {
        statusModal.classList.add("active");
        document.body.style.overflow = "hidden";
    }
}

function showCloudQueueModal(hash, isOfflineError = true, errorMsg = "") {
    const modalBackdrop = document.getElementById("reportModalBackdrop");
    const modalBadge = document.getElementById("modalBadge");
    const modalContent = document.getElementById("modalContent");

    if (modalBadge) {
        modalBadge.textContent = "DETONATION HOST OFFLINE";
    }

    modalContent.innerHTML = `
        <h1 class="report-headline">Detonation Host Offline &middot; Sample Uncataloged</h1>
        
        <div class="report-meta-grid">
            <div>
                <span class="meta-field-label">SUBMITTED SHA-256</span>
                <span class="meta-field-value">${escapeHtml(hash)}</span>
            </div>
            <div>
                <span class="meta-field-label">BACKEND STATUS</span>
                <span class="meta-field-value" style="color: #dc2626; font-weight: 700;">OFFLINE (STANDBY)</span>
            </div>
            <div>
                <span class="meta-field-label">DYNAMIC TARGET</span>
                <span class="meta-field-value">GCP Compute Host (Option B)</span>
            </div>
        </div>

        <h3 class="report-h3">Why didn't this sample analyze?</h3>
        <p class="report-para">
            This public GitHub Pages portal is a client-side static site that showcases verified threat intelligence reports. Dynamic 90-second air-gapped malware execution requires a live backend host (Option B on GCP Compute Engine) to download, isolate, and detonate untrusted binaries. No active backend is currently connected to this web page.
        </p>
        
        <h3 class="report-h3">How to Analyze This Sample</h3>
        <ol style="margin-left: 20px; font-size: 14px; line-height: 1.8; color: var(--text-body); margin-bottom: 20px;">
            <li><strong>Analyze via Local Terminal</strong>: You can execute the Hunter CLI pipeline directly:
                <div style="background: var(--bg-subtle); padding: 8px 12px; border-radius: 4px; font-family: var(--font-mono); font-size: 12px; margin: 6px 0; border: 1px solid var(--border);">
                    python -m src.cli analyze ${escapeHtml(hash)}
                </div>
            </li>
            <li><strong>Deploy Cloud Detonation Host</strong>: Run <code>deploy/provision_gcp_detonation_host.sh</code> on your GCP Compute Engine VM and point <code>window.HUNTER_API_URL</code> to its endpoint.</li>
            <li><strong>Explore Cataloged Reports</strong>: In the meantime, browse the verified threat reports published below in the catalog.</li>
        </ol>

        <div style="margin-top: 24px; display: flex; justify-content: flex-end; gap: 10px;">
            <button class="btn-submit" onclick="closeReportModal()">Got it</button>
        </div>
    `;

    if (modalBackdrop) {
        modalBackdrop.classList.add("active");
        document.body.style.overflow = "hidden";
    }
}

// 2. Presenting Reports: Open Modal
function openReportModal(reportId) {
    if (typeof THREAT_REPORTS === "undefined") return;

    const report = THREAT_REPORTS.find(r => r.id === reportId || r.sha256 === reportId);
    if (!report) return;

    const modalBackdrop = document.getElementById("reportModalBackdrop");
    const modalBadge = document.getElementById("modalBadge");
    const modalContent = document.getElementById("modalContent");

    if (modalBadge) {
        modalBadge.textContent = `${(report.family || report.category || "REPORT").toUpperCase()} \u00B7 ${report.severity || "INFO"} SEVERITY`;
    }

    // Process hierarchy
    const treeLines = (report.behavior && report.behavior.processTree) ? report.behavior.processTree : [];
    const processTreeHtml = treeLines.length > 0
        ? `<div class="code-box">
             <button class="btn-code-copy" onclick="copyToClipboard(decodeURIComponent('${encodeURIComponent(treeLines.join('\n'))}'), 'Process tree copied!')">Copy</button>
             <pre>${escapeHtml(treeLines.join('\n'))}</pre>
           </div>`
        : `<p class="report-para" style="color: var(--text-muted);">No auxiliary child processes spawned during analysis.</p>`;

    // Dropped files
    const payloads = (report.behavior && report.behavior.droppedPayloads) ? report.behavior.droppedPayloads : [];
    const droppedHtml = payloads.length > 0
        ? payloads.map(p => `
            <div style="background: var(--bg-subtle); border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                    <strong style="color: var(--elastic-teal); font-family: var(--font-mono); font-size: 13px;">${escapeHtml(p.path)}</strong>
                    <span style="font-size: 11px; color: var(--text-muted);">${escapeHtml(p.size || "")}</span>
                </div>
                <p style="font-size: 12px; color: var(--text-body); margin-bottom: 6px;">${escapeHtml(p.magic || "")}</p>
                ${p.strings && p.strings.length > 0 ? `
                    <div style="font-size: 11px; font-family: var(--font-mono); color: #0369a1; background: #ffffff; border: 1px solid var(--border); padding: 6px 10px; border-radius: 4px;">
                        ${p.strings.map(s => `<div>+ ${escapeHtml(s)}</div>`).join("")}
                    </div>
                ` : ''}
            </div>
          `).join("")
        : `<p class="report-para" style="color: var(--text-muted);">No secondary binary payloads dropped to disk.</p>`;

    // IoC table rows
    const iocList = report.iocs || [];
    const iocRows = iocList.map(ioc => `
        <tr>
            <td style="font-weight: 600;">${escapeHtml(ioc.type)}</td>
            <td><code>${escapeHtml(ioc.value)}</code></td>
            <td>${escapeHtml(ioc.description)}</td>
            <td style="text-align: right; white-space: nowrap;">
                <button class="btn-copy" onclick="copyToClipboard('${escapeHtml(ioc.value)}', 'Copied IoC!')">Copy</button>
            </td>
        </tr>
    `).join("");

    // MITRE badges
    const mitreList = report.mitre || [];
    const mitreBadges = mitreList.map(m => `
        <span class="mitre-badge">
            <strong>${escapeHtml(m.id)}</strong> (${escapeHtml(m.tactic)}): ${escapeHtml(m.name)}
        </span>
    `).join("");

    modalContent.innerHTML = `
        <h1 class="report-headline">${escapeHtml(report.title)}</h1>
        
        <div class="report-meta-grid">
            <div>
                <span class="meta-field-label">SAMPLE SHA-256</span>
                <span class="meta-field-value">${escapeHtml(report.sha256)}</span>
            </div>
            <div>
                <span class="meta-field-label">DATE PUBLISHED</span>
                <span class="meta-field-value" style="font-family: var(--font-sans);">${escapeHtml(report.date || "2026-09-13")}</span>
            </div>
            <div>
                <span class="meta-field-label">SEVERITY SCORE</span>
                <span class="meta-field-value" style="font-family: var(--font-sans); color: #b91c1c; font-weight: 700;">${escapeHtml(report.severityScore || report.severity || "HIGH")}</span>
            </div>
        </div>

        <h3 class="report-h3">Executive Summary</h3>
        <p class="report-para">${escapeHtml(report.summary)}</p>

        ${mitreBadges ? `
            <h3 class="report-h3">MITRE ATT&amp;CK Mapping</h3>
            <div style="margin-bottom: 16px;">${mitreBadges}</div>
        ` : ''}

        <h3 class="report-h3">Process Hierarchy</h3>
        ${processTreeHtml}

        <h3 class="report-h3">Extracted Payloads &amp; Artifacts</h3>
        ${droppedHtml}

        <h3 class="report-h3">Indicators of Compromise (IoCs)</h3>
        <div style="overflow-x: auto;">
            <table class="report-table">
                <thead>
                    <tr>
                        <th style="width: 22%;">Type</th>
                        <th style="width: 38%;">Indicator (Defanged)</th>
                        <th>Description</th>
                        <th style="width: 60px; text-align: right;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${iocRows}
                </tbody>
            </table>
        </div>

        ${report.yaraRule ? `
            <h3 class="report-h3">YARA Signature</h3>
            <div class="code-box">
                <button class="btn-code-copy" onclick="copyToClipboard(decodeURIComponent('${encodeURIComponent(report.yaraRule)}'), 'YARA rule copied!')">Copy YARA</button>
                <pre><code>${escapeHtml(report.yaraRule)}</code></pre>
            </div>
        ` : ''}
    `;

    if (modalBackdrop) {
        modalBackdrop.classList.add("active");
        document.body.style.overflow = "hidden";
    }
}

function closeReportModal(e) {
    if (e && e.target !== e.currentTarget) return;
    const modalBackdrop = document.getElementById("reportModalBackdrop");
    if (modalBackdrop) {
        modalBackdrop.classList.remove("active");
    }
    document.body.style.overflow = "auto";
}

function closeStatusModal(e) {
    if (e && e.target !== e.currentTarget) return;
    if (activePollingInterval) {
        clearInterval(activePollingInterval);
        activePollingInterval = null;
    }
    const statusModal = document.getElementById("statusModalBackdrop");
    if (statusModal) {
        statusModal.classList.remove("active");
    }
    document.body.style.overflow = "auto";
}

// Clipboard helper
function copyToClipboard(text, message = "Copied to clipboard!") {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => showToast(message)).catch(() => fallbackCopy(text, message));
    } else {
        fallbackCopy(text, message);
    }
}

function fallbackCopy(text, message) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-999999px";
    document.body.appendChild(textArea);
    textArea.select();
    try {
        document.execCommand("copy");
        showToast(message);
    } catch (err) {
        console.error("Copy failed", err);
    }
    document.body.removeChild(textArea);
}

// Toast notification
function showToast(message) {
    const toast = document.getElementById("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("show");
    setTimeout(() => {
        toast.classList.remove("show");
    }, 2500);
}

// Utilities
function escapeHtml(text) {
    if (!text) return "";
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.toString().replace(/[&<>"']/g, m => map[m]);
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
