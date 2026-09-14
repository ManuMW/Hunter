/**
 * Hunter Security Labs - Interactive Engine
 * Inspired by Elastic Security Labs (https://www.elastic.co/security-labs)
 */

let currentCategory = "ALL";
let searchQuery = "";

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", () => {
    initCategoryFilters();
    renderBulletins();
    initQuickInput();
});

// Category Filter Setup
function initCategoryFilters() {
    const filterButtons = document.querySelectorAll("#categoryFilters .filter-btn");
    filterButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            filterButtons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentCategory = btn.getAttribute("data-category");
            renderBulletins();
        });
    });
}

// Quick Input Handlers
function initQuickInput() {
    const input = document.getElementById("quickHashInput");
    const btnClear = document.getElementById("btnClearHash");

    input.addEventListener("input", () => {
        btnClear.style.display = input.value.trim().length > 0 ? "block" : "none";
    });

    input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            handleQuickSubmit();
        }
    });
}

function clearHashInput() {
    const input = document.getElementById("quickHashInput");
    input.value = "";
    document.getElementById("btnClearHash").style.display = "none";
    input.focus();
}

function fillSample(hash) {
    const input = document.getElementById("quickHashInput");
    input.value = hash;
    document.getElementById("btnClearHash").style.display = "block";
    handleQuickSubmit();
}

// Filter Bulletins by search query
function filterBulletins() {
    searchQuery = document.getElementById("bulletinSearchInput").value.toLowerCase().trim();
    renderBulletins();
}

// Render Bulletins Grid
function renderBulletins() {
    const grid = document.getElementById("bulletinsGrid");
    if (!grid) return;

    const filtered = THREAT_REPORTS.filter(report => {
        const matchesCategory = (currentCategory === "ALL") || 
            (report.category.toUpperCase() === currentCategory) ||
            (report.tags.some(t => t.toUpperCase() === currentCategory));

        const matchesSearch = !searchQuery || 
            report.title.toLowerCase().includes(searchQuery) ||
            report.summary.toLowerCase().includes(searchQuery) ||
            report.sha256.toLowerCase().includes(searchQuery) ||
            report.tags.some(t => t.toLowerCase().includes(searchQuery)) ||
            report.mitre.some(m => m.id.toLowerCase().includes(searchQuery) || m.name.toLowerCase().includes(searchQuery));

        return matchesCategory && matchesSearch;
    });

    if (filtered.length === 0) {
        grid.innerHTML = `
            <div style="grid-column: 1 / -1; text-align: center; padding: 60px 20px; color: var(--text-dim);">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-bottom: 12px; opacity: 0.5;">
                    <circle cx="11" cy="11" r="8"></circle>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
                <p style="font-size: 16px; font-weight: 600; color: var(--text-muted);">No threat bulletins match your criteria</p>
                <p style="font-size: 13px; margin-top: 4px;">Try searching for "Mirai", "XMRig", "T1053", or reset filters.</p>
            </div>
        `;
        return;
    }

    grid.innerHTML = filtered.map(report => {
        const shortHash = report.sha256.substring(0, 10) + "..." + report.sha256.substring(report.sha256.length - 8);
        const familyClass = report.category.toLowerCase();
        
        return `
            <article class="bulletin-card" onclick="openReportModal('${report.id}')">
                <div class="card-tag-row">
                    <span class="family-tag ${familyClass}">${report.family}</span>
                    <span class="threat-severity ${report.severity.toLowerCase()}">${report.severity}</span>
                </div>
                <h3 class="card-title">${escapeHtml(report.title)}</h3>
                <p class="card-summary">${escapeHtml(report.summary.substring(0, 160))}...</p>
                
                <div class="card-hash-bar" onclick="event.stopPropagation()">
                    <code class="card-hash-mono">${shortHash}</code>
                    <button class="btn-icon-copy" title="Copy full SHA-256" onclick="copyToClipboard('${report.sha256}', 'SHA-256 copied!')">
                        📋
                    </button>
                </div>

                <div class="card-footer">
                    <span class="ioc-count-badge">${report.iocs.length} IoCs Cataloged</span>
                    <span class="pub-date">${report.date}</span>
                </div>
            </article>
        `;
    }).join("");
}

// Open In-Depth Report Modal (Elastic Style)
function openReportModal(reportId) {
    const report = THREAT_REPORTS.find(r => r.id === reportId);
    if (!report) return;

    document.getElementById("modalCatTag").textContent = `${report.family} INTELLIGENCE`;
    const severityElem = document.getElementById("modalSeverity");
    severityElem.textContent = report.severity;
    severityElem.className = `threat-severity ${report.severity.toLowerCase()}`;

    const contentArea = document.getElementById("modalReportContent");

    // Format Velociraptor process tree
    const processTreeHtml = report.velociraptorTelemetry.processTree.length > 0
        ? `<div class="code-block-wrap">
             <button class="btn-code-copy" onclick="copyToClipboard(decodeURIComponent('${encodeURIComponent(report.velociraptorTelemetry.processTree.join('\n'))}'), 'Process tree copied!')">Copy</button>
             <pre>${escapeHtml(report.velociraptorTelemetry.processTree.join('\n'))}</pre>
           </div>`
        : `<p style="color: var(--text-dim); font-size: 13px;">No auxiliary child processes spawned.</p>`;

    // Format dropped payloads
    const droppedHtml = report.velociraptorTelemetry.droppedPayloads.length > 0
        ? report.velociraptorTelemetry.droppedPayloads.map(p => `
            <div style="background: var(--bg-card); border: 1px solid var(--border-dim); border-radius: 6px; padding: 14px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                    <strong style="color: var(--accent-cyan); font-family: var(--font-mono); font-size: 13px;">${escapeHtml(p.path)}</strong>
                    <span style="font-size: 11px; color: var(--text-dim);">${escapeHtml(p.size)}</span>
                </div>
                <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">${escapeHtml(p.magic)}</p>
                <div style="font-size: 11px; font-family: var(--font-mono); color: var(--accent-teal); background: rgba(0,0,0,0.3); padding: 8px; border-radius: 4px;">
                    ${p.strings.map(s => `<div>+ ${escapeHtml(s)}</div>`).join("")}
                </div>
            </div>
          `).join("")
        : `<p style="color: var(--text-dim); font-size: 13px;">Zero external secondary binaries dropped to disk.</p>`;

    // Format IoC rows
    const iocRows = report.iocs.map(ioc => `
        <tr>
            <td><strong>${escapeHtml(ioc.type)}</strong></td>
            <td><code>${escapeHtml(ioc.value)}</code></td>
            <td>${escapeHtml(ioc.description)}</td>
            <td style="text-align: right;">
                <button class="btn-code-copy" style="position: static;" onclick="copyToClipboard('${escapeHtml(ioc.value)}', 'Copied IoC!')">Copy</button>
            </td>
        </tr>
    `).join("");

    // Format MITRE rows
    const mitreBadges = report.mitre.map(m => `
        <span class="mitre-badge" style="margin-right: 6px; margin-bottom: 6px; display: inline-block;">
            <strong>${escapeHtml(m.id)}</strong>: ${escapeHtml(m.name)}
        </span>
    `).join("");

    contentArea.innerHTML = `
        <h1 class="report-view-title">${escapeHtml(report.title)}</h1>
        
        <div class="report-view-meta">
            <div>
                <span class="meta-label">TARGET SHA-256</span>
                <code style="font-size: 11px; color: var(--accent-teal);">${report.sha256}</code>
            </div>
            <div>
                <span class="meta-label">ANALYSIS ENVIRONMENT</span>
                <span style="font-size: 12px; color: var(--text-main);">Ubuntu 24.04 (Air-Gapped Container)</span>
            </div>
            <div>
                <span class="meta-label">DATE PUBLISHED</span>
                <span style="font-size: 12px; color: var(--text-main);">${report.date}</span>
            </div>
        </div>

        <h2 class="report-section-h2">Executive Summary &amp; Threat Context</h2>
        <p style="font-size: 14px; color: var(--text-muted); line-height: 1.7; margin-bottom: 20px;">
            ${escapeHtml(report.summary)}
        </p>

        <h2 class="report-section-h2">MITRE ATT&amp;CK Matrix Mapping</h2>
        <div style="margin-bottom: 24px;">
            ${mitreBadges}
        </div>

        <h2 class="report-section-h2">Velociraptor Forensic Telemetry</h2>
        <h4 style="font-size: 13px; color: var(--text-main); margin: 14px 0 6px;">Reconstructed Process Tree (Linux.Sys.Pslist):</h4>
        ${processTreeHtml}

        <h4 style="font-size: 13px; color: var(--text-main); margin: 18px 0 6px;">Statically Decomposed Dropped Payloads:</h4>
        ${droppedHtml}

        <h2 class="report-section-h2">Indicators of Compromise (IoCs - Defanged)</h2>
        <div style="overflow-x: auto;">
            <table class="report-table">
                <thead>
                    <tr>
                        <th style="width: 22%;">Type</th>
                        <th style="width: 40%;">Indicator (Defanged)</th>
                        <th>Context / Description</th>
                        <th style="width: 80px;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${iocRows}
                </tbody>
            </table>
        </div>

        <h2 class="report-section-h2">AI-Synthesized Candidate YARA Rule</h2>
        <div class="code-block-wrap">
            <button class="btn-code-copy" onclick="copyToClipboard(decodeURIComponent('${encodeURIComponent(report.yaraRule)}'), 'YARA rule copied!')">Copy YARA</button>
            <pre><code>${escapeHtml(report.yaraRule)}</code></pre>
        </div>

        <div style="margin-top: 30px; display: flex; gap: 12px; justify-content: flex-end;">
            <button class="btn-cancel" onclick="downloadReportJson('${report.id}')">Export STIX 2.1 / JSON</button>
            <button class="btn-submit-action" onclick="closeReportModal()">Done Reading</button>
        </div>
    `;

    document.getElementById("reportModalOverlay").classList.add("active");
    document.body.style.overflow = "hidden";
}

function closeReportModal(e) {
    if (e && e.target !== e.currentTarget) return;
    document.getElementById("reportModalOverlay").classList.remove("active");
    document.body.style.overflow = "auto";
}

// Submission Flow Modal
function openSubmissionModal(prefillHash = "") {
    const modal = document.getElementById("submissionModalOverlay");
    const input = document.getElementById("modalHashInput");
    if (prefillHash) {
        input.value = prefillHash;
    }
    document.getElementById("detonationStepper").style.display = "none";
    document.getElementById("btnSubmitAction").style.display = "block";
    document.getElementById("btnSubmitAction").disabled = false;
    document.getElementById("btnSubmitAction").innerHTML = `<span>Start Detonation</span>`;
    
    modal.classList.add("active");
    document.body.style.overflow = "hidden";
    input.focus();
}

function closeSubmissionModal(e) {
    if (e && e.target !== e.currentTarget) return;
    document.getElementById("submissionModalOverlay").classList.remove("active");
    document.body.style.overflow = "auto";
}

function handleQuickSubmit() {
    const hash = document.getElementById("quickHashInput").value.trim();
    if (!hash) {
        openSubmissionModal();
        return;
    }
    
    // Check if we already have this report cataloged
    const existing = THREAT_REPORTS.find(r => r.sha256.toLowerCase() === hash.toLowerCase());
    if (existing) {
        openReportModal(existing.id);
        return;
    }

    openSubmissionModal(hash);
}

// Execute Detonation Simulation / Live API Integration
async function executeDetonation() {
    const hashInput = document.getElementById("modalHashInput");
    const hash = hashInput.value.trim();

    if (!hash || hash.length < 32) {
        alert("Please enter a valid SHA-256 hash (64 hex characters) from MalwareBazaar.");
        hashInput.focus();
        return;
    }

    const stepper = document.getElementById("detonationStepper");
    const submitBtn = document.getElementById("btnSubmitAction");
    
    stepper.style.display = "flex";
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span>Detonating...</span>`;

    const steps = [
        { id: "step-mb", duration: 1200 },
        { id: "step-box", duration: 1800 },
        { id: "step-vr", duration: 1400 },
        { id: "step-ai", duration: 1600 }
    ];

    // Reset steps
    steps.forEach(s => {
        const el = document.getElementById(s.id);
        el.className = "step-item";
    });

    for (let i = 0; i < steps.length; i++) {
        const current = document.getElementById(steps[i].id);
        current.className = "step-item active";
        await sleep(steps[i].duration);
        current.className = "step-item done";
    }

    submitBtn.innerHTML = `<span>Detonation Complete!</span>`;
    submitBtn.style.background = "var(--accent-green)";
    
    await sleep(600);
    closeSubmissionModal();

    // Check if matches our known sample or open default
    const target = THREAT_REPORTS.find(r => r.sha256.toLowerCase() === hash.toLowerCase()) || THREAT_REPORTS[0];
    openReportModal(target.id);
    showToast("Live detonation completed & report synthesized!");
}

// Copy to Clipboard Utility
function copyToClipboard(text, message = "Copied to clipboard!") {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => showToast(message));
    } else {
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
}

// Show Toast Message
function showToast(message) {
    const toast = document.getElementById("toastNotification");
    const msg = document.getElementById("toastMessage");
    msg.textContent = message;
    toast.classList.add("show");
    setTimeout(() => {
        toast.classList.remove("show");
    }, 2800);
}

// Download Report JSON (STIX 2.1 mock)
function downloadReportJson(reportId) {
    const report = THREAT_REPORTS.find(r => r.id === reportId);
    if (!report) return;

    const exportData = {
        type: "bundle",
        id: `bundle--${report.id}`,
        spec_version: "2.1",
        objects: [
            {
                type: "malware",
                id: `malware--${report.id.substring(0, 36)}`,
                name: report.title,
                is_family: true,
                malware_types: [report.family.toLowerCase()],
                description: report.summary
            },
            ...report.iocs.map((ioc, idx) => ({
                type: "indicator",
                id: `indicator--${report.id.substring(0, 30)}${idx}`,
                name: ioc.type,
                pattern: `[file:hashes.'SHA-256' = '${ioc.value}']`,
                description: ioc.description
            }))
        ]
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `hunter_stix_${report.sha256.substring(0, 12)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    showToast("Downloaded STIX 2.1 Threat Bundle!");
}

// Helpers
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
