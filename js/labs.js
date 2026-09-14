/**
 * Hunter Security Labs - Interactive Engine
 * Inspired by Elastic Security Labs (https://www.elastic.co/security-labs)
 * Two core responsibilities:
 * 1. Accept SHA-256 hash submissions
 * 2. Present clean threat intelligence reports
 */

let currentCategory = "ALL";
let isAnalyzing = false;

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

    // Check if report already exists
    const existing = (typeof THREAT_REPORTS !== "undefined" && Array.isArray(THREAT_REPORTS))
        ? THREAT_REPORTS.find(r => r.sha256.toLowerCase() === hash || r.id.toLowerCase() === hash)
        : null;

    if (existing) {
        openReportModal(existing.id);
        return;
    }

    // Otherwise run simulated dynamic analysis workflow
    await runDynamicAnalysis(hash);
}

// Dynamic analysis simulation stepper
async function runDynamicAnalysis(hash) {
    isAnalyzing = true;
    const statusModal = document.getElementById("statusModalBackdrop");
    const hashDisplay = document.getElementById("statusHashDisplay");
    const btnAnalyze = document.getElementById("btnAnalyze");

    if (hashDisplay) {
        hashDisplay.textContent = `Target SHA-256: ${hash}`;
    }

    if (btnAnalyze) {
        btnAnalyze.disabled = true;
        btnAnalyze.textContent = "Analyzing...";
    }

    // Reset step indicators
    const stepIds = ["step-1", "step-2", "step-3", "step-4"];
    stepIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.className = "status-step";
        }
    });

    if (statusModal) {
        statusModal.classList.add("active");
        document.body.style.overflow = "hidden";
    }

    // Step through execution stages
    for (let i = 0; i < stepIds.length; i++) {
        const el = document.getElementById(stepIds[i]);
        if (el) el.className = "status-step active";
        await sleep(750);
        if (el) el.className = "status-step done";
    }

    await sleep(400);

    // Close status modal
    closeStatusModal();

    if (btnAnalyze) {
        btnAnalyze.disabled = false;
        btnAnalyze.textContent = "Analyze Hash";
    }
    isAnalyzing = false;

    // Create and prepend a generated report entry based on analysis
    const newReport = createSampleReport(hash);
    if (typeof THREAT_REPORTS !== "undefined") {
        THREAT_REPORTS.unshift(newReport);
        renderReports();
    }

    openReportModal(newReport.id);
    showToast("Analysis complete. Threat report generated.");
}

function createSampleReport(hash) {
    const dateStr = new Date().toISOString().split("T")[0];
    return {
        id: hash,
        sha256: hash,
        title: `Dynamic Behavioral Analysis: Automated ELF Detonation and IoC Extraction`,
        family: "Linux Malware",
        category: "DROPPER",
        severity: "HIGH",
        severityScore: "7.5/10",
        date: dateStr,
        author: "Hunter Research Team",
        readTime: "3 min read",
        summary: `Dynamic behavioral execution analysis completed for binary ${hash}. The sample demonstrated evasion heuristics, attempted socket initialization, and spawned auxiliary processes in temporary runtime storage before payload termination.`,
        tags: ["DROPPER", "DYNAMIC_ANALYSIS", "PERSISTENCE"],
        mitre: [
            { id: "T1059.004", name: "Unix Shell", tactic: "Execution" },
            { id: "T1564.001", name: "Hidden Files and Directories", tactic: "Defense Evasion" },
            { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" }
        ],
        iocs: [
            { type: "SHA-256 (Primary)", value: hash, description: "Detonated sample binary" },
            { type: "Network Endpoint", value: "203[.]0[.]113[.]42:8080", description: "Outbound beacon target (defanged)" },
            { type: "Dropped Binary", value: "/tmp/.sys_agent", description: "Secondary dropped payload" }
        ],
        behavior: {
            processTree: [
                `${hash.substring(0, 16)}.bin (PID: 201)`,
                `└── /bin/sh -c cp /proc/self/exe /tmp/.sys_agent`,
                `└── /tmp/.sys_agent --daemon (PID: 205)`
            ],
            droppedPayloads: [
                {
                    path: "/tmp/.sys_agent",
                    size: "142 KB",
                    magic: "ELF 64-bit LSB executable, x86-64",
                    strings: ["203[.]0[.]113[.]42", "CONNECT_FAILED", "DAEMON_MODE"]
                }
            ]
        },
        yaraRule: `rule Linux_Threat_${hash.substring(0, 8)}_Hunter {\n    meta:\n        description = "Automated detection rule generated by Hunter Security Labs"\n        sha256 = "${hash}"\n        date = "${dateStr}"\n    strings:\n        $s1 = "/tmp/.sys_agent" ascii\n        $s2 = "203.0.113.42" ascii\n    condition:\n        uint32(0) == 0x464c457f and any of them\n}`
    };
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
