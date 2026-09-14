/**
 * Hunter Security Labs - Interactive Engine
 * Inspired by Elastic Security Labs (https://www.elastic.co/security-labs)
 */

let currentCategory = "ALL";
let searchQuery = "";

document.addEventListener("DOMContentLoaded", () => {
    initCategoryFilters();
    renderBulletins();
    initQuickInput();
});

function initCategoryFilters() {
    const filterButtons = document.querySelectorAll("#categoryFilters .tab-btn");
    filterButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            filterButtons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentCategory = btn.getAttribute("data-category");
            renderBulletins();
        });
    });
}

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

function filterBulletins() {
    searchQuery = document.getElementById("bulletinSearchInput").value.toLowerCase().trim();
    renderBulletins();
}

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
            <div style="grid-column: 1 / -1; text-align: center; padding: 50px 20px; color: var(--text-muted);">
                <p style="font-size: 15px; font-weight: 600; color: var(--text-secondary);">No threat bulletins match your criteria</p>
                <p style="font-size: 13px; margin-top: 4px;">Try searching by hash, family ("XMRig", "Mirai"), or technique ID ("T1053").</p>
            </div>
        `;
        return;
    }

    grid.innerHTML = filtered.map(report => {
        const shortHash = report.sha256.substring(0, 10) + "..." + report.sha256.substring(report.sha256.length - 8);
        
        return `
            <article class="bulletin-card" onclick="openReportModal('${report.id}')">
                <div class="card-top">
                    <span class="pill pill-category">${report.family}</span>
                    <span style="font-size: 12px; color: var(--text-muted);">${report.readTime}</span>
                </div>
                <h3 class="card-heading">${escapeHtml(report.title)}</h3>
                <p class="card-desc">${escapeHtml(report.summary.substring(0, 150))}...</p>
                
                <div class="card-hash-bar" onclick="event.stopPropagation()">
                    <code class="hash-preview">${shortHash}</code>
                    <button class="btn-copy-small" title="Copy full SHA-256" onclick="copyToClipboard('${report.sha256}', 'SHA-256 copied!')">
                        📋
                    </button>
                </div>

                <div class="card-foot">
                    <span class="ioc-counter">${report.iocs.length} Defanged IoCs</span>
                    <span>${report.date}</span>
                </div>
            </article>
        `;
    }).join("");
}

function openReportModal(reportId) {
    const report = THREAT_REPORTS.find(r => r.id === reportId);
    if (!report) return;

    document.getElementById("modalCatTag").textContent = `${report.family.toUpperCase()} RESEARCH`;
    const severityElem = document.getElementById("modalSeverity");
    severityElem.textContent = `${report.severity} SEVERITY (${report.severityScore})`;

    const contentArea = document.getElementById("modalReportContent");

    // Process hierarchy without engine names
    const processTreeHtml = report.behavior.processTree.length > 0
        ? `<div class="code-wrap">
             <button class="btn-code-copy" onclick="copyToClipboard(decodeURIComponent('${encodeURIComponent(report.behavior.processTree.join('\n'))}'), 'Process tree copied!')">Copy</button>
             <pre>${escapeHtml(report.behavior.processTree.join('\n'))}</pre>
           </div>`
        : `<p style="color: var(--text-muted); font-size: 13px;">No auxiliary child processes spawned.</p>`;

    // Dropped files
    const droppedHtml = report.behavior.droppedPayloads.length > 0
        ? report.behavior.droppedPayloads.map(p => `
            <div style="background: var(--elastic-surface-subtle); border: 1px solid var(--elastic-border); border-radius: 6px; padding: 12px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                    <strong style="color: var(--elastic-teal); font-family: var(--font-mono); font-size: 13px;">${escapeHtml(p.path)}</strong>
                    <span style="font-size: 11px; color: var(--text-muted);">${escapeHtml(p.size)}</span>
                </div>
                <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 6px;">${escapeHtml(p.magic)}</p>
                <div style="font-size: 11px; font-family: var(--font-mono); color: var(--elastic-sky); background: rgba(0,0,0,0.25); padding: 6px 10px; border-radius: 4px;">
                    ${p.strings.map(s => `<div>+ ${escapeHtml(s)}</div>`).join("")}
                </div>
            </div>
          `).join("")
        : `<p style="color: var(--text-muted); font-size: 13px;">Zero external secondary binaries dropped to disk.</p>`;

    // IoC table
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

    // MITRE badges
    const mitreBadges = report.mitre.map(m => `
        <span class="mitre-chip" style="margin-right: 6px; margin-bottom: 6px; display: inline-block;">
            <strong>${escapeHtml(m.id)}</strong> (${escapeHtml(m.tactic)}): ${escapeHtml(m.name)}
        </span>
    `).join("");

    contentArea.innerHTML = `
        <h1 class="report-headline">${escapeHtml(report.title)}</h1>
        
        <div class="report-meta-box">
            <div>
                <span class="meta-box-label">SAMPLE SHA-256</span>
                <span class="meta-box-val">${report.sha256}</span>
            </div>
            <div>
                <span class="meta-box-label">RESEARCH TEAM</span>
                <span style="font-size: 12px; color: var(--text-white);">${report.author}</span>
            </div>
            <div>
                <span class="meta-box-label">DATE PUBLISHED</span>
                <span style="font-size: 12px; color: var(--text-white);">${report.date}</span>
            </div>
        </div>

        <h3 class="report-h3">Executive Summary</h3>
        <p class="report-p">${escapeHtml(report.summary)}</p>

        <h3 class="report-h3">MITRE ATT&amp;CK Mapping</h3>
        <div style="margin-bottom: 20px;">
            ${mitreBadges}
        </div>

        <h3 class="report-h3">Process Hierarchy</h3>
        ${processTreeHtml}

        <h3 class="report-h3">Extracted Payloads &amp; Artifacts</h3>
        ${droppedHtml}

        <h3 class="report-h3">Indicators of Compromise (IoCs - Defanged)</h3>
        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">All network endpoints are defanged with brackets [.] to prevent inadvertent network resolution.</p>
        <div style="overflow-x: auto;">
            <table class="report-table">
                <thead>
                    <tr>
                        <th style="width: 22%;">Type</th>
                        <th style="width: 40%;">Indicator (Defanged)</th>
                        <th>Description</th>
                        <th style="width: 70px;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${iocRows}
                </tbody>
            </table>
        </div>

        <h3 class="report-h3">YARA Signature Detection</h3>
        <div class="code-wrap">
            <button class="btn-code-copy" onclick="copyToClipboard(decodeURIComponent('${encodeURIComponent(report.yaraRule)}'), 'YARA rule copied!')">Copy YARA</button>
            <pre><code>${escapeHtml(report.yaraRule)}</code></pre>
        </div>

        <div style="margin-top: 26px; display: flex; gap: 10px; justify-content: flex-end;">
            <button class="btn-primary" onclick="closeReportModal()">Done Reading</button>
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

function openSubmissionModal(prefillHash = "") {
    const modal = document.getElementById("submissionModalOverlay");
    const input = document.getElementById("modalHashInput");
    if (prefillHash) {
        input.value = prefillHash;
    }
    document.getElementById("detonationStepper").style.display = "none";
    document.getElementById("btnSubmitAction").style.display = "block";
    document.getElementById("btnSubmitAction").disabled = false;
    document.getElementById("btnSubmitAction").innerHTML = `Start Analysis`;
    
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
    
    const existing = THREAT_REPORTS.find(r => r.sha256.toLowerCase() === hash.toLowerCase());
    if (existing) {
        openReportModal(existing.id);
        return;
    }

    openSubmissionModal(hash);
}

async function executeDetonation() {
    const hashInput = document.getElementById("modalHashInput");
    const hash = hashInput.value.trim();

    if (!hash || hash.length < 32) {
        alert("Please enter a valid SHA-256 hash (64 hex characters).");
        hashInput.focus();
        return;
    }

    const stepper = document.getElementById("detonationStepper");
    const submitBtn = document.getElementById("btnSubmitAction");
    
    stepper.style.display = "flex";
    submitBtn.disabled = true;
    submitBtn.innerHTML = `Analyzing...`;

    const steps = [
        { id: "step-mb", duration: 1000 },
        { id: "step-box", duration: 1200 },
        { id: "step-vr", duration: 1000 },
        { id: "step-ai", duration: 1000 }
    ];

    steps.forEach(s => {
        const el = document.getElementById(s.id);
        el.className = "step-row";
    });

    for (let i = 0; i < steps.length; i++) {
        const current = document.getElementById(steps[i].id);
        current.className = "step-row active";
        await sleep(steps[i].duration);
        current.className = "step-row done";
    }

    submitBtn.innerHTML = `Analysis Complete!`;
    submitBtn.style.background = "var(--elastic-teal)";
    
    await sleep(500);
    closeSubmissionModal();

    const target = THREAT_REPORTS.find(r => r.sha256.toLowerCase() === hash.toLowerCase()) || THREAT_REPORTS[0];
    openReportModal(target.id);
    showToast("Analysis complete. Displaying threat bulletin.");
}

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

function showToast(message) {
    const toast = document.getElementById("toastNotification");
    const msg = document.getElementById("toastMessage");
    msg.textContent = message;
    toast.classList.add("show");
    setTimeout(() => {
        toast.classList.remove("show");
    }, 2800);
}

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
