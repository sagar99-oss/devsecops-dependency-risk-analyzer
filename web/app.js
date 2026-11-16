// Software Dependency Security Analyzer - Frontend Application
let currentScanData = null;
let allInventoryDeps = [];
let allVulnerabilities = [];
let sortCol = "name";
let sortAsc = true;

// Charts
let dashSeverityChart = null;
let dashTrendChart = null;
let licenseChart = null;

// Graph state
let graphNodes = [];
let graphEdges = [];
let graphScale = 1.0;
let graphPanX = 0;
let graphPanY = 0;
let isDraggingNode = false;
let draggedNode = null;
let isPanningGraph = false;
let panStartX = 0;
let panStartY = 0;
let hoveredNode = null;
let highlightVulnOnly = false;

document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initDropzone();
    initGithubForm();
    initGraph();
    initModals();
    loadAnalytics();
    loadScanHistory();
});

// Toast notification helper
function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    const icon = type === "success" ? "✅" : type === "error" ? "❌" : "ℹ️";
    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// 1. Navigation Controller
function initNavigation() {
    const navItems = document.querySelectorAll(".nav-item");
    const viewPanels = document.querySelectorAll(".view-panel");
    const pageTitle = document.getElementById("pageTitle");

    const titles = {
        dashboard: "Security Overview Dashboard",
        scanner: "Dependency Vulnerability Scanner",
        inventory: "Software Dependency Inventory",
        vulnerabilities: "Vulnerability Management & Tracking",
        licenses: "License Compliance & Legal Risks",
        graph: "Interactive Dependency Graph",
        remediation: "Automated Remediation Recommendations",
        history: "Scan History & Security Posture Comparison",
        reports: "Security Reports & Compliance Artifacts",
        settings: "Scanner Configuration & Feeds"
    };

    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const viewId = item.getAttribute("data-view");
            navItems.forEach(n => n.classList.remove("active"));
            item.classList.add("active");

            viewPanels.forEach(panel => {
                if (panel.id === `view-${viewId}`) {
                    panel.classList.add("active");
                } else {
                    panel.classList.remove("active");
                }
            });

            if (pageTitle && titles[viewId]) {
                pageTitle.innerText = titles[viewId];
            }

            // Redraw charts or graph if their panel became visible
            if (viewId === "graph") {
                setTimeout(() => renderGraphCanvas(), 50);
            } else if (viewId === "licenses" && currentScanData) {
                renderLicenseChart(currentScanData.license_summary || {});
            }
        });
    });

    const btnNewScan = document.getElementById("btnTriggerNewScan");
    if (btnNewScan) {
        btnNewScan.addEventListener("click", () => {
            const scannerNav = document.querySelector('.nav-item[data-view="scanner"]');
            if (scannerNav) scannerNav.click();
        });
    }
}

// 2. Dropzone & File Upload
function initDropzone() {
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("fileInput");

    if (!dropzone || !fileInput) return;

    dropzone.addEventListener("click", () => fileInput.click());

    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));

    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });
}

function handleFileUpload(file) {
    const validExtensions = [".txt", ".json", ".xml", ".toml", ".req", ".lock", ".mod"];
    const ext = "." + file.name.split(".").pop().toLowerCase();
    const isRequirement = file.name.toLowerCase().includes("requirement");

    if (!validExtensions.includes(ext) && !isRequirement) {
        showToast(`Unsupported file: ${file.name}. Use requirements.txt, package.json, pom.xml, or pyproject.toml.`, "error");
        return;
    }

    const threshold = parseFloat(document.getElementById("uploadRiskThreshold")?.value || "70.0");
    const failCritical = document.getElementById("chkFailCriticalUpload")?.checked ?? true;

    showLoading(true, `Parsing and scanning ${file.name}...`);

    const formData = new FormData();
    formData.append("file", file);
    formData.append("threshold", threshold);
    formData.append("fail_on_critical", failCritical);

    fetch("/api/scan/file", {
        method: "POST",
        body: formData
    })
    .then(async res => {
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "File scan failed");
        return data;
    })
    .then(data => {
        showLoading(false);
        showToast(`Scan complete for ${file.name}! Found ${data.total_dependencies} dependencies.`, "success");
        renderCompleteScan(data);
        loadAnalytics();
        loadScanHistory();
        // Switch to dashboard
        document.querySelector('.nav-item[data-view="dashboard"]')?.click();
    })
    .catch(err => {
        showLoading(false);
        showToast(err.message, "error");
    });
}

// 3. GitHub Remote Scan
function initGithubForm() {
    const btn = document.getElementById("btnLaunchGithubScan");
    if (!btn) return;

    btn.addEventListener("click", () => {
        const url = document.getElementById("githubUrl")?.value.trim();
        const branch = document.getElementById("githubBranch")?.value.trim() || "main";
        const threshold = parseFloat(document.getElementById("githubRiskThreshold")?.value || "70.0");
        const failCritical = document.getElementById("chkFailCriticalGithub")?.checked ?? true;

        if (!url || !url.toLowerCase().includes("github.com")) {
            showToast("Please enter a valid GitHub repository URL (e.g. https://github.com/owner/repo)", "error");
            return;
        }

        showLoading(true, `Cloning & analyzing manifests from GitHub: ${url}...`);

        fetch("/api/scan/github", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, branch, threshold, fail_on_critical: failCritical })
        })
        .then(async res => {
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || "GitHub scan failed");
            return data;
        })
        .then(data => {
            showLoading(false);
            showToast(`GitHub scan complete for ${url}!`, "success");
            renderCompleteScan(data);
            loadAnalytics();
            loadScanHistory();
            document.querySelector('.nav-item[data-view="dashboard"]')?.click();
        })
        .catch(err => {
            showLoading(false);
            showToast(err.message, "error");
        });
    });
}

function showLoading(show, message = "Processing...") {
    const overlay = document.getElementById("loadingOverlay");
    const statusText = document.getElementById("loadingText");
    if (!overlay) return;

    if (show) {
        if (statusText) statusText.innerText = message;
        overlay.style.display = "flex";
    } else {
        overlay.style.display = "none";
    }
}

// 4. Render All Modules with Scan Data
function renderCompleteScan(data) {
    currentScanData = data;

    // Header display
    const targetDisp = document.getElementById("currentTargetDisplay");
    if (targetDisp) targetDisp.innerText = data.target_path || "Scanned Target";

    // Setup Quick Exports
    if (data.scan_id) {
        const topExportGroup = document.getElementById("quickExportGroup");
        if (topExportGroup) topExportGroup.style.display = "flex";

        const setLink = (id, format) => {
            const el = document.getElementById(id);
            if (el) el.onclick = () => window.open(`/api/scans/${data.scan_id}/export/${format}`, "_blank");
        };
        setLink("btnExportHtmlTop", "html");
        setLink("btnExportJsonTop", "json");
        setLink("btnExportSarifTop", "sarif");

        const setReportBtn = (id, format) => {
            const el = document.getElementById(id);
            if (el) el.href = `/api/scans/${data.scan_id}/export/${format}`;
        };
        setReportBtn("btnDownloadHtml", "html");
        setReportBtn("btnDownloadJson", "json");
        setReportBtn("btnDownloadSarif", "sarif");
        setReportBtn("btnDownloadCycloneDx", "cyclonedx");
    }

    // 10 Core Security Metrics
    renderKPICards(data);

    // Research Innovations
    if (data.research_metrics) {
        document.getElementById("resFalsePositives").innerText = data.research_metrics.false_positives_eliminated || 0;
        document.getElementById("resBlastRadius").innerText = (data.research_metrics.average_blast_radius || 0.0).toFixed(1);
        document.getElementById("resZeroDays").innerText = data.research_metrics.predicted_zero_day_threats || 0;
        document.getElementById("resBreakingChanges").innerText = data.research_metrics.breaking_changes_prevented || 0;
    }

    // Dashboard Charts
    renderSeverityChart(data.severity_counts || {});

    // Module A: Inventory
    renderInventoryModule(data);

    // Module B: Vulnerabilities
    renderVulnerabilitiesModule(data);

    // Module C: Licenses
    renderLicenseModule(data);

    // Module D: Dependency Graph
    setupGraphData(data);

    // Module E: Remediation Center
    renderRemediationModule(data);
}

function renderKPICards(data) {
    // 1. Overall Risk Score
    const scoreVal = document.getElementById("kpiRiskScore");
    if (scoreVal) {
        scoreVal.innerText = data.overall_risk_score;
        scoreVal.style.color = data.overall_risk_score >= 70 ? "#f43f5e" : (data.overall_risk_score >= 40 ? "#fb923c" : "#4ade80");
    }

    const badgeRisk = document.getElementById("kpiRiskLevelBadge");
    if (badgeRisk) {
        badgeRisk.innerHTML = `<span class="badge badge-${data.risk_level}">${data.risk_level} RISK</span>`;
    }

    // 2. Total Dependencies
    document.getElementById("kpiTotalDeps").innerText = data.total_dependencies || 0;

    // 3. Vulnerable Packages
    const vulnDeps = data.vulnerable_dependencies_count || 0;
    document.getElementById("kpiVulnDeps").innerText = vulnDeps;
    const rate = data.total_dependencies > 0 ? Math.round((vulnDeps / data.total_dependencies) * 100) : 0;
    document.getElementById("kpiVulnRate").innerText = `${rate}% exposure rate`;

    // 4. Critical CVEs
    const critCount = data.critical_count ?? data.severity_counts?.CRITICAL ?? 0;
    document.getElementById("kpiCritVulns").innerText = critCount;

    // 5. High CVEs
    const highCount = data.high_count ?? data.severity_counts?.HIGH ?? 0;
    document.getElementById("kpiHighVulns").innerText = highCount;

    // 6. Outdated Packages
    document.getElementById("kpiOutdatedDeps").innerText = data.outdated_dependencies_count || 0;

    // 7. License Issues
    const licIssues = data.license_compliance_issues_count || 0;
    const licEl = document.getElementById("kpiLicenseIssues");
    if (licEl) {
        licEl.innerText = licIssues;
        licEl.style.color = licIssues > 0 ? "#f43f5e" : "#4ade80";
    }

    // 8. Transitive Dependencies
    document.getElementById("kpiTransitiveDeps").innerText = data.transitive_dependencies_count || 0;

    // 9. Security Issues Fixed
    document.getElementById("kpiFixedIssues").innerText = data.security_issues_fixed_count || 0;

    // 10. Health Score & Quality Gate
    const healthEl = document.getElementById("kpiHealthScore");
    if (healthEl) {
        healthEl.innerText = data.dependency_health_score ?? 100;
        healthEl.style.color = (data.dependency_health_score >= 80) ? "#4ade80" : (data.dependency_health_score >= 50 ? "#facc15" : "#f43f5e");
    }

    const gateEl = document.getElementById("kpiQualityGateDisplay");
    if (gateEl) {
        if (data.quality_gate_passed) {
            gateEl.innerHTML = `<span class="badge badge-passed">GATE PASSED</span>`;
        } else {
            gateEl.innerHTML = `<span class="badge badge-failed">GATE BREACHED</span>`;
        }
    }

    // Update nav badge
    const totalVuln = (critCount + highCount + (data.medium_count || data.severity_counts?.MEDIUM || 0) + (data.low_count || data.severity_counts?.LOW || 0));
    const navBadge = document.getElementById("navVulnBadge");
    if (navBadge) {
        navBadge.innerText = totalVuln;
        navBadge.style.display = totalVuln > 0 ? "inline-block" : "none";
    }
}

// 5. Module A: Dependency Inventory Table & Filters
function renderInventoryModule(data) {
    allInventoryDeps = (data.dependencies || []).map(a => a.dependency);
    applyInventoryFilters();

    const searchInput = document.getElementById("invSearchInput");
    const ecoFilter = document.getElementById("invEcosystemFilter");
    const statusFilter = document.getElementById("invStatusFilter");

    if (searchInput) searchInput.oninput = () => applyInventoryFilters();
    if (ecoFilter) ecoFilter.onchange = () => applyInventoryFilters();
    if (statusFilter) statusFilter.onchange = () => applyInventoryFilters();
}

function applyInventoryFilters() {
    const search = document.getElementById("invSearchInput")?.value.toLowerCase().trim() || "";
    const eco = document.getElementById("invEcosystemFilter")?.value || "ALL";
    const status = document.getElementById("invStatusFilter")?.value || "ALL";

    let filtered = allInventoryDeps.filter(dep => {
        // Search filter
        if (search) {
            const matchName = dep.name.toLowerCase().includes(search);
            const matchVer = dep.version.toLowerCase().includes(search);
            const matchLic = (dep.license || "").toLowerCase().includes(search);
            if (!matchName && !matchVer && !matchLic) return false;
        }

        // Ecosystem filter
        if (eco !== "ALL" && dep.ecosystem.toLowerCase() !== eco.toLowerCase()) return false;

        // Status filter
        if (status === "VULNERABLE") {
            const hasVuln = currentScanData.dependencies.some(a => a.dependency.name === dep.name && a.vulnerabilities.length > 0);
            if (!hasVuln) return false;
        } else if (status === "OUTDATED" && !dep.is_outdated) {
            return false;
        } else if (status === "DIRECT" && !dep.is_direct) {
            return false;
        } else if (status === "TRANSITIVE" && dep.is_direct) {
            return false;
        } else if (status === "LICENSE_RISK" && !dep.is_license_risk) {
            return false;
        }

        return true;
    });

    // Sort
    filtered.sort((a, b) => {
        let valA = a[sortCol] || "";
        let valB = b[sortCol] || "";
        if (typeof valA === "string") valA = valA.toLowerCase();
        if (typeof valB === "string") valB = valB.toLowerCase();
        return sortAsc ? (valA > valB ? 1 : -1) : (valA < valB ? 1 : -1);
    });

    const tbody = document.getElementById("inventoryTableBody");
    if (!tbody) return;

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="empty-state-cell"><div class="empty-state"><p>No dependencies match the selected filters.</p></div></td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(dep => {
        const analysis = currentScanData.dependencies.find(a => a.dependency.name === dep.name);
        const vulnCount = analysis ? analysis.vulnerabilities.length : 0;
        const highestSev = analysis && vulnCount > 0 ? analysis.highest_severity : "NONE";

        const typeBadge = dep.is_direct 
            ? `<span class="badge" style="background:rgba(56,189,248,0.15); color:var(--accent-blue)">Direct</span>`
            : `<span class="badge" style="background:rgba(156,163,175,0.15); color:var(--text-muted)">Transitive (Depth ${dep.depth})</span>`;

        let statusBadge = "";
        if (dep.is_malicious) statusBadge = `<span class="badge badge-CRITICAL">🚨 MALWARE</span>`;
        else if (dep.is_deprecated) statusBadge = `<span class="badge badge-HIGH">⚠️ Deprecated</span>`;
        else if (vulnCount > 0) statusBadge = `<span class="badge badge-${highestSev}">${vulnCount} CVE${vulnCount > 1 ? 's' : ''}</span>`;
        else if (dep.is_outdated) statusBadge = `<span class="badge badge-MEDIUM">Outdated</span>`;
        else statusBadge = `<span class="badge" style="background:rgba(74,222,128,0.15); color:var(--low-green)">Safe</span>`;

        const complianceBadge = dep.is_license_risk
            ? `<span class="badge badge-HIGH">${dep.license_category || 'Restrictive'}</span>`
            : `<span class="badge" style="background:rgba(74,222,128,0.15); color:var(--low-green)">${dep.license_category || 'Permissive'}</span>`;

        return `
            <tr>
                <td><strong>${escapeHtml(dep.name)}</strong></td>
                <td><code>${escapeHtml(dep.version)}</code></td>
                <td><code style="color:${dep.is_outdated ? 'var(--high-orange)' : 'var(--text-secondary)'}">${escapeHtml(dep.latest_version || dep.version)}</code></td>
                <td><span class="tag">${escapeHtml(dep.ecosystem)}</span></td>
                <td>${typeBadge}</td>
                <td>${statusBadge}</td>
                <td><code>${escapeHtml(dep.license || 'Unknown')}</code></td>
                <td>${complianceBadge}</td>
                <td>
                    <button class="btn btn-sm btn-outline" onclick="inspectDependency('${escapeHtml(dep.name)}')">Inspect</button>
                </td>
            </tr>
        `;
    }).join("");
}

function sortInventoryTable(col) {
    if (sortCol === col) sortAsc = !sortAsc;
    else { sortCol = col; sortAsc = true; }
    applyInventoryFilters();
}

function inspectDependency(depName) {
    const analysis = currentScanData?.dependencies?.find(a => a.dependency.name === depName);
    if (!analysis) return;

    const dep = analysis.dependency;
    const body = `
        <div style="margin-bottom:0.75rem;"><strong>Package:</strong> ${escapeHtml(dep.name)}</div>
        <div style="margin-bottom:0.75rem;"><strong>Installed Version:</strong> ${escapeHtml(dep.version)}</div>
        <div style="margin-bottom:0.75rem;"><strong>Latest Version:</strong> ${escapeHtml(dep.latest_version || dep.version)}</div>
        <div style="margin-bottom:0.75rem;"><strong>Ecosystem:</strong> ${escapeHtml(dep.ecosystem)}</div>
        <div style="margin-bottom:0.75rem;"><strong>Type:</strong> ${dep.is_direct ? 'Direct Dependency' : 'Transitive Dependency (Depth ' + dep.depth + ')'}</div>
        <div style="margin-bottom:0.75rem;"><strong>License:</strong> ${escapeHtml(dep.license)} (${escapeHtml(dep.license_category)})</div>
        <div style="margin-bottom:0.75rem;"><strong>Blast Radius Score:</strong> ${dep.blast_radius_score} / 100</div>
        <div style="margin-bottom:0.75rem;"><strong>Zero-Day ML Risk:</strong> ${dep.zero_day_risk_score} / 100</div>
        <div><strong>Vulnerabilities Detected:</strong> ${analysis.vulnerabilities.length}</div>
    `;

    document.getElementById("inspectNodeTitle").innerText = dep.name;
    document.getElementById("inspectNodeBody").innerHTML = body;
    document.getElementById("nodeInspectorPanel").style.display = "block";
    document.querySelector('.nav-item[data-view="graph"]')?.click();
}

// 6. Module B: Vulnerability Management
function renderVulnerabilitiesModule(data) {
    allVulnerabilities = [];
    (data.dependencies || []).forEach(analysis => {
        analysis.vulnerabilities.forEach(vuln => {
            allVulnerabilities.push({
                ...vuln,
                package_name: analysis.dependency.name,
                package_version: analysis.dependency.version,
                ecosystem: analysis.dependency.ecosystem,
                reachability: vuln.reachability || (analysis.is_reachable ? "REACHABLE" : "UNREACHABLE")
            });
        });
    });

    applyVulnerabilityFilters("ALL");

    // Filter Buttons
    const filterBtns = document.querySelectorAll(".severity-filter-group .btn-filter");
    filterBtns.forEach(btn => {
        btn.onclick = () => {
            filterBtns.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            applyVulnerabilityFilters(btn.getAttribute("data-sev"));
        };
    });

    const search = document.getElementById("vulnSearchInput");
    if (search) search.oninput = () => {
        const activeBtn = document.querySelector(".severity-filter-group .btn-filter.active");
        applyVulnerabilityFilters(activeBtn?.getAttribute("data-sev") || "ALL");
    };
}

function applyVulnerabilityFilters(severityFilter) {
    const search = document.getElementById("vulnSearchInput")?.value.toLowerCase().trim() || "";

    const filtered = allVulnerabilities.filter(v => {
        if (severityFilter !== "ALL" && v.severity.toUpperCase() !== severityFilter) return false;
        if (search) {
            const mId = (v.vuln_id || "").toLowerCase().includes(search);
            const mPkg = (v.package_name || "").toLowerCase().includes(search);
            const mSum = (v.summary || "").toLowerCase().includes(search);
            if (!mId && !mPkg && !mSum) return false;
        }
        return true;
    });

    const tbody = document.getElementById("vulnTableBody");
    if (!tbody) return;

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="empty-state-cell"><div class="empty-state"><div class="empty-icon">🛡️</div><p>No vulnerabilities match this severity filter or search query.</p></div></td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(v => {
        const cvss = v.cvss_score ? v.cvss_score.toFixed(1) : "N/A";
        const epss = v.epss_score ? `${(v.epss_score * 100).toFixed(1)}%` : "N/A";
        const fixed = v.fixed_version ? `<span class="text-green"><strong>${escapeHtml(v.fixed_version)}</strong></span>` : `<span class="text-muted">None</span>`;
        const reachBadge = v.reachability === "REACHABLE"
            ? `<span class="badge badge-HIGH">REACHABLE</span>`
            : `<span class="badge" style="background:rgba(156,163,175,0.15); color:var(--text-muted)">UNREACHABLE</span>`;

        return `
            <tr>
                <td><span class="badge badge-${v.severity}">${v.severity}</span></td>
                <td><code>${escapeHtml(v.vuln_id)}</code></td>
                <td><strong>${escapeHtml(v.package_name)}</strong></td>
                <td><code>${escapeHtml(v.package_version)}</code></td>
                <td><strong>${cvss}</strong></td>
                <td>${epss}</td>
                <td>${fixed}</td>
                <td>${reachBadge}</td>
                <td>
                    <button class="btn btn-sm btn-outline" onclick="openVulnModal('${escapeHtml(v.vuln_id)}', '${escapeHtml(v.package_name)}')">View Details</button>
                </td>
            </tr>
        `;
    }).join("");
}

function openVulnModal(vulnId, pkgName) {
    const vuln = allVulnerabilities.find(v => v.vuln_id === vulnId && v.package_name === pkgName);
    if (!vuln) return;

    const modal = document.getElementById("vulnDetailModal");
    document.getElementById("modalVulnTitle").innerText = vuln.vuln_id;
    document.getElementById("modalVulnPkg").innerText = `${vuln.package_name} @ ${vuln.package_version} (${vuln.ecosystem})`;
    document.getElementById("modalVulnCvss").innerText = vuln.cvss_score ? `${vuln.cvss_score.toFixed(1)} / 10.0` : "Not evaluated";
    document.getElementById("modalVulnEpss").innerText = vuln.epss_score ? `${(vuln.epss_score * 100).toFixed(2)}% probability of active exploitation` : "N/A";
    document.getElementById("modalVulnFixed").innerText = vuln.fixed_version || "No official patch version reported";
    document.getElementById("modalVulnSummary").innerText = vuln.description || vuln.summary;

    const badge = document.getElementById("modalVulnSeverityBadge");
    badge.className = `badge badge-${vuln.severity}`;
    badge.innerText = vuln.severity;

    const remEl = document.getElementById("modalVulnRemediation");
    if (vuln.fixed_version) {
        remEl.innerHTML = `✅ <strong>Recommended Fix:</strong> Upgrade <code>${vuln.package_name}</code> to version <strong>${vuln.fixed_version}</strong> or later.`;
    } else {
        remEl.innerHTML = `⚠️ <strong>Mitigation:</strong> No fixed version released yet. Consider alternative libraries or applying application-level input sanitation.`;
    }

    const refsEl = document.getElementById("modalVulnRefs");
    if (vuln.references && vuln.references.length > 0) {
        refsEl.innerHTML = vuln.references.map(r => `<li><a href="${escapeHtml(r)}" target="_blank" rel="noopener">${escapeHtml(r)}</a></li>`).join("");
    } else {
        refsEl.innerHTML = `<li><a href="https://osv.dev/vulnerability/${vuln.vuln_id}" target="_blank">View on Google OSV.dev</a></li>`;
    }

    modal.style.display = "flex";
}

// 7. Module C: License Compliance
function renderLicenseModule(data) {
    const licSummary = data.license_summary || {};
    const permissive = licSummary["Permissive"] || 0;
    const weak = licSummary["Weak Copyleft"] || 0;
    const strong = licSummary["Strong Copyleft (Restrictive)"] || 0;
    const unknown = licSummary["Unknown"] || 0;

    document.getElementById("licPermissiveCount").innerText = permissive;
    document.getElementById("licWeakCopyleftCount").innerText = weak;
    document.getElementById("licStrongCopyleftCount").innerText = strong;
    document.getElementById("licUnknownCount").innerText = unknown;

    const alertBox = document.getElementById("licenseAlertBox");
    if (alertBox) {
        alertBox.style.display = strong > 0 ? "block" : "none";
    }

    renderLicenseChart(licSummary);

    // License Table
    const tbody = document.getElementById("licenseTableBody");
    if (!tbody) return;

    const deps = (data.dependencies || []).map(a => a.dependency);
    tbody.innerHTML = deps.map(dep => {
        const commercialSafe = !dep.is_license_risk 
            ? `<span class="badge badge-passed">PERMITTED</span>`
            : `<span class="badge badge-failed">REVIEW NEEDED</span>`;

        return `
            <tr>
                <td><strong>${escapeHtml(dep.name)}</strong></td>
                <td><code>${escapeHtml(dep.version)}</code></td>
                <td>${escapeHtml(dep.ecosystem)}</td>
                <td><code>${escapeHtml(dep.license || 'Unknown')}</code></td>
                <td>${escapeHtml(dep.license_category || 'Unknown')}</td>
                <td>${commercialSafe}</td>
                <td>${dep.is_license_risk ? '<span class="text-red">Copyleft / Restrictive</span>' : '<span class="text-green">Non-Reciprocal</span>'}</td>
            </tr>
        `;
    }).join("");
}

function renderLicenseChart(licSummary) {
    const ctx = document.getElementById("licenseChart")?.getContext("2d");
    if (!ctx) return;
    if (licenseChart) licenseChart.destroy();

    const labels = Object.keys(licSummary).filter(k => licSummary[k] > 0);
    const counts = labels.map(k => licSummary[k]);

    licenseChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels.length ? labels : ['No Data'],
            datasets: [{
                data: counts.length ? counts : [1],
                backgroundColor: ['#4ade80', '#38bdf8', '#f43f5e', '#facc15', '#a855f7', '#94a3b8'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8' } }
            }
        }
    });
}

// 8. Module D: Interactive Dependency Graph
function initGraph() {
    const canvas = document.getElementById("dependencyGraphCanvas");
    if (!canvas) return;

    // Handle Resize
    const resizeCanvas = () => {
        const container = document.getElementById("graphContainer");
        if (container) {
            canvas.width = container.clientWidth;
            canvas.height = container.clientHeight;
            renderGraphCanvas();
        }
    };
    window.addEventListener("resize", resizeCanvas);
    setTimeout(resizeCanvas, 100);

    // Zoom and Pan Controls
    document.getElementById("btnGraphZoomIn")?.addEventListener("click", () => {
        graphScale = Math.min(graphScale * 1.25, 3.0);
        renderGraphCanvas();
    });
    document.getElementById("btnGraphZoomOut")?.addEventListener("click", () => {
        graphScale = Math.max(graphScale / 1.25, 0.4);
        renderGraphCanvas();
    });
    document.getElementById("btnGraphReset")?.addEventListener("click", () => {
        graphScale = 1.0;
        graphPanX = 0;
        graphPanY = 0;
        highlightVulnOnly = false;
        renderGraphCanvas();
    });
    document.getElementById("btnGraphToggleVulnOnly")?.addEventListener("click", () => {
        highlightVulnOnly = !highlightVulnOnly;
        renderGraphCanvas();
    });
    document.getElementById("btnCloseInspector")?.addEventListener("click", () => {
        document.getElementById("nodeInspectorPanel").style.display = "none";
    });

    // Canvas Mouse Events (Drag & Hover)
    canvas.addEventListener("mousedown", (e) => {
        const rect = canvas.getBoundingClientRect();
        const mx = (e.clientX - rect.left - graphPanX - canvas.width / 2) / graphScale;
        const my = (e.clientY - rect.top - graphPanY - canvas.height / 2) / graphScale;

        // Check if clicked a node
        const clicked = graphNodes.find(n => Math.hypot(n.x - mx, n.y - my) <= n.radius + 4);
        if (clicked) {
            isDraggingNode = true;
            draggedNode = clicked;
            inspectDependency(clicked.name);
        } else {
            isPanningGraph = true;
            panStartX = e.clientX - graphPanX;
            panStartY = e.clientY - graphPanY;
        }
    });

    window.addEventListener("mousemove", (e) => {
        const rect = canvas.getBoundingClientRect();
        const mx = (e.clientX - rect.left - graphPanX - canvas.width / 2) / graphScale;
        const my = (e.clientY - rect.top - graphPanY - canvas.height / 2) / graphScale;

        if (isDraggingNode && draggedNode) {
            draggedNode.x = mx;
            draggedNode.y = my;
            renderGraphCanvas();
        } else if (isPanningGraph) {
            graphPanX = e.clientX - panStartX;
            graphPanY = e.clientY - panStartY;
            renderGraphCanvas();
        } else {
            // Hover Tooltip Check
            const hovered = graphNodes.find(n => Math.hypot(n.x - mx, n.y - my) <= n.radius + 4);
            const tooltip = document.getElementById("nodeTooltip");
            if (hovered && tooltip) {
                tooltip.style.display = "block";
                tooltip.style.left = `${e.clientX - rect.left + 12}px`;
                tooltip.style.top = `${e.clientY - rect.top + 12}px`;
                tooltip.innerHTML = `<strong>${escapeHtml(hovered.name)}</strong> @ ${escapeHtml(hovered.version)}<br><span style="color:${hovered.has_vulns ? '#f43f5e' : '#4ade80'}">${hovered.has_vulns ? '⚠️ ' + hovered.vuln_count + ' CVEs' : '✅ Clean'}</span>`;
                hoveredNode = hovered;
            } else if (tooltip) {
                tooltip.style.display = "none";
                hoveredNode = null;
            }
        }
    });

    window.addEventListener("mouseup", () => {
        isDraggingNode = false;
        draggedNode = null;
        isPanningGraph = false;
    });
}

function setupGraphData(data) {
    const rawNodes = data.dependency_graph?.nodes || [];
    const rawEdges = data.dependency_graph?.edges || [];

    const total = rawNodes.length;
    graphNodes = rawNodes.map((n, idx) => {
        // Arrange nodes organically in rings based on direct vs transitive
        const angle = (idx / Math.max(total, 1)) * 2 * Math.PI;
        const dist = n.is_direct ? (120 + (idx % 2) * 35) : (230 + (idx % 3) * 45);

        return {
            ...n,
            x: Math.cos(angle) * dist,
            y: Math.sin(angle) * dist,
            radius: n.is_direct ? 18 : 12,
            color: n.has_vulns ? '#f43f5e' : (n.is_direct ? '#38bdf8' : '#64748b')
        };
    });

    graphEdges = rawEdges;
    renderGraphCanvas();
}

function renderGraphCanvas() {
    const canvas = document.getElementById("dependencyGraphCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.save();
    ctx.translate(canvas.width / 2 + graphPanX, canvas.height / 2 + graphPanY);
    ctx.scale(graphScale, graphScale);

    // Draw Root Center Indicator
    ctx.beginPath();
    ctx.arc(0, 0, 10, 0, 2 * Math.PI);
    ctx.fillStyle = "rgba(99, 102, 241, 0.4)";
    ctx.fill();
    ctx.strokeStyle = "#6366f1";
    ctx.stroke();

    // Draw Edges
    const nodeMap = new Map(graphNodes.map(n => [n.id, n]));
    graphEdges.forEach(e => {
        const src = nodeMap.get(e.source);
        const tgt = nodeMap.get(e.target);
        if (src && tgt) {
            ctx.beginPath();
            ctx.moveTo(src.x, src.y);
            ctx.lineTo(tgt.x, tgt.y);
            ctx.strokeStyle = (src.has_vulns || tgt.has_vulns) ? "rgba(244, 63, 94, 0.4)" : "rgba(255, 255, 255, 0.12)";
            ctx.lineWidth = (src.has_vulns || tgt.has_vulns) ? 2 : 1;
            ctx.stroke();
        }
    });

    // Draw Nodes
    graphNodes.forEach(node => {
        if (highlightVulnOnly && !node.has_vulns) return;

        // Glow ring for vulnerable nodes
        if (node.has_vulns) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius + 6, 0, 2 * Math.PI);
            ctx.fillStyle = "rgba(244, 63, 94, 0.25)";
            ctx.fill();
        }

        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);
        ctx.fillStyle = node.color;
        ctx.fill();
        ctx.strokeStyle = node.has_vulns ? "#f43f5e" : "#ffffff";
        ctx.lineWidth = node.is_direct ? 2 : 1;
        ctx.stroke();

        // Node Label
        ctx.fillStyle = "#f8fafc";
        ctx.font = "11px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText(node.name, node.x, node.y + node.radius + 14);
    });

    ctx.restore();
}

// 9. Module E: Remediation Center
function renderRemediationModule(data) {
    const tbody = document.getElementById("remediationTableBody");
    if (!tbody) return;

    const recommendations = data.remediation_recommendations || [];
    if (recommendations.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state-cell"><div class="empty-state"><div class="empty-icon">✨</div><p>No vulnerable dependencies requiring remediation.</p></div></td></tr>`;
        return;
    }

    tbody.innerHTML = recommendations.map(rec => {
        const cves = (rec.resolved_cves || []).map(c => `<code>${escapeHtml(c)}</code>`).join(" ");
        const breakingRisk = parseFloat(rec.breaking_change_risk || "0.0");
        const riskColor = breakingRisk > 0.6 ? "#f43f5e" : (breakingRisk > 0.3 ? "#fb923c" : "#4ade80");

        return `
            <tr>
                <td><strong>${escapeHtml(rec.package)}</strong></td>
                <td><code>${escapeHtml(rec.installed_version)}</code></td>
                <td><strong class="text-green">${escapeHtml(rec.recommended_version)}</strong></td>
                <td>${cves}</td>
                <td><span class="badge badge-${rec.highest_severity}">${rec.highest_severity}</span></td>
                <td><span style="color:${riskColor}; font-weight:700;">${breakingRisk.toFixed(2)} / 1.0</span></td>
                <td><code>${escapeHtml(rec.upgrade_command)}</code></td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="copyCommand('${escapeHtml(rec.upgrade_command)}')">📋 Copy Command</button>
                </td>
            </tr>
        `;
    }).join("");
}

function copyCommand(cmd) {
    navigator.clipboard.writeText(cmd).then(() => {
        showToast(`Copied to clipboard: ${cmd}`, "success");
    }).catch(() => {
        showToast("Unable to copy to clipboard", "error");
    });
}

// 10. Module G: Scan History & Comparison
function loadScanHistory() {
    fetch("/api/scans")
        .then(res => res.json())
        .then(scans => {
            const tbody = document.getElementById("historyTableBody");
            if (!tbody) return;

            if (scans.length === 0) {
                tbody.innerHTML = `<tr><td colspan="9" class="empty-state-cell"><div class="empty-state"><p>No previous scans recorded.</p></div></td></tr>`;
                return;
            }

            tbody.innerHTML = scans.map(s => {
                const gateBadge = s.quality_gate_passed 
                    ? `<span class="badge badge-passed">PASSED</span>` 
                    : `<span class="badge badge-failed">BREACHED</span>`;

                const riskColor = s.overall_risk_score >= 70 ? '#f43f5e' : (s.overall_risk_score >= 40 ? '#fb923c' : '#4ade80');
                const dateStr = new Date(s.scan_timestamp).toLocaleString();

                return `
                    <tr>
                        <td><strong>#${s.id}</strong></td>
                        <td><strong>${escapeHtml(s.target_name)}</strong></td>
                        <td><span style="color:${riskColor}; font-weight:800;">${s.overall_risk_score}</span> / 100</td>
                        <td>${s.health_score ?? 100} / 100</td>
                        <td>${s.total_dependencies}</td>
                        <td><span class="text-orange">${s.vulnerable_dependencies_count}</span></td>
                        <td>${gateBadge}</td>
                        <td class="text-muted font-mono" style="font-size:0.8rem;">${dateStr}</td>
                        <td>
                            <button class="btn btn-sm btn-outline" onclick="loadScanById(${s.id})">📂 View</button>
                        </td>
                    </tr>
                `;
            }).join("");

            // Also populate scan comparison select dropdowns
            populateCompareDropdowns(scans);
        })
        .catch(err => console.error("Error loading scan history:", err));
}

function loadScanById(scanId) {
    showLoading(true, `Loading historical scan #${scanId}...`);
    fetch(`/api/scans/${scanId}`)
        .then(res => res.json())
        .then(data => {
            showLoading(false);
            if (data.report) {
                data.report.scan_id = data.id;
                renderCompleteScan(data.report);
                document.querySelector('.nav-item[data-view="dashboard"]')?.click();
                showToast(`Loaded scan #${scanId} (${data.target_name})`, "info");
            }
        })
        .catch(err => {
            showLoading(false);
            showToast("Failed to load scan record", "error");
        });
}

function populateCompareDropdowns(scans) {
    const selA = document.getElementById("compareScanA");
    const selB = document.getElementById("compareScanB");
    if (!selA || !selB) return;

    const options = scans.map(s => `<option value="${s.id}">Scan #${s.id} - ${escapeHtml(s.target_name)} (Risk: ${s.overall_risk_score})</option>`).join("");
    selA.innerHTML = options;
    selB.innerHTML = options;

    if (scans.length >= 2) {
        selA.selectedIndex = 1;
        selB.selectedIndex = 0;
    }
}

function initModals() {
    // Vuln detail close
    document.getElementById("btnCloseVulnModal")?.addEventListener("click", () => {
        document.getElementById("vulnDetailModal").style.display = "none";
    });

    // Compare modal trigger & close
    const btnOpenCmp = document.getElementById("btnLaunchCompareModal");
    const cmpModal = document.getElementById("compareModal");
    const btnCloseCmp = document.getElementById("btnCloseCompareModal");

    if (btnOpenCmp && cmpModal) {
        btnOpenCmp.addEventListener("click", () => {
            cmpModal.style.display = "flex";
        });
    }
    if (btnCloseCmp && cmpModal) {
        btnCloseCmp.addEventListener("click", () => {
            cmpModal.style.display = "none";
        });
    }

    // Execute comparison
    document.getElementById("btnExecuteCompare")?.addEventListener("click", () => {
        const idA = document.getElementById("compareScanA")?.value;
        const idB = document.getElementById("compareScanB")?.value;

        if (!idA || !idB || idA === idB) {
            showToast("Please choose two distinct scans to compare.", "error");
            return;
        }

        showLoading(true, "Comparing security posture across scans...");
        fetch(`/api/scans/compare?scan_a=${idA}&scan_b=${idB}`)
            .then(res => res.json())
            .then(cmp => {
                showLoading(false);
                renderComparisonResults(cmp);
            })
            .catch(err => {
                showLoading(false);
                showToast("Failed to compare scans: " + err, "error");
            });
    });
}

function renderComparisonResults(cmp) {
    const area = document.getElementById("compareResultsArea");
    if (!area) return;
    area.style.display = "block";

    const riskDelta = cmp.deltas.risk_score_delta;
    const healthDelta = cmp.deltas.health_score_delta;

    const rDeltaEl = document.getElementById("cmpRiskDelta");
    const rTextEl = document.getElementById("cmpRiskDeltaText");
    rDeltaEl.innerText = (riskDelta > 0 ? `+${riskDelta}` : `${riskDelta}`);
    rDeltaEl.style.color = riskDelta < 0 ? "#4ade80" : (riskDelta > 0 ? "#f43f5e" : "#94a3b8");
    rTextEl.innerText = riskDelta < 0 ? "✨ Security Improved" : (riskDelta > 0 ? "⚠️ Security Regressed" : "No score change");

    const hDeltaEl = document.getElementById("cmpHealthDelta");
    hDeltaEl.innerText = (healthDelta > 0 ? `+${healthDelta}` : `${healthDelta}`);
    hDeltaEl.style.color = healthDelta > 0 ? "#4ade80" : (healthDelta < 0 ? "#f43f5e" : "#94a3b8");

    document.getElementById("cmpNewVulnsCount").innerText = cmp.deltas.total_new_vulnerabilities;
    document.getElementById("cmpResolvedVulnsCount").innerText = cmp.deltas.total_resolved_vulnerabilities;

    // Newly introduced vulnerabilities list
    const newEl = document.getElementById("cmpNewVulnsList");
    if (cmp.newly_introduced_vulnerabilities.length === 0) {
        newEl.innerHTML = `<p class="text-green" style="font-size:0.85rem">✨ No new vulnerabilities introduced in Scan B!</p>`;
    } else {
        newEl.innerHTML = cmp.newly_introduced_vulnerabilities.map(v => `
            <div class="compare-vuln-item">
                <div>
                    <strong>${escapeHtml(v.package)}</strong> <code>${escapeHtml(v.vuln_id)}</code>
                    <div class="text-muted" style="font-size:0.75rem">${escapeHtml(v.summary)}</div>
                </div>
                <span class="badge badge-${v.severity}">${v.severity}</span>
            </div>
        `).join("");
    }

    // Resolved vulnerabilities list
    const resEl = document.getElementById("cmpResolvedVulnsList");
    if (cmp.resolved_vulnerabilities.length === 0) {
        resEl.innerHTML = `<p class="text-muted" style="font-size:0.85rem">No vulnerabilities resolved between these scans.</p>`;
    } else {
        resEl.innerHTML = cmp.resolved_vulnerabilities.map(v => `
            <div class="compare-vuln-item">
                <div>
                    <strong>${escapeHtml(v.package)}</strong> <code>${escapeHtml(v.vuln_id)}</code>
                    <div class="text-muted" style="font-size:0.75rem">${escapeHtml(v.summary)}</div>
                </div>
                <span class="badge badge-passed">RESOLVED</span>
            </div>
        `).join("");
    }
}

// 11. Dashboard Analytics & Trend Chart
function loadAnalytics() {
    fetch("/api/analytics")
        .then(res => res.json())
        .then(data => {
            const trendData = data.trend || [];
            const labels = trendData.map(t => `#${t.id} ${t.target_name.slice(0, 15)}`);
            const scores = trendData.map(t => t.overall_risk_score);

            const ctx = document.getElementById("dashTrendChart")?.getContext("2d");
            if (!ctx) return;
            if (dashTrendChart) dashTrendChart.destroy();

            dashTrendChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels.length ? labels : ['No Scans'],
                    datasets: [{
                        label: 'Overall Risk Score (0-100)',
                        data: scores.length ? scores : [0],
                        borderColor: '#38bdf8',
                        backgroundColor: 'rgba(56, 189, 248, 0.1)',
                        fill: true,
                        tension: 0.35,
                        pointBackgroundColor: '#38bdf8',
                        pointRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { min: 0, max: 100, grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8' } },
                        x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8', font: { size: 10 } } }
                    },
                    plugins: {
                        legend: { labels: { color: '#94a3b8' } }
                    }
                }
            });
        })
        .catch(err => console.error("Error loading analytics:", err));
}

function renderSeverityChart(counts) {
    const ctx = document.getElementById("dashSeverityChart")?.getContext("2d");
    if (!ctx) return;
    if (dashSeverityChart) dashSeverityChart.destroy();

    dashSeverityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [
                    counts.CRITICAL || 0,
                    counts.HIGH || 0,
                    counts.MEDIUM || 0,
                    counts.LOW || 0
                ],
                backgroundColor: ['#f43f5e', '#fb923c', '#facc15', '#4ade80'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8' } }
            }
        }
    });
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
