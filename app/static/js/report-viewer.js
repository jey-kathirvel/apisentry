"use strict";

const params = new URLSearchParams(window.location.search);
const projectId = Number(params.get("project_id"));
const projectName = params.get("project_name") || `Project #${projectId}`;
const state = {findings: [], selectedScanId: null};
const elements = {
    projectName: document.getElementById("reportProjectName"),
    generatedAt: document.getElementById("reportGeneratedAt"),
    history: document.getElementById("scanHistorySelect"),
    loading: document.getElementById("reportLoading"),
    error: document.getElementById("reportError"),
    content: document.getElementById("reportContent"),
    score: document.getElementById("reportScore"),
    risk: document.getElementById("reportRisk"),
    findingCount: document.getElementById("findingCount"),
    highRiskCount: document.getElementById("highRiskCount"),
    endpointCount: document.getElementById("endpointCount"),
    fileCount: document.getElementById("fileCount"),
    search: document.getElementById("findingSearch"),
    severity: document.getElementById("severityFilter"),
    category: document.getElementById("categoryFilter"),
    source: document.getElementById("sourceFilter"),
    filteredCount: document.getElementById("filteredCount"),
    list: document.getElementById("findingsList"),
    empty: document.getElementById("findingsEmpty"),
    htmlButton: document.getElementById("downloadHtmlButton"),
    jsonButton: document.getElementById("downloadJsonButton"),
    closeButton: document.getElementById("closeReportButton"),
};

function escapeHtml(value) {
    const node = document.createElement("div");
    node.textContent = value ?? "";
    return node.innerHTML;
}

function authHeaders() {
    const token = localStorage.getItem("apisentry_access_token");
    return token ? {Authorization: `Bearer ${token}`} : {};
}

function locationText(finding) {
    const location = finding.location || finding.source_location || {};
    const file = location.file_path || "Project-wide";
    const line = location.line_start || location.line_number;
    return line ? `${file}:${line}` : file;
}

function normalizeFindings(report) {
    const endpointFindings = (report.assessments || []).flatMap((assessment) =>
        (assessment.findings || []).map((finding) => ({
            ...finding,
            origin: "endpoint",
            endpoint_method: finding.endpoint_method || assessment.method,
            endpoint_path: finding.endpoint_path || assessment.path,
        }))
    );
    const sourceFindings = (report.source_analysis?.issues || []).map((finding) => ({
        ...finding,
        origin: "source",
    }));
    const unique = new Map();
    [...endpointFindings, ...sourceFindings].forEach((finding) => {
        const key = finding.fingerprint || [
            finding.rule_id,
            finding.endpoint_method,
            finding.endpoint_path,
            locationText(finding),
        ].join("|");
        if (!unique.has(key)) unique.set(key, finding);
    });
    return [...unique.values()];
}

function renderCategories() {
    const categories = [...new Set(state.findings.map((item) => item.category).filter(Boolean))].sort();
    elements.category.innerHTML = '<option value="">All categories</option>' + categories
        .map((category) => `<option value="${escapeHtml(category)}">${escapeHtml(category.replaceAll("_", " "))}</option>`)
        .join("");
}

function renderFindings() {
    const query = elements.search.value.trim().toLowerCase();
    const severity = elements.severity.value;
    const category = elements.category.value;
    const origin = elements.source.value;
    const findings = state.findings.filter((finding) => {
        if (severity && finding.severity !== severity) return false;
        if (category && finding.category !== category) return false;
        if (origin && finding.origin !== origin) return false;
        if (!query) return true;
        return [finding.rule_id, finding.title, finding.description, finding.remediation,
            finding.endpoint_method, finding.endpoint_path, locationText(finding)]
            .filter(Boolean).join(" ").toLowerCase().includes(query);
    });

    elements.filteredCount.textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
    elements.empty.classList.toggle("hidden", findings.length !== 0);
    elements.list.innerHTML = findings.map((finding, index) => {
        const endpoint = finding.endpoint_path
            ? `${finding.endpoint_method || "API"} ${finding.endpoint_path}`
            : locationText(finding);
        return `<article class="finding-card" data-severity="${escapeHtml(finding.severity)}">
            <div class="finding-summary" data-finding-index="${index}" role="button" tabindex="0">
                <span class="severity-badge">${escapeHtml(finding.severity)}</span>
                <div><h3 class="finding-title">${escapeHtml(finding.title)}</h3>
                    <p class="finding-meta">${escapeHtml(finding.rule_id)} · ${escapeHtml(finding.category)} · ${escapeHtml(endpoint)} · ${escapeHtml(finding.origin)} analysis</p></div>
                <button class="finding-toggle" type="button">Details</button>
            </div>
            <div class="finding-details">
                <h3>Description</h3><p>${escapeHtml(finding.description)}</p>
                <h3>Location</h3><p>${escapeHtml(locationText(finding))}</p>
                ${finding.evidence ? `<h3>Evidence</h3><pre>${escapeHtml(finding.evidence)}</pre>` : ""}
                <h3>Recommended remediation</h3><p>${escapeHtml(finding.remediation)}</p>
                ${(finding.owasp_reference || finding.cwe_id) ? `<h3>References</h3><p>${escapeHtml([finding.owasp_reference, finding.cwe_id].filter(Boolean).join(" · "))}</p>` : ""}
            </div>
        </article>`;
    }).join("");

    elements.list.querySelectorAll(".finding-summary").forEach((summary) => {
        const toggle = () => summary.closest(".finding-card").classList.toggle("open");
        summary.addEventListener("click", toggle);
        summary.addEventListener("keydown", (event) => {
            if (["Enter", " "].includes(event.key)) { event.preventDefault(); toggle(); }
        });
    });
}

function renderReport(report) {
    state.findings = normalizeFindings(report);
    const criticalHigh = state.findings.filter((item) => ["critical", "high"].includes(item.severity)).length;
    elements.projectName.textContent = report.project?.name || projectName;
    elements.generatedAt.textContent = `Generated ${new Date(report.generated_at).toLocaleString()} · Scan #${report.scan?.id}`;
    elements.score.textContent = `${Number(report.summary?.score ?? 0)}/100`;
    elements.risk.textContent = `${report.summary?.severity || "unknown"} risk`;
    elements.findingCount.textContent = state.findings.length;
    elements.highRiskCount.textContent = criticalHigh;
    elements.endpointCount.textContent = report.scan?.endpoint_count ?? report.assessments?.length ?? 0;
    elements.fileCount.textContent = report.scan?.files_scanned ?? report.source_analysis?.files_scanned ?? 0;
    renderCategories();
    renderFindings();
    elements.loading.classList.add("hidden");
    elements.error.classList.add("hidden");
    elements.content.classList.remove("hidden");
}

async function loadReport(scanId) {
    state.selectedScanId = Number(scanId);
    elements.loading.classList.remove("hidden");
    elements.content.classList.add("hidden");
    const response = await fetch(`/api/v1/projects/${projectId}/report?format=json&scan_id=${state.selectedScanId}`, {headers: authHeaders()});
    if (!response.ok) throw new Error("The selected security report could not be loaded.");
    renderReport(await response.json());
}

async function initialize() {
    try {
        const response = await fetch(`/api/v1/projects/${projectId}/scans`, {headers: authHeaders()});
        if (!response.ok) throw new Error("Scan history could not be loaded.");
        const history = await response.json();
        const scans = history.scans.filter((scan) => scan.report_available);
        if (!scans.length) throw new Error("No completed security report is available yet.");
        elements.history.innerHTML = scans.map((scan) => `<option value="${scan.id}">Scan #${scan.id} · ${new Date(scan.completed_at || scan.created_at).toLocaleString()}</option>`).join("");
        await loadReport(scans[0].id);
    } catch (error) {
        elements.loading.classList.add("hidden");
        elements.error.textContent = error.message;
        elements.error.classList.remove("hidden");
    }
}

async function download(format) {
    const response = await fetch(`/api/v1/projects/${projectId}/report?format=${format}&scan_id=${state.selectedScanId}`, {headers: authHeaders()});
    if (!response.ok) return;
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `api-sentry-project-${projectId}-scan-${state.selectedScanId}.${format}`;
    document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
}

[elements.search, elements.severity, elements.category, elements.source].forEach((element) => element.addEventListener("input", renderFindings));
elements.history.addEventListener("change", () => loadReport(elements.history.value).catch((error) => { elements.error.textContent = error.message; elements.error.classList.remove("hidden"); }));
elements.htmlButton.addEventListener("click", () => download("html"));
elements.jsonButton.addEventListener("click", () => download("json"));
elements.closeButton.addEventListener("click", () => window.parent.postMessage({type: "apisentry:close-report-viewer"}, window.location.origin));
initialize();
