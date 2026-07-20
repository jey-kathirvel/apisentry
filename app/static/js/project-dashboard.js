"use strict";

const API_BASE = "/api/v1";

const state = {
    accessToken: localStorage.getItem(
        "apisentry_access_token"
    ),
    refreshToken: localStorage.getItem(
        "apisentry_refresh_token"
    ),
    currentUser: null,
    projects: [],
    securityDashboardKey: "",
    securityDashboardLoading: false,
};

const elements = {
    authView: document.getElementById("authView"),
    dashboardView: document.getElementById(
        "dashboardView"
    ),
    loginForm: document.getElementById("loginForm"),
    loginButton: document.getElementById(
        "loginButton"
    ),
    authTabs: document.getElementById("authTabs"),
    authPanels: document.querySelectorAll(".auth-panel"),
    authPanelButtons: document.querySelectorAll(
        "[data-auth-panel]"
    ),
    signupForm: document.getElementById("signupForm"),
    signupButton: document.getElementById("signupButton"),
    signupMessage: document.getElementById("signupMessage"),
    forgotPasswordForm: document.getElementById(
        "forgotPasswordForm"
    ),
    forgotPasswordButton: document.getElementById(
        "forgotPasswordButton"
    ),
    forgotPasswordMessage: document.getElementById(
        "forgotPasswordMessage"
    ),
    resendVerificationForm: document.getElementById(
        "resendVerificationForm"
    ),
    resendVerificationButton: document.getElementById(
        "resendVerificationButton"
    ),
    resendVerificationMessage: document.getElementById(
        "resendVerificationMessage"
    ),
    checkEmailText: document.getElementById("checkEmailText"),
    resendEmail: document.getElementById("resendEmail"),
    verifyStatusIcon: document.getElementById("verifyStatusIcon"),
    verifyTitle: document.getElementById("verifyTitle"),
    verifyMessage: document.getElementById("verifyMessage"),
    verifyLoginButton: document.getElementById("verifyLoginButton"),
    resetPasswordForm: document.getElementById("resetPasswordForm"),
    resetPasswordButton: document.getElementById("resetPasswordButton"),
    resetPasswordMessage: document.getElementById("resetPasswordMessage"),
    authMessage: document.getElementById(
        "authMessage"
    ),
    logoutButton: document.getElementById(
        "logoutButton"
    ),
    sidebar: document.getElementById("sidebar"),
    mobileMenuButton: document.getElementById(
        "mobileMenuButton"
    ),
    sidebarUserName: document.getElementById(
        "sidebarUserName"
    ),
    sidebarUserEmail: document.getElementById(
        "sidebarUserEmail"
    ),
    sidebarUserAvatar: document.getElementById(
        "sidebarUserAvatar"
    ),
    uploadProjectButton: document.getElementById(
        "uploadProjectButton"
    ),
    sidebarUploadButton: document.getElementById(
        "sidebarUploadButton"
    ),
    bannerUploadButton: document.getElementById(
        "bannerUploadButton"
    ),
    emptyUploadButton: document.getElementById(
        "emptyUploadButton"
    ),
    refreshButton: document.getElementById(
        "refreshButton"
    ),
    uploadModal: document.getElementById(
        "uploadModal"
    ),
    closeUploadModalButton: document.getElementById(
        "closeUploadModalButton"
    ),
    cancelUploadButton: document.getElementById(
        "cancelUploadButton"
    ),
    uploadForm: document.getElementById(
        "uploadForm"
    ),
    submitUploadButton: document.getElementById(
        "submitUploadButton"
    ),
    projectFile: document.getElementById(
        "projectFile"
    ),
    selectedFile: document.getElementById(
        "selectedFile"
    ),
    dropZone: document.getElementById("dropZone"),
    uploadMessage: document.getElementById(
        "uploadMessage"
    ),
    uploadProgressContainer: document.getElementById(
        "uploadProgressContainer"
    ),
    uploadProgressText: document.getElementById(
        "uploadProgressText"
    ),
    uploadProgressBar: document.getElementById(
        "uploadProgressBar"
    ),
    projectLoadingState: document.getElementById(
        "projectLoadingState"
    ),
    projectEmptyState: document.getElementById(
        "projectEmptyState"
    ),
    projectsGrid: document.getElementById(
        "projectsGrid"
    ),
    scanMonitorPanel: document.getElementById("scanMonitorPanel"),
    scanMonitorFrameShell: document.getElementById("scanMonitorFrameShell"),
    scanMonitorFrame: document.getElementById("scanMonitorFrame"),
    minimizeScanMonitorButton: document.getElementById("minimizeScanMonitorButton"),
    restoreScanMonitorButton: document.getElementById("restoreScanMonitorButton"),
    minimizedScanLabel: document.getElementById("minimizedScanLabel"),
    minimizedScanProgress: document.getElementById("minimizedScanProgress"),
    reportViewerPanel: document.getElementById("reportViewerPanel"),
    reportViewerFrame: document.getElementById("reportViewerFrame"),
    projectSearchInput: document.getElementById(
        "projectSearchInput"
    ),
    totalProjectsMetric: document.getElementById(
        "totalProjectsMetric"
    ),
    readyProjectsMetric: document.getElementById(
        "readyProjectsMetric"
    ),
    scanningProjectsMetric: document.getElementById(
        "scanningProjectsMetric"
    ),
    completedProjectsMetric: document.getElementById(
        "completedProjectsMetric"
    ),
    applicationSummary: document.getElementById(
        "applicationSummary"
    ),
    activeScanSummary: document.getElementById(
        "activeScanSummary"
    ),
    securityScoreRing: document.getElementById(
        "securityScoreRing"
    ),
    securityScoreValue: document.getElementById(
        "securityScoreValue"
    ),
    securityScoreLabel: document.getElementById(
        "securityScoreLabel"
    ),
    criticalRiskMetric: document.getElementById(
        "criticalRiskMetric"
    ),
    highRiskMetric: document.getElementById(
        "highRiskMetric"
    ),
    mediumRiskMetric: document.getElementById(
        "mediumRiskMetric"
    ),
    lowRiskMetric: document.getElementById(
        "lowRiskMetric"
    ),
    criticalFindingSummary: document.getElementById(
        "criticalFindingSummary"
    ),
    latestPostureValue: document.getElementById(
        "latestPostureValue"
    ),
    latestScanProject: document.getElementById(
        "latestScanProject"
    ),
    latestScanTime: document.getElementById(
        "latestScanTime"
    ),
    toastContainer: document.getElementById(
        "toastContainer"
    ),
};

function setTokens(
    accessToken,
    refreshToken,
) {
    state.accessToken = accessToken;
    state.refreshToken = refreshToken;

    if (accessToken) {
        localStorage.setItem(
            "apisentry_access_token",
            accessToken,
        );
    } else {
        localStorage.removeItem(
            "apisentry_access_token"
        );
    }

    if (refreshToken) {
        localStorage.setItem(
            "apisentry_refresh_token",
            refreshToken,
        );
    } else {
        localStorage.removeItem(
            "apisentry_refresh_token"
        );
    }
}

function clearSession() {
    state.currentUser = null;
    state.projects = [];
    state.securityDashboardKey = "";
    state.securityDashboardLoading = false;

    resetExecutiveSecurityDashboard();

    setTokens(null, null);
}

function showAuthView() {
    elements.authView.classList.remove("hidden");
    elements.dashboardView.classList.add("hidden");
}

function showDashboardView() {
    elements.authView.classList.add("hidden");
    elements.dashboardView.classList.remove("hidden");
}

function setFormMessage(
    element,
    message = "",
    type = "",
) {
    element.textContent = message;
    element.className = "form-message";

    if (type) {
        element.classList.add(type);
    }
}

function getErrorMessage(data, fallback) {
    if (typeof data.detail === "string") {
        return data.detail;
    }

    if (Array.isArray(data.detail)) {
        return data.detail
            .map((item) => item.msg || "Invalid value")
            .join(" ");
    }

    if (data.error && data.error.message) {
        return data.error.message;
    }

    return fallback;
}

function showAuthPanel(panelName) {
    elements.authPanels.forEach((panel) => {
        panel.classList.toggle(
            "hidden",
            panel.id !== `${panelName}Panel`,
        );
    });

    const showTabs = ["login", "signup"].includes(panelName);
    elements.authTabs.classList.toggle("hidden", !showTabs);

    elements.authTabs
        .querySelectorAll(".auth-tab")
        .forEach((tab) => {
            tab.classList.toggle(
                "active",
                tab.dataset.authPanel === panelName,
            );
            tab.setAttribute(
                "aria-selected",
                String(tab.dataset.authPanel === panelName),
            );
        });

    const panel = document.getElementById(`${panelName}Panel`);
    const focusTarget = panel && panel.querySelector("input");
    if (focusTarget) {
        window.setTimeout(() => focusTarget.focus(), 50);
    }
}

function showToast(
    message,
    type = "success",
) {
    const toast = document.createElement("div");

    toast.className = `toast ${type}`;
    toast.textContent = message;

    elements.toastContainer.appendChild(toast);

    window.setTimeout(
        () => {
            toast.remove();
        },
        4200,
    );
}

async function parseResponse(response) {
    const contentType = response.headers.get(
        "content-type"
    ) || "";

    if (
        contentType.includes(
            "application/json"
        )
    ) {
        return response.json();
    }

    const text = await response.text();

    return {
        detail: text || response.statusText,
    };
}

async function refreshAccessToken() {
    if (!state.refreshToken) {
        return false;
    }

    try {
        const response = await fetch(
            `${API_BASE}/auth/refresh`,
            {
                method: "POST",
                headers: {
                    "Content-Type":
                        "application/json",
                },
                body: JSON.stringify({
                    refresh_token:
                        state.refreshToken,
                }),
            },
        );

        if (!response.ok) {
            clearSession();
            return false;
        }

        const data = await response.json();

        setTokens(
            data.access_token,
            data.refresh_token
                || state.refreshToken,
        );

        return true;

    } catch (error) {
        console.error(error);
        clearSession();

        return false;
    }
}

async function apiFetch(
    path,
    options = {},
    retry = true,
) {
    const headers = new Headers(
        options.headers || {}
    );

    if (
        state.accessToken
        && !headers.has("Authorization")
    ) {
        headers.set(
            "Authorization",
            `Bearer ${state.accessToken}`,
        );
    }

    const response = await fetch(
        `${API_BASE}${path}`,
        {
            ...options,
            headers,
        },
    );

    if (
        response.status === 401
        && retry
        && state.refreshToken
    ) {
        const refreshed = await refreshAccessToken();

        if (refreshed) {
            return apiFetch(
                path,
                options,
                false,
            );
        }
    }

    return response;
}

function getStatusClass(status) {
    const normalized = (
        status || "uploaded"
    ).toLowerCase();

    const allowed = new Set([
        "ready",
        "scanning",
        "completed",
        "failed",
        "uploaded",
    ]);

    return allowed.has(normalized)
        ? normalized
        : "uploaded";
}

function getFrameworkShortName(framework) {
    if (!framework) {
        return "API";
    }

    const aliases = {
        "FastAPI": "FA",
        "Django": "DJ",
        "Flask": "FL",
        "Spring Boot": "SB",
        "Next.js": "NX",
        "Express": "EX",
        "NestJS": "NS",
        "Laravel": "LV",
        "ASP.NET Core": "NT",
        "Flutter": "FT",
        "React": "RE",
        "Vue": "VU",
        "Angular": "AN",
    };

    return aliases[framework]
        || framework
            .replace(/[^A-Za-z]/g, "")
            .slice(0, 2)
            .toUpperCase();
}

function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) {
        return "—";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB",
    ];

    let value = bytes;
    let unitIndex = 0;

    while (
        value >= 1024
        && unitIndex < units.length - 1
    ) {
        value /= 1024;
        unitIndex += 1;
    }

    return `${
        value.toFixed(
            unitIndex === 0 ? 0 : 1
        )
    } ${units[unitIndex]}`;
}

function formatDate(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "—";
    }

    return new Intl.DateTimeFormat(
        undefined,
        {
            day: "2-digit",
            month: "short",
            year: "numeric",
        },
    ).format(date);
}

function escapeHtml(value) {
    const element = document.createElement("div");

    element.textContent = value ?? "";

    return element.innerHTML;
}


function clampSecurityScore(value) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return null;
    }

    return Math.max(
        0,
        Math.min(100, Math.round(number)),
    );
}

function normalizeSeverityCounts(value = {}) {
    const source = (
        value
        && typeof value === "object"
    )
        ? value
        : {};

    return {
        critical: Number(
            source.critical
            || source.CRITICAL
            || 0
        ),
        high: Number(
            source.high
            || source.HIGH
            || 0
        ),
        medium: Number(
            source.medium
            || source.MEDIUM
            || 0
        ),
        low: Number(
            source.low
            || source.LOW
            || 0
        ),
    };
}

function getReportSummary(payload) {
    if (!payload || typeof payload !== "object") {
        return null;
    }

    if (
        payload.summary
        && typeof payload.summary === "object"
    ) {
        return payload.summary;
    }

    if (
        payload.report
        && payload.report.summary
        && typeof payload.report.summary === "object"
    ) {
        return payload.report.summary;
    }

    if (
        payload.data
        && payload.data.summary
        && typeof payload.data.summary === "object"
    ) {
        return payload.data.summary;
    }

    return null;
}

function getLatestScanTimestamp(project, report) {
    const scan = (
        project.latest_scan
        || report?.scan
        || {}
    );

    const candidates = [
        scan.completed_at,
        scan.finished_at,
        scan.updated_at,
        scan.started_at,
        scan.created_at,
        report?.generated_at,
        project.updated_at,
        project.created_at,
    ];

    for (const value of candidates) {
        if (!value) {
            continue;
        }

        const timestamp = new Date(value).getTime();

        if (Number.isFinite(timestamp)) {
            return {
                raw: value,
                timestamp,
            };
        }
    }

    return {
        raw: null,
        timestamp: 0,
    };
}

function formatSecurityDateTime(value) {
    if (!value) {
        return "Completed scan";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "Completed scan";
    }

    return new Intl.DateTimeFormat(
        undefined,
        {
            day: "2-digit",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
        },
    ).format(date);
}

function getPostureFromSecurityData(
    score,
    severityCounts,
) {
    if (severityCounts.critical > 0) {
        return {
            label: "Critical",
            className: "posture-critical",
            ringClass: "score-critical",
        };
    }

    if (severityCounts.high > 0) {
        return {
            label: "High Risk",
            className: "posture-high",
            ringClass: "score-high",
        };
    }

    if (
        severityCounts.medium > 0
        || (
            Number.isFinite(score)
            && score < 70
        )
    ) {
        return {
            label: "Needs Review",
            className: "posture-medium",
            ringClass: "score-medium",
        };
    }

    if (
        severityCounts.low > 0
        || (
            Number.isFinite(score)
            && score < 85
        )
    ) {
        return {
            label: "Moderate",
            className: "posture-low",
            ringClass: "score-good",
        };
    }

    return {
        label: "Secure",
        className: "posture-secure",
        ringClass: "score-excellent",
    };
}

function animateMetric(element, value) {
    if (!element) {
        return;
    }

    element.textContent = String(value);
    element.classList.add("metric-updated");

    window.setTimeout(
        () => {
            element.classList.remove(
                "metric-updated"
            );
        },
        240,
    );
}

function resetExecutiveSecurityDashboard() {
    animateMetric(elements.criticalRiskMetric, 0);
    animateMetric(elements.highRiskMetric, 0);
    animateMetric(elements.mediumRiskMetric, 0);
    animateMetric(elements.lowRiskMetric, 0);
    animateMetric(elements.criticalFindingSummary, 0);

    if (elements.securityScoreValue) {
        elements.securityScoreValue.textContent = "—";
    }

    if (elements.securityScoreLabel) {
        elements.securityScoreLabel.textContent =
            "Security Score";
    }

    if (elements.securityScoreRing) {
        elements.securityScoreRing.style.setProperty(
            "--security-score-angle",
            "0deg",
        );

        elements.securityScoreRing.classList.remove(
            "has-score",
            "score-critical",
            "score-high",
            "score-medium",
            "score-good",
            "score-excellent",
        );

        elements.securityScoreRing.setAttribute(
            "aria-label",
            "Security score unavailable",
        );
    }

    if (elements.latestPostureValue) {
        elements.latestPostureValue.textContent =
            "Pending";

        elements.latestPostureValue.className = "";
    }

    if (elements.latestScanProject) {
        elements.latestScanProject.textContent =
            "No completed scan";
    }

    if (elements.latestScanTime) {
        elements.latestScanTime.textContent =
            "Security findings and score will populate "
            + "after the first completed source-code scan.";
    }
}

function renderExecutiveSecurityDashboard(data) {
    const score = clampSecurityScore(
        data.securityScore
    );

    const severityCounts =
        normalizeSeverityCounts(
            data.severityCounts
        );

    animateMetric(
        elements.criticalRiskMetric,
        severityCounts.critical,
    );

    animateMetric(
        elements.highRiskMetric,
        severityCounts.high,
    );

    animateMetric(
        elements.mediumRiskMetric,
        severityCounts.medium,
    );

    animateMetric(
        elements.lowRiskMetric,
        severityCounts.low,
    );

    animateMetric(
        elements.criticalFindingSummary,
        severityCounts.critical,
    );

    if (
        score !== null
        && elements.securityScoreValue
    ) {
        elements.securityScoreValue.textContent =
            `${score}`;

        elements.securityScoreValue.classList.add(
            "score-updated"
        );

        window.setTimeout(
            () => {
                elements.securityScoreValue
                    .classList.remove(
                        "score-updated"
                    );
            },
            260,
        );
    }

    const posture = getPostureFromSecurityData(
        score,
        severityCounts,
    );

    if (elements.securityScoreRing) {
        const angle = (
            score === null
                ? 0
                : score * 3.6
        );

        elements.securityScoreRing.style.setProperty(
            "--security-score-angle",
            `${angle}deg`,
        );

        elements.securityScoreRing.classList.remove(
            "score-critical",
            "score-high",
            "score-medium",
            "score-good",
            "score-excellent",
        );

        elements.securityScoreRing.classList.add(
            "has-score",
            posture.ringClass,
        );

        elements.securityScoreRing.setAttribute(
            "aria-label",
            score === null
                ? "Security score unavailable"
                : `Overall security score ${score} out of 100`,
        );
    }

    if (elements.latestPostureValue) {
        elements.latestPostureValue.textContent =
            posture.label;

        elements.latestPostureValue.className =
            posture.className;
    }

    if (elements.latestScanProject) {
        elements.latestScanProject.textContent =
            data.latestProjectName
            || "Completed security scan";
    }

    if (elements.latestScanTime) {
        const scoreText = (
            score === null
                ? ""
                : ` · Score ${score}/100`
        );

        elements.latestScanTime.textContent =
            `${formatSecurityDateTime(
                data.latestScanAt
            )}${scoreText}`;
    }
}

async function loadProjectSecurityReport(project) {
    const response = await apiFetch(
        `/projects/${project.id}/report`,
    );

    if (!response.ok) {
        return null;
    }

    const report = await parseResponse(response);
    const summary = getReportSummary(report);

    if (!summary) {
        return null;
    }

    const severityCounts =
        normalizeSeverityCounts(
            summary.severity_counts
            || summary.severity_summary
            || report.severity_counts
            || {},
        );

    const score = clampSecurityScore(
        summary.score
        ?? summary.security_score
        ?? project.security_score,
    );

    const scanDate = getLatestScanTimestamp(
        project,
        report,
    );

    return {
        project,
        report,
        score,
        severityCounts,
        latestScanAt: scanDate.raw,
        latestScanTimestamp:
            scanDate.timestamp,
    };
}

async function refreshExecutiveSecurityDashboard(
    projects,
) {
    const candidates = projects.filter(
        (project) => {
            const status = String(
                project.status || ""
            ).toLowerCase();

            return (
                status === "completed"
                || project.report_available === true
                || Number(project.security_score || 0) > 0
            );
        },
    );

    const dashboardKey = candidates
        .map(
            (project) => [
                project.id,
                project.status,
                project.security_score,
                project.updated_at,
            ].join(":")
        )
        .join("|");

    if (
        state.securityDashboardLoading
        || (
            dashboardKey
            && dashboardKey
                === state.securityDashboardKey
        )
    ) {
        return;
    }

    state.securityDashboardKey = dashboardKey;

    if (candidates.length === 0) {
        resetExecutiveSecurityDashboard();
        return;
    }

    state.securityDashboardLoading = true;

    try {
        const results = await Promise.allSettled(
            candidates.map(
                loadProjectSecurityReport
            ),
        );

        const reports = results
            .filter(
                (result) =>
                    result.status === "fulfilled"
                    && result.value
            )
            .map(
                (result) => result.value
            );

        if (reports.length === 0) {
            resetExecutiveSecurityDashboard();
            return;
        }

        const severityCounts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        const validScores = [];

        for (const item of reports) {
            severityCounts.critical +=
                item.severityCounts.critical;

            severityCounts.high +=
                item.severityCounts.high;

            severityCounts.medium +=
                item.severityCounts.medium;

            severityCounts.low +=
                item.severityCounts.low;

            if (item.score !== null) {
                validScores.push(item.score);
            }
        }

        const latestReport = reports
            .slice()
            .sort(
                (left, right) =>
                    right.latestScanTimestamp
                    - left.latestScanTimestamp
            )[0];

        const securityScore = (
            validScores.length > 0
                ? Math.round(
                    validScores.reduce(
                        (total, value) =>
                            total + value,
                        0,
                    )
                    / validScores.length
                )
                : null
        );

        renderExecutiveSecurityDashboard({
            securityScore,
            severityCounts,
            latestProjectName:
                latestReport.project.name,
            latestScanAt:
                latestReport.latestScanAt,
        });

    } catch (error) {
        console.error(
            "Unable to aggregate security dashboard",
            error,
        );

        resetExecutiveSecurityDashboard();

    } finally {
        state.securityDashboardLoading = false;
    }
}

function updateMetrics(projects) {
    const countStatus = (status) => (
        projects.filter(
            (project) =>
                String(project.status)
                    .toLowerCase()
                === status
        ).length
    );

    elements.totalProjectsMetric.textContent =
        projects.length;

    elements.readyProjectsMetric.textContent =
        countStatus("ready");

    elements.scanningProjectsMetric.textContent =
        countStatus("scanning");

    elements.completedProjectsMetric.textContent =
        countStatus("completed");

    if (elements.applicationSummary) {
        elements.applicationSummary.textContent =
            projects.length;
    }

    if (elements.activeScanSummary) {
        elements.activeScanSummary.textContent =
            countStatus("scanning");
    }

    void refreshExecutiveSecurityDashboard(
        projects
    );
}

function renderProjects(projects) {
    elements.projectLoadingState.classList.add(
        "hidden"
    );

    updateMetrics(state.projects);

    if (projects.length === 0) {
        elements.projectsGrid.classList.add(
            "hidden"
        );

        elements.projectEmptyState.classList.remove(
            "hidden"
        );

        return;
    }

    elements.projectEmptyState.classList.add(
        "hidden"
    );

    elements.projectsGrid.classList.remove(
        "hidden"
    );

    elements.projectsGrid.innerHTML = projects
        .map((project) => {
            const status = getStatusClass(
                project.status
            );

            const description = (
                project.description
                || "No description provided."
            );

            const canScan = ![
                "scanning",
            ].includes(status);

            return `
                <article
                    class="project-card"
                    data-project-id="${project.id}"
                >
                    <div class="project-card-top">

                        <div class="project-identity">

                            <div class="framework-icon">
                                ${escapeHtml(
                                    getFrameworkShortName(
                                        project.detected_framework
                                    )
                                )}
                            </div>

                            <div>
                                <h3 class="project-name">
                                    ${escapeHtml(project.name)}
                                </h3>

                                <small>
                                    ${escapeHtml(
                                        project.detected_framework
                                        || "Framework pending"
                                    )}
                                </small>
                            </div>

                        </div>

                        <span
                            class="status-badge status-${status}"
                        >
                            ${escapeHtml(status)}
                        </span>

                    </div>

                    <p class="project-description">
                        ${escapeHtml(description)}
                    </p>

                    <div class="project-meta-grid">

                        <div class="project-meta-item">
                            <span>Language</span>
                            <strong>
                                ${escapeHtml(
                                    project.detected_language
                                    || "Unknown"
                                )}
                            </strong>
                        </div>

                        <div class="project-meta-item">
                            <span>Version</span>
                            <strong>
                                ${escapeHtml(
                                    project.version
                                    || "—"
                                )}
                            </strong>
                        </div>

                        <div class="project-meta-item">
                            <span>API Count</span>
                            <strong>
                                ${Number(
                                    project.api_count || 0
                                )}
                            </strong>
                        </div>

                        <div class="project-meta-item">
                            <span>Security Score</span>
                            <strong>
                                ${Number(
                                    project.security_score || 0
                                )}/100
                            </strong>
                        </div>

                        <div class="project-meta-item">
                            <span>Uploaded</span>
                            <strong>
                                ${formatDate(
                                    project.created_at
                                )}
                            </strong>
                        </div>

                        <div class="project-meta-item">
                            <span>Project ID</span>
                            <strong>
                                #${Number(project.id)}
                            </strong>
                        </div>

                    </div>

                    <div class="project-actions">

                        <button
                            class="button button-primary scan-button"
                            type="button"
                            data-project-id="${project.id}"
                            ${canScan ? "" : "disabled"}
                        >
                            ${
                                status === "scanning"
                                    ? "Scanning..."
                                    : "Start Scan"
                            }
                        </button>

                        <button
                            class="button button-danger delete-button"
                            type="button"
                            data-project-id="${project.id}"
                        >
                            Delete
                        </button>

                        ${status === "completed" ? `
                            <button
                                class="button button-secondary view-report-button"
                                type="button"
                                data-project-id="${project.id}"
                            >
                                View Findings
                            </button>

                            <button
                                class="text-button report-button"
                                type="button"
                                data-project-id="${project.id}"
                                data-report-format="json"
                            >
                                Download JSON
                            </button>
                        ` : ""}

                        ${status === "scanning" ? `
                            <button
                                class="button button-secondary scan-progress-button"
                                type="button"
                                data-project-id="${project.id}"
                            >
                                View Progress
                            </button>
                        ` : ""}

                    </div>

                </article>
            `;
        })
        .join("");

    bindProjectActions();
}

function bindProjectActions() {
    document
        .querySelectorAll(".scan-button")
        .forEach((button) => {
            button.addEventListener(
                "click",
                () => {
                    startScan(
                        Number(
                            button.dataset.projectId
                        )
                    );
                },
            );
        });

    document
        .querySelectorAll(".delete-button")
        .forEach((button) => {
            button.addEventListener(
                "click",
                () => {
                    deleteProject(
                        Number(
                            button.dataset.projectId
                        )
                    );
                },
            );
        });

    document
        .querySelectorAll(".report-button")
        .forEach((button) => {
            button.addEventListener(
                "click",
                () => {
                    downloadReport(
                        Number(button.dataset.projectId),
                        button.dataset.reportFormat,
                    );
                },
            );
        });

    document
        .querySelectorAll(".view-report-button")
        .forEach((button) => {
            button.addEventListener("click", () => {
                const project = state.projects.find(
                    (item) => item.id === Number(button.dataset.projectId)
                );
                if (project) openReportViewer(project.id, project.name);
            });
        });

    document
        .querySelectorAll(".scan-progress-button")
        .forEach((button) => {
            button.addEventListener("click", () => {
                const project = state.projects.find(
                    (item) => item.id === Number(button.dataset.projectId)
                );
                if (project) openScanMonitor(project.id, project.name);
            });
        });
}

async function loadCurrentUser() {
    const response = await apiFetch(
        "/auth/me"
    );

    if (!response.ok) {
        throw new Error(
            "Your session has expired."
        );
    }

    state.currentUser =
        await response.json();

    const name = (
        state.currentUser.full_name
        || state.currentUser.email
        || "User"
    );

    elements.sidebarUserName.textContent = name;

    elements.sidebarUserEmail.textContent =
        state.currentUser.email || "—";

    elements.sidebarUserAvatar.textContent =
        name.trim().charAt(0).toUpperCase() || "U";
}

async function loadProjects() {
    elements.projectLoadingState.classList.remove(
        "hidden"
    );

    elements.projectEmptyState.classList.add(
        "hidden"
    );

    elements.projectsGrid.classList.add(
        "hidden"
    );

    try {
        const response = await apiFetch(
            "/projects"
        );

        const data = await parseResponse(
            response
        );

        if (!response.ok) {
            throw new Error(
                data.detail
                || "Unable to load projects."
            );
        }

        state.projects = Array.isArray(
            data.projects
        )
            ? data.projects
            : [];

        renderProjects(state.projects);

    } catch (error) {
        elements.projectLoadingState.classList.add(
            "hidden"
        );

        elements.projectEmptyState.classList.remove(
            "hidden"
        );

        showToast(
            error.message,
            "error",
        );
    }
}

async function handleLogin(event) {
    event.preventDefault();

    const formData = new FormData(
        elements.loginForm
    );

    const payload = {
        email: String(
            formData.get("email") || ""
        ).trim(),
        password: String(
            formData.get("password") || ""
        ),
    };

    setFormMessage(
        elements.authMessage
    );

    elements.loginButton.disabled = true;
    elements.loginButton.textContent =
        "Signing In...";

    try {
        const response = await fetch(
            `${API_BASE}/auth/login`,
            {
                method: "POST",
                headers: {
                    "Content-Type":
                        "application/json",
                },
                body: JSON.stringify(payload),
            },
        );

        const data = await parseResponse(
            response
        );

        if (!response.ok) {
            throw new Error(
                data.detail
                || "Unable to sign in."
            );
        }

        setTokens(
            data.access_token,
            data.refresh_token,
        );

        await loadCurrentUser();

        showDashboardView();
        await loadProjects();
        openRequestedReport();

        elements.loginForm.reset();

    } catch (error) {
        clearSession();

        setFormMessage(
            elements.authMessage,
            error.message,
            "error",
        );

    } finally {
        elements.loginButton.disabled = false;
        elements.loginButton.textContent =
            "Sign In";
    }
}

async function handleSignup(event) {
    event.preventDefault();
    const formData = new FormData(elements.signupForm);
    const email = String(formData.get("email") || "").trim();
    const password = String(formData.get("password") || "");
    const confirmation = String(
        formData.get("password_confirmation") || ""
    );

    setFormMessage(elements.signupMessage);

    if (password !== confirmation) {
        setFormMessage(
            elements.signupMessage,
            "Passwords do not match.",
            "error",
        );
        return;
    }

    if (!formData.get("terms")) {
        setFormMessage(
            elements.signupMessage,
            "You must accept the terms and privacy policy.",
            "error",
        );
        return;
    }

    elements.signupButton.disabled = true;
    elements.signupButton.textContent = "Creating Account...";

    try {
        const response = await fetch(`${API_BASE}/auth/signup`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                full_name: String(formData.get("full_name") || "").trim(),
                email,
                password,
            }),
        });
        const data = await parseResponse(response);

        if (!response.ok) {
            throw new Error(
                getErrorMessage(data, "Unable to create your account.")
            );
        }

        elements.resendEmail.value = email;
        elements.checkEmailText.textContent =
            `We sent a verification link to ${email}.`;
        elements.signupForm.reset();
        showAuthPanel("checkEmail");
    } catch (error) {
        setFormMessage(
            elements.signupMessage,
            error.message,
            "error",
        );
    } finally {
        elements.signupButton.disabled = false;
        elements.signupButton.textContent = "Create Account";
    }
}

async function handleForgotPassword(event) {
    event.preventDefault();
    const formData = new FormData(elements.forgotPasswordForm);
    elements.forgotPasswordButton.disabled = true;
    setFormMessage(elements.forgotPasswordMessage);

    try {
        const response = await fetch(`${API_BASE}/auth/forgot-password`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                email: String(formData.get("email") || "").trim(),
            }),
        });
        const data = await parseResponse(response);
        if (!response.ok) {
            throw new Error(
                getErrorMessage(data, "Unable to request a password reset.")
            );
        }
        setFormMessage(
            elements.forgotPasswordMessage,
            data.message,
            "success",
        );
    } catch (error) {
        setFormMessage(
            elements.forgotPasswordMessage,
            error.message,
            "error",
        );
    } finally {
        elements.forgotPasswordButton.disabled = false;
    }
}

async function handleResendVerification(event) {
    event.preventDefault();
    const formData = new FormData(elements.resendVerificationForm);
    elements.resendVerificationButton.disabled = true;
    setFormMessage(elements.resendVerificationMessage);

    try {
        const response = await fetch(`${API_BASE}/auth/resend-verification`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                email: String(formData.get("email") || "").trim(),
            }),
        });
        const data = await parseResponse(response);
        if (!response.ok) {
            throw new Error(
                getErrorMessage(data, "Unable to resend verification email.")
            );
        }
        setFormMessage(
            elements.resendVerificationMessage,
            data.message,
            "success",
        );
    } catch (error) {
        setFormMessage(
            elements.resendVerificationMessage,
            error.message,
            "error",
        );
    } finally {
        elements.resendVerificationButton.disabled = false;
    }
}

async function verifyEmailToken(token) {
    showAuthPanel("verify");
    elements.verifyStatusIcon.textContent = "...";

    if (!token) {
        elements.verifyStatusIcon.textContent = "!";
        elements.verifyStatusIcon.classList.add("error");
        elements.verifyTitle.textContent = "Verification link is invalid";
        elements.verifyMessage.textContent =
            "Request a new verification email and try again.";
        elements.verifyLoginButton.classList.remove("hidden");
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/auth/verify-email`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({token}),
        });
        const data = await parseResponse(response);
        if (!response.ok) {
            throw new Error(
                getErrorMessage(data, "Unable to verify this email link.")
            );
        }
        elements.verifyStatusIcon.textContent = "OK";
        elements.verifyStatusIcon.classList.add("success");
        elements.verifyTitle.textContent = "Email verified";
        elements.verifyMessage.textContent =
            "Your account is active. You can now sign in.";
        window.history.replaceState({}, "", "/dashboard");
    } catch (error) {
        elements.verifyStatusIcon.textContent = "!";
        elements.verifyStatusIcon.classList.add("error");
        elements.verifyTitle.textContent = "Verification failed";
        elements.verifyMessage.textContent = error.message;
    }

    elements.verifyLoginButton.classList.remove("hidden");
}

async function handleResetPassword(event) {
    event.preventDefault();
    const formData = new FormData(elements.resetPasswordForm);
    const password = String(formData.get("password") || "");
    const confirmation = String(
        formData.get("password_confirmation") || ""
    );
    const token = new URLSearchParams(window.location.search).get("token");

    setFormMessage(elements.resetPasswordMessage);
    if (password !== confirmation) {
        setFormMessage(
            elements.resetPasswordMessage,
            "Passwords do not match.",
            "error",
        );
        return;
    }
    if (!token) {
        setFormMessage(
            elements.resetPasswordMessage,
            "This password reset link is invalid.",
            "error",
        );
        return;
    }

    elements.resetPasswordButton.disabled = true;
    try {
        const response = await fetch(`${API_BASE}/auth/reset-password`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({token, new_password: password}),
        });
        const data = await parseResponse(response);
        if (!response.ok) {
            throw new Error(
                getErrorMessage(data, "Unable to reset your password.")
            );
        }
        elements.resetPasswordForm.reset();
        setFormMessage(
            elements.resetPasswordMessage,
            data.message,
            "success",
        );
        window.history.replaceState({}, "", "/dashboard");
    } catch (error) {
        setFormMessage(
            elements.resetPasswordMessage,
            error.message,
            "error",
        );
    } finally {
        elements.resetPasswordButton.disabled = false;
    }
}

function openUploadModal() {
    elements.uploadModal.classList.remove(
        "hidden"
    );

    document.body.style.overflow = "hidden";

    window.setTimeout(
        () => {
            document
                .getElementById("projectName")
                .focus();
        },
        50,
    );
}

function closeUploadModal() {
    elements.uploadModal.classList.add(
        "hidden"
    );

    document.body.style.overflow = "";

    elements.uploadForm.reset();

    elements.selectedFile.classList.add(
        "hidden"
    );

    elements.uploadProgressContainer.classList.add(
        "hidden"
    );

    elements.uploadProgressBar.style.width = "0%";
    elements.uploadProgressText.textContent = "0%";

    setFormMessage(
        elements.uploadMessage
    );
}

function updateSelectedFile() {
    const file = elements.projectFile.files[0];

    if (!file) {
        elements.selectedFile.classList.add(
            "hidden"
        );

        elements.selectedFile.innerHTML = "";

        return;
    }

    elements.selectedFile.innerHTML = `
        <strong>${escapeHtml(file.name)}</strong>
        · ${formatBytes(file.size)}
    `;

    elements.selectedFile.classList.remove(
        "hidden"
    );
}

async function handleUpload(event) {
    event.preventDefault();

    const file = elements.projectFile.files[0];

    if (!file) {
        setFormMessage(
            elements.uploadMessage,
            "Select a project archive.",
            "error",
        );

        return;
    }

    const formData = new FormData(
        elements.uploadForm
    );

    setFormMessage(
        elements.uploadMessage
    );

    elements.submitUploadButton.disabled = true;
    elements.cancelUploadButton.disabled = true;

    elements.submitUploadButton.textContent =
        "Uploading...";

    elements.uploadProgressContainer.classList.remove(
        "hidden"
    );

    let progress = 8;

    const progressTimer = window.setInterval(
        () => {
            if (progress < 88) {
                progress += Math.max(
                    1,
                    Math.round(
                        (88 - progress) * 0.08
                    )
                );

                elements.uploadProgressBar.style.width =
                    `${progress}%`;

                elements.uploadProgressText.textContent =
                    `${progress}%`;
            }
        },
        280,
    );

    try {
        const response = await apiFetch(
            "/projects/upload",
            {
                method: "POST",
                body: formData,
            },
        );

        const data = await parseResponse(
            response
        );

        if (!response.ok) {
            throw new Error(
                data.detail
                || "Project upload failed."
            );
        }

        progress = 100;

        elements.uploadProgressBar.style.width =
            "100%";

        elements.uploadProgressText.textContent =
            "100%";

        setFormMessage(
            elements.uploadMessage,
            "Project uploaded successfully.",
            "success",
        );

        showToast(
            `${data.name} uploaded successfully.`,
            "success",
        );

        await loadProjects();

        window.setTimeout(
            closeUploadModal,
            550,
        );

    } catch (error) {
        setFormMessage(
            elements.uploadMessage,
            error.message,
            "error",
        );

    } finally {
        window.clearInterval(progressTimer);

        elements.submitUploadButton.disabled =
            false;

        elements.cancelUploadButton.disabled =
            false;

        elements.submitUploadButton.textContent =
            "Upload & Analyze";
    }
}

async function startScan(projectId) {
    const project = state.projects.find(
        (item) => item.id === projectId
    );

    if (!project) {
        return;
    }

    try {
        const response = await apiFetch(
            `/projects/${projectId}/scan`,
            {
                method: "POST",
            },
        );

        const data = await parseResponse(
            response
        );

        if (!response.ok) {
            throw new Error(
                data.detail
                || "Unable to start scan."
            );
        }

        project.status = "scanning";

        renderProjects(
            filterProjects(
                elements.projectSearchInput.value
            )
        );

        showToast(
            `Security scan queued for ${project.name}.`,
            "success",
        );

        openScanMonitor(projectId, project.name);
        pollScan(projectId, project.name);

    } catch (error) {
        showToast(
            error.message,
            "error",
        );
    }
}

function openScanMonitor(projectId, projectName) {
    const query = new URLSearchParams({
        project_id: String(projectId),
        project_name: projectName,
    });
    elements.scanMonitorFrame.src = `/scan-monitor?${query.toString()}`;
    elements.minimizedScanLabel.textContent = `${projectName} scan`;
    elements.scanMonitorPanel.classList.remove("hidden");
    elements.scanMonitorFrameShell.classList.remove("hidden");
    elements.restoreScanMonitorButton.classList.add("hidden");
}

function minimizeScanMonitor() {
    elements.scanMonitorFrameShell.classList.add("hidden");
    elements.restoreScanMonitorButton.classList.remove("hidden");
}

function restoreScanMonitor() {
    elements.scanMonitorFrameShell.classList.remove("hidden");
    elements.restoreScanMonitorButton.classList.add("hidden");
}

function openReportViewer(projectId, projectName) {
    const query = new URLSearchParams({
        project_id: String(projectId),
        project_name: projectName,
    });
    elements.reportViewerFrame.src = `/report-viewer?${query.toString()}`;
    elements.reportViewerPanel.classList.remove("hidden");
    document.body.style.overflow = "hidden";
}

function closeReportViewer() {
    elements.reportViewerPanel.classList.add("hidden");
    elements.reportViewerFrame.src = "about:blank";
    document.body.style.overflow = "";
}

function openRequestedReport() {
    const query = new URLSearchParams(window.location.search);
    const projectId = Number(query.get("report_project_id"));
    if (!projectId) return;
    const project = state.projects.find((item) => item.id === projectId);
    if (!project) return;
    openReportViewer(project.id, project.name);
    window.history.replaceState({}, "", "/dashboard");
}

async function pollScan(projectId, projectName) {
    for (let attempt = 0; attempt < 120; attempt += 1) {
        await new Promise((resolve) => {
            window.setTimeout(resolve, 1500);
        });

        try {
            const response = await apiFetch(
                `/projects/${projectId}/status`
            );
            const data = await parseResponse(response);

            if (!response.ok) {
                return;
            }

            const scanStatus = data.latest_scan?.status;
            if (scanStatus === "completed") {
                await loadProjects();
                showToast(
                    `Security scan completed for ${projectName}.`,
                    "success",
                );
                return;
            }

            if (["failed", "cancelled"].includes(scanStatus)) {
                await loadProjects();
                showToast(
                    scanStatus === "cancelled"
                        ? `Security scan cancelled for ${projectName}.`
                        : `Security scan failed for ${projectName}.`,
                    scanStatus === "cancelled" ? "success" : "error",
                );
                return;
            }
        } catch (error) {
            return;
        }
    }
}

async function downloadReport(projectId, format) {
    try {
        const response = await apiFetch(
            `/projects/${projectId}/report?format=${format}`
        );
        if (!response.ok) {
            const data = await parseResponse(response);
            throw new Error(
                data.detail || "Unable to load the security report."
            );
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);

        if (format === "html") {
            window.open(url, "_blank", "noopener,noreferrer");
            window.setTimeout(() => URL.revokeObjectURL(url), 60000);
            return;
        }

        const link = document.createElement("a");
        link.href = url;
        link.download = `api-sentry-project-${projectId}-report.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
    } catch (error) {
        showToast(error.message, "error");
    }
}

async function deleteProject(projectId) {
    const project = state.projects.find(
        (item) => item.id === projectId
    );

    if (!project) {
        return;
    }

    const confirmed = window.confirm(
        `Delete "${project.name}" and its uploaded source files?`
    );

    if (!confirmed) {
        return;
    }

    try {
        const response = await apiFetch(
            `/projects/${projectId}`,
            {
                method: "DELETE",
            },
        );

        const data = await parseResponse(
            response
        );

        if (!response.ok) {
            throw new Error(
                data.detail
                || "Unable to delete project."
            );
        }

        state.projects = state.projects.filter(
            (item) => item.id !== projectId
        );

        renderProjects(
            filterProjects(
                elements.projectSearchInput.value
            )
        );

        showToast(
            `${project.name} deleted.`,
            "success",
        );

    } catch (error) {
        showToast(
            error.message,
            "error",
        );
    }
}

function filterProjects(query) {
    const normalized = String(query || "")
        .trim()
        .toLowerCase();

    if (!normalized) {
        return state.projects;
    }

    return state.projects.filter(
        (project) => {
            const searchable = [
                project.name,
                project.description,
                project.detected_language,
                project.detected_framework,
                project.status,
            ]
                .filter(Boolean)
                .join(" ")
                .toLowerCase();

            return searchable.includes(
                normalized
            );
        },
    );
}

async function logout() {
    try {
        if (state.accessToken) {
            await apiFetch(
                "/auth/logout",
                {
                    method: "POST",
                },
                false,
            );
        }
    } catch (error) {
        console.error(error);
    }

    clearSession();
    showAuthView();

    showToast(
        "Signed out successfully.",
        "success",
    );
}

function bindEvents() {
    elements.loginForm.addEventListener(
        "submit",
        handleLogin,
    );

    elements.signupForm.addEventListener(
        "submit",
        handleSignup,
    );

    elements.forgotPasswordForm.addEventListener(
        "submit",
        handleForgotPassword,
    );

    elements.resendVerificationForm.addEventListener(
        "submit",
        handleResendVerification,
    );

    elements.resetPasswordForm.addEventListener(
        "submit",
        handleResetPassword,
    );

    elements.authPanelButtons.forEach((button) => {
        button.addEventListener("click", () => {
            const panelName = button.dataset.authPanel;
            if (panelName === "login") {
                window.history.replaceState({}, "", "/dashboard");
            }
            showAuthPanel(panelName);
        });
    });

    elements.logoutButton.addEventListener(
        "click",
        logout,
    );

    [
        elements.uploadProjectButton,
        elements.sidebarUploadButton,
        elements.bannerUploadButton,
        elements.emptyUploadButton,
    ].forEach((button) => {
        button.addEventListener(
            "click",
            openUploadModal,
        );
    });

    elements.closeUploadModalButton.addEventListener(
        "click",
        closeUploadModal,
    );

    elements.cancelUploadButton.addEventListener(
        "click",
        closeUploadModal,
    );

    elements.uploadModal
        .querySelector(".modal-backdrop")
        .addEventListener(
            "click",
            closeUploadModal,
        );

    elements.uploadForm.addEventListener(
        "submit",
        handleUpload,
    );

    elements.projectFile.addEventListener(
        "change",
        updateSelectedFile,
    );

    elements.refreshButton.addEventListener(
        "click",
        loadProjects,
    );

    elements.minimizeScanMonitorButton.addEventListener(
        "click",
        minimizeScanMonitor,
    );

    elements.restoreScanMonitorButton.addEventListener(
        "click",
        restoreScanMonitor,
    );

    window.addEventListener("message", (event) => {
        if (event.origin !== window.location.origin) return;
        if (event.data?.type === "apisentry:minimize-scan-monitor") {
            minimizeScanMonitor();
            return;
        }
        if (event.data?.type === "apisentry:close-report-viewer") {
            closeReportViewer();
            return;
        }
        if (event.data?.type !== "apisentry:scan-status") return;

        elements.minimizedScanProgress.textContent =
            `${Number(event.data.progress || 0)}%`;
        if (["completed", "failed", "cancelled"].includes(event.data.status)) {
            loadProjects();
        }
    });

    elements.reportViewerPanel
        .querySelector(".report-viewer-backdrop")
        .addEventListener("click", closeReportViewer);

    elements.projectSearchInput.addEventListener(
        "input",
        (event) => {
            renderProjects(
                filterProjects(
                    event.target.value
                )
            );
        },
    );

    elements.mobileMenuButton.addEventListener(
        "click",
        () => {
            elements.sidebar.classList.toggle(
                "open"
            );
        },
    );

    elements.dropZone.addEventListener(
        "dragover",
        (event) => {
            event.preventDefault();

            elements.dropZone.classList.add(
                "dragging"
            );
        },
    );

    elements.dropZone.addEventListener(
        "dragleave",
        () => {
            elements.dropZone.classList.remove(
                "dragging"
            );
        },
    );

    elements.dropZone.addEventListener(
        "drop",
        () => {
            elements.dropZone.classList.remove(
                "dragging"
            );
        },
    );

    document.addEventListener(
        "keydown",
        (event) => {
            if (
                event.key === "Escape"
                && !elements.uploadModal.classList
                    .contains("hidden")
            ) {
                closeUploadModal();
            }
        },
    );
}

async function initialize() {
    bindEvents();

    const pathname = window.location.pathname;
    const query = new URLSearchParams(window.location.search);

    if (pathname === "/verify-email") {
        showAuthView();
        await verifyEmailToken(query.get("token"));
        return;
    }

    if (pathname === "/reset-password") {
        showAuthView();
        showAuthPanel("reset");
        return;
    }

    if (pathname === "/signup" && !state.accessToken) {
        showAuthView();
        showAuthPanel("signup");
        return;
    }

    if (!state.accessToken) {
        showAuthView();
        showAuthPanel("login");
        return;
    }

    try {
        await loadCurrentUser();

        showDashboardView();
        await loadProjects();
        openRequestedReport();

    } catch (error) {
        clearSession();
        showAuthView();
    }
}

initialize();
