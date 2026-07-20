"use strict";

const projectId = Number(new URLSearchParams(window.location.search).get("project_id"));
const stageOrder = ["preparing", "inventory", "discovery", "analysis", "reporting"];
const elements = {
    projectName: document.getElementById("monitorProjectName"),
    stage: document.getElementById("monitorStage"),
    percentage: document.getElementById("monitorPercentage"),
    progressBar: document.getElementById("monitorProgressBar"),
    message: document.getElementById("monitorMessage"),
    eta: document.getElementById("monitorEta"),
    status: document.getElementById("monitorStatus"),
    error: document.getElementById("monitorError"),
    stages: document.querySelectorAll("[data-stage]"),
    minimizeButton: document.getElementById("monitorMinimizeButton"),
};

function formatEta(seconds) {
    if (!Number.isFinite(seconds)) return "Calculating…";
    if (seconds <= 0) return "Less than a minute";
    const minutes = Math.ceil(seconds / 60);
    if (minutes === 1) return "About 1 minute";
    if (minutes < 60) return `About ${minutes} minutes`;
    const hours = Math.floor(minutes / 60);
    const remainder = minutes % 60;
    return `${hours}h ${remainder}m`;
}

function render(data) {
    const scan = data.latest_scan;
    if (!scan) return;
    const progress = Math.max(0, Math.min(100, Number(scan.progress || 0)));
    elements.stage.textContent = String(scan.current_stage || scan.status);
    elements.percentage.textContent = `${progress}%`;
    elements.progressBar.style.width = `${progress}%`;
    elements.message.textContent = scan.status_message || "Scan is running.";
    elements.eta.textContent = scan.status === "completed"
        ? "Complete"
        : scan.status === "failed"
            ? "Unavailable"
            : formatEta(scan.estimated_seconds_remaining);
    elements.status.textContent = scan.status;

    const activeIndex = stageOrder.indexOf(scan.current_stage);
    elements.stages.forEach((item, index) => {
        item.classList.toggle("complete", scan.status === "completed" || index < activeIndex);
        item.classList.toggle("active", scan.status !== "completed" && index === activeIndex);
    });

    window.parent.postMessage({
        type: "apisentry:scan-status",
        projectId,
        status: scan.status,
        progress,
    }, window.location.origin);
}

async function refresh() {
    const token = localStorage.getItem("apisentry_access_token");
    if (!projectId || !token) {
        elements.error.textContent = "Unable to load scan progress. Please sign in again.";
        elements.error.classList.remove("hidden");
        return false;
    }

    try {
        const response = await fetch(`/api/v1/projects/${projectId}/status`, {
            headers: {Authorization: `Bearer ${token}`},
        });
        if (!response.ok) throw new Error("Scan progress is unavailable.");
        const data = await response.json();
        render(data);
        return !["completed", "failed"].includes(data.latest_scan?.status);
    } catch (error) {
        elements.error.textContent = error.message;
        elements.error.classList.remove("hidden");
        return false;
    }
}

elements.minimizeButton.addEventListener("click", () => {
    window.parent.postMessage({type: "apisentry:minimize-scan-monitor"}, window.location.origin);
});

elements.projectName.textContent = new URLSearchParams(window.location.search).get("project_name") || `Project #${projectId}`;

async function poll() {
    const shouldContinue = await refresh();
    if (shouldContinue) window.setTimeout(poll, 1500);
}

poll();
