from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.web.dashboard import router
from app.main import app as application


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


@pytest.mark.parametrize(
    "path",
    [
        "/dashboard",
        "/signup",
        "/login",
        "/verify-email?token=test-token",
        "/reset-password?token=test-token",
    ],
)
def test_authentication_pages_render(
    client: TestClient,
    path: str,
) -> None:
    response = client.get(path)

    assert response.status_code == 200
    assert 'id="authView"' in response.text


def test_dashboard_contains_complete_authentication_ui(
    client: TestClient,
) -> None:
    response = client.get("/dashboard")

    for element_id in (
        "loginForm",
        "signupForm",
        "forgotPasswordForm",
        "resendVerificationForm",
        "verifyPanel",
        "resetPasswordForm",
    ):
        assert f'id="{element_id}"' in response.text

    assert 'data-auth-panel="signup"' in response.text
    assert "check your spam or junk folder" in response.text
    assert 'src="/static/js/project-dashboard.js"' in response.text


def test_application_root_redirects_to_dashboard() -> None:
    app_client = TestClient(application)
    response = app_client.get(
        "/",
        follow_redirects=False,
    )

    assert response.status_code == 307
    assert response.headers["location"] == "/dashboard"


def test_scan_monitor_page_renders(client: TestClient) -> None:
    response = client.get("/scan-monitor?project_id=1")

    assert response.status_code == 200
    assert 'id="monitorProgressBar"' in response.text
    assert "Expected time remaining" in response.text
    assert 'src="/static/js/scan-monitor.js"' in response.text


def test_report_viewer_page_renders(client: TestClient) -> None:
    response = client.get("/report-viewer?project_id=1")

    assert response.status_code == 200
    assert 'id="findingsList"' in response.text
    assert "Recommended remediation" not in response.text
    assert 'src="/static/js/report-viewer.js"' in response.text
