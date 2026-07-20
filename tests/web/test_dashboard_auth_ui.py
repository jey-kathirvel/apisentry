from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.web.dashboard import router


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
    assert 'src="/static/js/project-dashboard.js"' in response.text
