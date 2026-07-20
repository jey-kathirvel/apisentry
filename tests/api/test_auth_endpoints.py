from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.v1.auth import router
from app.db.session import get_db
from app.models.email_verification import EmailVerification
from app.models.user import User
from app.services.mail.exceptions import EmailDeliveryError
from app.services.auth.exceptions import WeakPasswordError
import app.api.v1.auth as auth_api
import app.services.auth_service as auth_service


class RecordingWorkflow:
    def __init__(self) -> None:
        self.tokens: list[str] = []
        self.welcome_count = 0

    def send_verification_email(self, *, token: str, **_kwargs):
        self.tokens.append(token)

    def send_welcome_email(self, **_kwargs):
        self.welcome_count += 1


def test_signup_verify_and_resend_http_lifecycle(monkeypatch) -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    User.__table__.create(engine)
    EmailVerification.__table__.create(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    workflow = RecordingWorkflow()
    monkeypatch.setattr(
        auth_service,
        "create_auth_email_workflow",
        lambda: workflow,
    )

    def override_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_db] = override_db

    with TestClient(app) as client:
        signup_response = client.post(
            "/api/v1/auth/signup",
            json={
                "full_name": "Jey Kathirvel",
                "email": "JEY@example.com",
                "password": "SecurePass1!",
            },
        )
        assert signup_response.status_code == 201
        assert signup_response.json()["email"] == "jey@example.com"
        assert len(workflow.tokens) == 1

        resend_response = client.post(
            "/api/v1/auth/resend-verification",
            json={"email": "jey@example.com"},
        )
        assert resend_response.status_code == 200
        assert len(workflow.tokens) == 2

        verify_response = client.post(
            "/api/v1/auth/verify-email",
            json={"token": workflow.tokens[-1]},
        )
        assert verify_response.status_code == 200
        assert workflow.welcome_count == 1

        reused_response = client.post(
            "/api/v1/auth/verify-email",
            json={"token": workflow.tokens[-1]},
        )
        assert reused_response.status_code == 400

        generic_response = client.post(
            "/api/v1/auth/resend-verification",
            json={"email": "missing@example.com"},
        )
        assert generic_response.status_code == 200

    with factory() as session:
        assert len(session.scalars(select(User)).all()) == 1
        records = session.scalars(select(EmailVerification)).all()
        assert len(records) == 2
        assert all(record.used_at is not None for record in records)

    engine.dispose()


def test_signup_delivery_failure_returns_retryable_response(
    monkeypatch,
) -> None:
    def fail_signup(**_kwargs):
        raise EmailDeliveryError(
            "SMTP unavailable",
            attempts=3,
            provider="smtp",
        )

    monkeypatch.setattr(auth_api, "create_user", fail_signup)
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/signup",
            json={
                "full_name": "Jey Kathirvel",
                "email": "jey@example.com",
                "password": "SecurePass1!",
            },
        )

    assert response.status_code == 503
    assert "try again" in response.json()["detail"].lower()


def test_signup_validation_error_returns_actionable_response(
    monkeypatch,
) -> None:
    def reject_password(**_kwargs):
        raise WeakPasswordError(
            "Password does not meet the security requirements.",
            errors=[
                "Password must contain at least one uppercase letter.",
                "Password must contain at least one number.",
            ],
        )

    monkeypatch.setattr(auth_api, "create_user", reject_password)
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/signup",
            json={
                "full_name": "Ads Team",
                "email": "team@ads-ai.in",
                "password": "password!",
            },
        )

    assert response.status_code == 422
    assert "uppercase" in response.json()["detail"]
    assert "number" in response.json()["detail"]
