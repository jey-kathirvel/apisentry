from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.email_verification import EmailVerification
from app.models.user import User, UserStatus
from app.schemas.auth import SignupRequest
from app.services.auth.token import compare_token_hash
from app.services.auth_service import (
    InvalidVerificationTokenError,
    create_user,
    resend_verification,
    verify_email,
)


class RecordingWorkflow:
    def __init__(
        self,
        *,
        fail_verification: bool = False,
        fail_welcome: bool = False,
    ) -> None:
        self.fail_verification = fail_verification
        self.fail_welcome = fail_welcome
        self.verification_messages: list[dict[str, object]] = []
        self.welcome_messages: list[dict[str, str]] = []

    def send_verification_email(self, **message):
        self.verification_messages.append(message)
        if self.fail_verification:
            raise RuntimeError("delivery failed")

    def send_welcome_email(self, **message):
        self.welcome_messages.append(message)
        if self.fail_welcome:
            raise RuntimeError("delivery failed")


@pytest.fixture()
def db_session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    User.__table__.create(engine)
    EmailVerification.__table__.create(engine)
    factory = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def signup_payload(email: str = "jey@example.com") -> SignupRequest:
    return SignupRequest(
        full_name="Jey Kathirvel",
        email=email,
        password="SecurePass1!",
    )


def test_signup_persists_user_and_token_only_after_delivery(
    db_session: Session,
) -> None:
    workflow = RecordingWorkflow()

    user = create_user(
        db_session,
        signup_payload(),
        email_workflow=workflow,
    )

    records = db_session.scalars(
        select(EmailVerification).where(
            EmailVerification.user_id == user.id
        )
    ).all()
    assert len(records) == 1
    assert user.status == UserStatus.PENDING_VERIFICATION
    assert user.is_email_verified is False
    assert len(workflow.verification_messages) == 1
    raw_token = workflow.verification_messages[0]["token"]
    assert isinstance(raw_token, str)
    assert raw_token != records[0].token_hash
    assert compare_token_hash(raw_token, records[0].token_hash)


def test_signup_delivery_failure_rolls_back_user_and_token(
    db_session: Session,
) -> None:
    with pytest.raises(RuntimeError, match="delivery failed"):
        create_user(
            db_session,
            signup_payload(),
            email_workflow=RecordingWorkflow(
                fail_verification=True
            ),
        )

    assert db_session.scalar(select(User.id)) is None
    assert db_session.scalar(select(EmailVerification.id)) is None


def test_verification_is_atomic_one_time_and_welcome_is_best_effort(
    db_session: Session,
) -> None:
    signup_workflow = RecordingWorkflow()
    user = create_user(
        db_session,
        signup_payload(),
        email_workflow=signup_workflow,
    )
    token = signup_workflow.verification_messages[0]["token"]
    welcome_workflow = RecordingWorkflow(fail_welcome=True)

    verified = verify_email(
        db_session,
        token,
        email_workflow=welcome_workflow,
    )

    assert verified.status == UserStatus.ACTIVE
    assert verified.is_email_verified is True
    assert len(welcome_workflow.welcome_messages) == 1
    record = db_session.scalar(select(EmailVerification))
    assert record is not None and record.used_at is not None

    with pytest.raises(InvalidVerificationTokenError):
        verify_email(
            db_session,
            token,
            email_workflow=RecordingWorkflow(),
        )


@pytest.mark.parametrize("token_state", ["invalid", "expired"])
def test_verification_rejects_invalid_or_expired_token(
    db_session: Session,
    token_state: str,
) -> None:
    workflow = RecordingWorkflow()
    create_user(
        db_session,
        signup_payload(),
        email_workflow=workflow,
    )
    token = workflow.verification_messages[0]["token"]

    if token_state == "invalid":
        token = "x" * 64
    else:
        record = db_session.scalar(select(EmailVerification))
        assert record is not None
        record.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db_session.commit()

    with pytest.raises(InvalidVerificationTokenError):
        verify_email(
            db_session,
            token,
            email_workflow=RecordingWorkflow(),
        )


def test_resend_supersedes_old_token_and_is_generic(
    db_session: Session,
) -> None:
    signup_workflow = RecordingWorkflow()
    user = create_user(
        db_session,
        signup_payload(),
        email_workflow=signup_workflow,
    )
    resend_workflow = RecordingWorkflow()

    resend_verification(
        db_session,
        user.email,
        email_workflow=resend_workflow,
    )
    resend_verification(
        db_session,
        "missing@example.com",
        email_workflow=resend_workflow,
    )

    records = db_session.scalars(
        select(EmailVerification)
        .where(EmailVerification.user_id == user.id)
        .order_by(EmailVerification.id)
    ).all()
    assert len(records) == 2
    assert records[0].used_at is not None
    assert records[1].used_at is None
    assert len(resend_workflow.verification_messages) == 1


def test_resend_delivery_failure_preserves_previous_token(
    db_session: Session,
) -> None:
    signup_workflow = RecordingWorkflow()
    user = create_user(
        db_session,
        signup_payload(),
        email_workflow=signup_workflow,
    )

    resend_verification(
        db_session,
        user.email,
        email_workflow=RecordingWorkflow(fail_verification=True),
    )

    records = db_session.scalars(
        select(EmailVerification).where(
            EmailVerification.user_id == user.id
        )
    ).all()
    assert len(records) == 1
    assert records[0].used_at is None
