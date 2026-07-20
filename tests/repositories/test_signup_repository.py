from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
    timezone,
)

import pytest
from sqlalchemy import (
    create_engine,
    event,
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.email_verification import (
    EmailVerification,
)
from app.models.user import (
    User,
    UserStatus,
)
from app.repositories.signup_repository import (
    SQLAlchemySignupRepository,
)
from app.services.auth.exceptions import (
    DuplicateEmailError,
)


@pytest.fixture()
def db_session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={
            "check_same_thread": False,
        },
        poolclass=StaticPool,
    )

    @event.listens_for(
        engine,
        "connect",
    )
    def enable_sqlite_foreign_keys(
        dbapi_connection,
        _connection_record,
    ) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute(
            "PRAGMA foreign_keys=ON"
        )
        cursor.close()

    Base.metadata.create_all(
        bind=engine,
        tables=[
            User.__table__,
            EmailVerification.__table__,
        ],
    )

    session_factory = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    session = session_factory()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(
            bind=engine,
        )
        engine.dispose()


def test_email_exists_returns_false_for_unknown_email(
    db_session: Session,
) -> None:
    repository = SQLAlchemySignupRepository(
        db_session,
    )

    assert not repository.email_exists(
        "missing@example.com",
    )


def test_email_exists_is_case_insensitive(
    db_session: Session,
) -> None:
    db_session.add(
        User(
            full_name="Existing User",
            email="existing@example.com",
            password_hash="hashed-password",
        )
    )
    db_session.commit()

    repository = SQLAlchemySignupRepository(
        db_session,
    )

    assert repository.email_exists(
        "EXISTING@EXAMPLE.COM",
    )


def test_create_user_persists_pending_user(
    db_session: Session,
) -> None:
    repository = SQLAlchemySignupRepository(
        db_session,
    )

    expires_at = (
        datetime.now(
            timezone.utc,
        )
        + timedelta(
            hours=24,
        )
    )

    user = repository.create_user(
        full_name="Jey Kathirvel",
        email="jey@example.com",
        password_hash="secure-hash",
        verification_token_hash="token-hash",
        verification_token_expires_at=(
            expires_at
        ),
    )

    stored_user = db_session.execute(
        select(User).where(
            User.id == user.id,
        )
    ).scalar_one()

    assert stored_user.full_name == (
        "Jey Kathirvel"
    )
    assert stored_user.email == (
        "jey@example.com"
    )
    assert stored_user.password_hash == (
        "secure-hash"
    )
    assert stored_user.status == (
        UserStatus.PENDING_VERIFICATION
    )
    assert stored_user.is_email_verified is False
    assert stored_user.is_superuser is False


def test_create_user_persists_verification_record(
    db_session: Session,
) -> None:
    repository = SQLAlchemySignupRepository(
        db_session,
    )

    expires_at = (
        datetime.now(
            timezone.utc,
        )
        + timedelta(
            hours=24,
        )
    )

    user = repository.create_user(
        full_name="Jey Kathirvel",
        email="verify@example.com",
        password_hash="secure-hash",
        verification_token_hash=(
            "verification-token-hash"
        ),
        verification_token_expires_at=(
            expires_at
        ),
    )

    verification = db_session.execute(
        select(
            EmailVerification,
        ).where(
            EmailVerification.user_id
            == user.id,
        )
    ).scalar_one()

    assert verification.token_hash == (
        "verification-token-hash"
    )
    assert verification.used_at is None
    assert verification.expires_at is not None


def test_duplicate_email_raises_domain_exception(
    db_session: Session,
) -> None:
    repository = SQLAlchemySignupRepository(
        db_session,
    )

    expires_at = (
        datetime.now(
            timezone.utc,
        )
        + timedelta(
            hours=24,
        )
    )

    repository.create_user(
        full_name="First User",
        email="duplicate@example.com",
        password_hash="first-hash",
        verification_token_hash="token-1",
        verification_token_expires_at=(
            expires_at
        ),
    )

    with pytest.raises(
        DuplicateEmailError,
    ):
        repository.create_user(
            full_name="Second User",
            email="duplicate@example.com",
            password_hash="second-hash",
            verification_token_hash="token-2",
            verification_token_expires_at=(
                expires_at
            ),
        )


def test_transaction_rolls_back_when_token_is_duplicate(
    db_session: Session,
) -> None:
    repository = SQLAlchemySignupRepository(
        db_session,
    )

    expires_at = (
        datetime.now(
            timezone.utc,
        )
        + timedelta(
            hours=24,
        )
    )

    repository.create_user(
        full_name="First User",
        email="first@example.com",
        password_hash="first-hash",
        verification_token_hash=(
            "same-token-hash"
        ),
        verification_token_expires_at=(
            expires_at
        ),
    )

    with pytest.raises(
        IntegrityError,
    ):
        repository.create_user(
            full_name="Second User",
            email="second@example.com",
            password_hash="second-hash",
            verification_token_hash=(
                "same-token-hash"
            ),
            verification_token_expires_at=(
                expires_at
            ),
        )

    second_user = db_session.execute(
        select(User).where(
            User.email
            == "second@example.com",
        )
    ).scalar_one_or_none()

    assert second_user is None
