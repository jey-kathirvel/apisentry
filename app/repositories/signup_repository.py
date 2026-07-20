from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.email_verification import (
    EmailVerification,
)
from app.models.user import (
    User,
    UserStatus,
)
from app.services.auth.exceptions import (
    DuplicateEmailError,
)


class SQLAlchemySignupRepository:
    """
    SQLAlchemy implementation used by SignupService.

    Creates the user and email-verification record inside
    one database transaction.
    """

    def __init__(
        self,
        db: Session,
    ) -> None:
        self.db = db

    def email_exists(
        self,
        email: str,
    ) -> bool:
        normalized_email = email.strip().lower()

        statement = (
            select(User.id)
            .where(
                func.lower(User.email)
                == normalized_email
            )
            .limit(1)
        )

        return (
            self.db.execute(
                statement,
            ).scalar_one_or_none()
            is not None
        )

    def create_user(
        self,
        *,
        full_name: str,
        email: str,
        password_hash: str,
        verification_token_hash: str,
        verification_token_expires_at: datetime,
    ) -> User:
        user = User(
            full_name=full_name,
            email=email,
            password_hash=password_hash,
            status=(
                UserStatus.PENDING_VERIFICATION
            ),
            is_email_verified=False,
            is_superuser=False,
        )

        try:
            self.db.add(
                user,
            )

            self.db.flush()

            verification = EmailVerification(
                user_id=user.id,
                token_hash=verification_token_hash,
                expires_at=(
                    verification_token_expires_at
                ),
            )

            self.db.add(
                verification,
            )

            self.db.commit()

            self.db.refresh(
                user,
            )

            return user

        except IntegrityError as exc:
            self.db.rollback()

            if self.email_exists(
                email,
            ):
                raise DuplicateEmailError(
                    (
                        "An account already exists with "
                        "this email address."
                    )
                ) from exc

            raise

        except Exception:
            self.db.rollback()
            raise
