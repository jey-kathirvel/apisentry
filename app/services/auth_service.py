from datetime import (
    datetime,
    timedelta,
    timezone,
)

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_random_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.models import (
    EmailVerification,
    PasswordResetToken,
    User,
    UserStatus,
)
from app.schemas import (
    LoginRequest,
    SignupRequest,
)
from app.services.email_service import (
    send_password_reset_email,
    send_verification_email,
)


class AuthenticationError(Exception):
    pass


class EmailAlreadyRegisteredError(AuthenticationError):
    pass


class InvalidCredentialsError(AuthenticationError):
    pass


class InactiveUserError(AuthenticationError):
    pass


class EmailAlreadyVerifiedError(AuthenticationError):
    pass


class InvalidVerificationTokenError(AuthenticationError):
    pass


class InvalidPasswordResetTokenError(AuthenticationError):
    pass


class InvalidRefreshTokenError(AuthenticationError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def normalize_status(
    status: UserStatus | str,
) -> str:
    if isinstance(status, UserStatus):
        return status.value

    return str(status)


def get_user_by_email(
    db: Session,
    email: str,
) -> User | None:
    normalized_email = normalize_email(email)

    return (
        db.query(User)
        .filter(
            func.lower(User.email) == normalized_email,
        )
        .first()
    )


def create_email_verification_token(
    db: Session,
    user: User,
) -> str:
    now = utc_now()

    db.query(EmailVerification).filter(
        EmailVerification.user_id == user.id,
        EmailVerification.used_at.is_(None),
    ).update(
        {
            EmailVerification.used_at: now,
        },
        synchronize_session=False,
    )

    plain_token = generate_random_token()

    verification = EmailVerification(
        user_id=user.id,
        token_hash=hash_token(plain_token),
        expires_at=(
            now
            + timedelta(
                minutes=(
                    settings.email_verification_expire_minutes
                ),
            )
        ),
    )

    db.add(verification)
    db.commit()

    return plain_token


def create_password_reset_token(
    db: Session,
    user: User,
) -> str:
    now = utc_now()

    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at.is_(None),
    ).update(
        {
            PasswordResetToken.used_at: now,
        },
        synchronize_session=False,
    )

    plain_token = generate_random_token()

    reset_record = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_token(plain_token),
        expires_at=(
            now
            + timedelta(
                minutes=(
                    settings.password_reset_expire_minutes
                ),
            )
        ),
    )

    db.add(reset_record)
    db.commit()

    return plain_token


def create_user(
    db: Session,
    payload: SignupRequest,
) -> User:
    email = normalize_email(str(payload.email))

    existing_user = get_user_by_email(
        db=db,
        email=email,
    )

    if existing_user is not None:
        raise EmailAlreadyRegisteredError(
            "An account already exists for this email address."
        )

    user = User(
        full_name=payload.full_name.strip(),
        email=email,
        password_hash=hash_password(payload.password),
        status=UserStatus.PENDING_VERIFICATION,
        is_email_verified=False,
        is_superuser=False,
    )

    db.add(user)

    try:
        db.commit()
        db.refresh(user)

        verification_token = (
            create_email_verification_token(
                db=db,
                user=user,
            )
        )

        send_verification_email(
            recipient=user.email,
            full_name=user.full_name,
            verification_token=verification_token,
        )

    except Exception:
        db.rollback()
        raise

    return user


def resend_verification(
    db: Session,
    email: str,
) -> None:
    user = get_user_by_email(
        db=db,
        email=email,
    )

    if user is None:
        return

    if user.is_email_verified:
        raise EmailAlreadyVerifiedError(
            "This email address is already verified."
        )

    verification_token = (
        create_email_verification_token(
            db=db,
            user=user,
        )
    )

    send_verification_email(
        recipient=user.email,
        full_name=user.full_name,
        verification_token=verification_token,
    )


def verify_email(
    db: Session,
    plain_token: str,
) -> User:
    now = utc_now()

    verification = (
        db.query(EmailVerification)
        .filter(
            EmailVerification.token_hash
            == hash_token(plain_token),
            EmailVerification.used_at.is_(None),
        )
        .first()
    )

    if verification is None:
        raise InvalidVerificationTokenError(
            "Invalid or already used verification token."
        )

    expires_at = verification.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(
            tzinfo=timezone.utc,
        )

    if expires_at <= now:
        raise InvalidVerificationTokenError(
            "Verification token has expired."
        )

    user = (
        db.query(User)
        .filter(
            User.id == verification.user_id,
        )
        .first()
    )

    if user is None:
        raise InvalidVerificationTokenError(
            "Verification account was not found."
        )

    verification.used_at = now
    user.is_email_verified = True
    user.status = UserStatus.ACTIVE

    db.add(verification)
    db.add(user)

    try:
        db.commit()
        db.refresh(user)
    except Exception:
        db.rollback()
        raise

    return user


def authenticate_user(
    db: Session,
    payload: LoginRequest,
) -> User:
    user = get_user_by_email(
        db=db,
        email=str(payload.email),
    )

    if user is None:
        raise InvalidCredentialsError(
            "Invalid email address or password."
        )

    if not verify_password(
        payload.password,
        user.password_hash,
    ):
        raise InvalidCredentialsError(
            "Invalid email address or password."
        )

    if (
        normalize_status(user.status)
        != UserStatus.ACTIVE.value
    ):
        raise InactiveUserError(
            "Your account is not active."
        )

    if not user.is_email_verified:
        raise InactiveUserError(
            "Verify your email address before logging in."
        )

    user.last_login_at = utc_now()

    db.add(user)

    try:
        db.commit()
        db.refresh(user)
    except Exception:
        db.rollback()
        raise

    return user


def build_token_pair(
    user: User,
) -> tuple[str, str]:
    access_token = create_access_token(
        subject=str(user.id),
        additional_claims={
            "email": user.email,
            "is_superuser": user.is_superuser,
        },
    )

    refresh_token = create_refresh_token(
        subject=str(user.id),
        token_id=generate_random_token(24),
    )

    return access_token, refresh_token


def refresh_access_token(
    db: Session,
    refresh_token: str,
) -> tuple[str, str]:
    try:
        payload = decode_token(refresh_token)
    except ValueError as exc:
        raise InvalidRefreshTokenError(
            "Invalid or expired refresh token."
        ) from exc

    if payload.get("type") != "refresh":
        raise InvalidRefreshTokenError(
            "Invalid token type."
        )

    subject = payload.get("sub")

    if not subject:
        raise InvalidRefreshTokenError(
            "Invalid refresh token."
        )

    try:
        user_id = int(subject)
    except (TypeError, ValueError) as exc:
        raise InvalidRefreshTokenError(
            "Invalid refresh token subject."
        ) from exc

    user = (
        db.query(User)
        .filter(
            User.id == user_id,
        )
        .first()
    )

    if user is None:
        raise InvalidRefreshTokenError(
            "User account was not found."
        )

    if (
        normalize_status(user.status)
        != UserStatus.ACTIVE.value
        or not user.is_email_verified
    ):
        raise InvalidRefreshTokenError(
            "User account is not active."
        )

    return build_token_pair(user)


def request_password_reset(
    db: Session,
    email: str,
) -> None:
    user = get_user_by_email(
        db=db,
        email=email,
    )

    if user is None:
        return

    reset_token = create_password_reset_token(
        db=db,
        user=user,
    )

    send_password_reset_email(
        recipient=user.email,
        full_name=user.full_name,
        reset_token=reset_token,
    )


def reset_password(
    db: Session,
    plain_token: str,
    new_password: str,
) -> None:
    now = utc_now()

    reset_record = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token_hash
            == hash_token(plain_token),
            PasswordResetToken.used_at.is_(None),
        )
        .first()
    )

    if reset_record is None:
        raise InvalidPasswordResetTokenError(
            "Invalid or already used password reset token."
        )

    expires_at = reset_record.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(
            tzinfo=timezone.utc,
        )

    if expires_at <= now:
        raise InvalidPasswordResetTokenError(
            "Password reset token has expired."
        )

    user = (
        db.query(User)
        .filter(
            User.id == reset_record.user_id,
        )
        .first()
    )

    if user is None:
        raise InvalidPasswordResetTokenError(
            "Password reset account was not found."
        )

    user.password_hash = hash_password(new_password)
    reset_record.used_at = now

    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.id != reset_record.id,
        PasswordResetToken.used_at.is_(None),
    ).update(
        {
            PasswordResetToken.used_at: now,
        },
        synchronize_session=False,
    )

    db.add(user)
    db.add(reset_record)

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
