from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.config import settings
from app.db.session import get_db
from app.models import User
from app.schemas import (
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RefreshTokenRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    SignupRequest,
    TokenResponse,
    UserResponse,
    VerifyEmailRequest,
)
from app.services import (
    EmailAlreadyRegisteredError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
    InvalidRefreshTokenError,
    InvalidVerificationTokenError,
    authenticate_user,
    build_token_pair,
    create_user,
    refresh_access_token,
    request_password_reset,
    resend_verification,
    reset_password,
    verify_email,
)
from app.services.mail.exceptions import EmailDeliveryError


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/signup",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def signup(
    payload: SignupRequest,
    db: Session = Depends(get_db),
) -> User:
    try:
        return create_user(
            db=db,
            payload=payload,
        )
    except EmailAlreadyRegisteredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except EmailDeliveryError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Account creation could not be completed. "
                "Please try again."
            ),
        ) from exc


@router.post(
    "/verify-email",
    response_model=MessageResponse,
)
def verify_user_email(
    payload: VerifyEmailRequest,
    db: Session = Depends(get_db),
) -> MessageResponse:
    try:
        verify_email(
            db=db,
            plain_token=payload.token,
        )
    except InvalidVerificationTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return MessageResponse(
        message="Email verified successfully.",
    )


@router.post(
    "/resend-verification",
    response_model=MessageResponse,
)
def resend_user_verification(
    payload: ResendVerificationRequest,
    db: Session = Depends(get_db),
) -> MessageResponse:
    resend_verification(
        db=db,
        email=str(payload.email),
    )

    return MessageResponse(
        message=(
            "If the account exists, a verification "
            "email has been sent."
        ),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
)
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    try:
        user = authenticate_user(
            db=db,
            payload=payload,
        )
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from exc
    except InactiveUserError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    access_token, refresh_token = build_token_pair(
        user,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=(
            settings.access_token_expire_minutes * 60
        ),
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
)
def refresh(
    payload: RefreshTokenRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    try:
        access_token, refresh_token = (
            refresh_access_token(
                db=db,
                refresh_token=payload.refresh_token,
            )
        )
    except InvalidRefreshTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=(
            settings.access_token_expire_minutes * 60
        ),
    )


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
)
def forgot_password(
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db),
) -> MessageResponse:
    request_password_reset(
        db=db,
        email=str(payload.email),
    )

    return MessageResponse(
        message=(
            "If the account exists, password reset "
            "instructions have been sent."
        ),
    )


@router.post(
    "/reset-password",
    response_model=MessageResponse,
)
def reset_user_password(
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db),
) -> MessageResponse:
    try:
        reset_password(
            db=db,
            plain_token=payload.token,
            new_password=payload.new_password,
        )
    except InvalidPasswordResetTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return MessageResponse(
        message="Password reset successfully.",
    )


@router.get(
    "/me",
    response_model=UserResponse,
)
def get_my_profile(
    current_user: User = Depends(get_current_user),
) -> User:
    return current_user


@router.post(
    "/logout",
    response_model=MessageResponse,
)
def logout(
    current_user: User = Depends(get_current_user),
) -> MessageResponse:
    return MessageResponse(
        message="Logout successful.",
    )
