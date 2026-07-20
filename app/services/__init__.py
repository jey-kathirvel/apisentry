from app.services.auth_service import (
    AuthenticationError,
    EmailAlreadyRegisteredError,
    EmailAlreadyVerifiedError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
    InvalidRefreshTokenError,
    InvalidVerificationTokenError,
    authenticate_user,
    build_token_pair,
    create_user,
    get_user_by_email,
    refresh_access_token,
    request_password_reset,
    resend_verification,
    reset_password,
    verify_email,
)

__all__ = [
    "AuthenticationError",
    "EmailAlreadyRegisteredError",
    "EmailAlreadyVerifiedError",
    "InvalidCredentialsError",
    "InactiveUserError",
    "InvalidVerificationTokenError",
    "InvalidPasswordResetTokenError",
    "InvalidRefreshTokenError",
    "get_user_by_email",
    "create_user",
    "authenticate_user",
    "build_token_pair",
    "verify_email",
    "resend_verification",
    "request_password_reset",
    "reset_password",
    "refresh_access_token",
]

from app.services.technology_detector import (
    TechnologyDetectionResult,
    detect_project_technology,
)

from app.services.project_service import (
    DuplicateProjectUploadError,
    ProjectNotFoundError,
    ProjectServiceError,
    create_project_from_upload,
    create_scan_job,
    delete_project,
    get_owned_project,
    get_project_details,
    get_project_status,
    list_projects,
)
