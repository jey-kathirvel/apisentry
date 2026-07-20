# API Sentry — Codex Project Handoff

## 1. Project identity

**Project:** API Sentry  
**Purpose:** Upload application source code, discover APIs, analyze security vulnerabilities, calculate security scores, generate findings/remediation guidance, and later provide fix recommendations/code patches.  
**Repository:** `https://github.com/jey-kathirvel/apisentry`  
**Production URL:** `https://apisentry.ads-ai.in`  
**VPS project path:** `/opt/apisentry`  
**Operating system:** Ubuntu 24.04  
**Application:** FastAPI + SQLAlchemy + PostgreSQL + Alembic + Jinja2  
**Process:** Uvicorn behind Apache and systemd  
**Current bound port:** `127.0.0.1:8060` (8050 was already occupied during deployment)

## 2. Working style required

- Work directly against the existing architecture.
- Do not create duplicate services when an implementation already exists.
- Prefer complete production-ready files or one idempotent bash patch.
- Run tests before and after every patch.
- Preserve backward compatibility unless a migration plan is included.
- Never expose or commit `.env`, credentials, SMTP passwords, JWT secrets, uploaded customer code, scan artifacts, or the virtual environment.
- Keep user data/project ownership isolation enforced on every project endpoint.
- Use concise responses and focus on executable code.

## 3. Deployment baseline

Expected commands:

```bash
cd /opt/apisentry
source venv/bin/activate
python -m compileall app
pytest -q
sudo systemctl restart apisentry
sudo systemctl status apisentry --no-pager
curl -fsS https://apisentry.ads-ai.in/api/v1/health
```

Confirm the actual systemd unit name before restarting if `apisentry.service` is not present.

## 4. Current application structure

Important paths:

```text
app/main.py
app/api/dependencies.py
app/api/v1/router.py
app/api/v1/auth/__init__.py
app/api/v1/projects/__init__.py
app/api/v1/health.py
app/api/v1/security_report.py

app/core/config.py
app/core/email_config.py
app/core/security.py
app/core/exceptions.py

app/db/base.py
app/db/session.py

app/models/user.py
app/models/email_verification.py
app/models/password_reset_token.py
app/models/project.py
app/models/project_upload.py
app/models/scan_job.py
app/models/discovered_api.py
app/models/api_parameter.py
app/models/api_response.py

app/repositories/signup_repository.py

app/services/auth_service.py
app/services/email_service.py
app/services/auth/
app/services/mail/
app/services/project_service.py
app/services/archive_service.py
app/services/technology_detector.py
app/services/source_code_walker.py
app/services/fastapi_ast_discovery.py
app/services/discovery/
app/services/security/

app/templates/emails/
app/templates/dashboard/projects.html
app/static/css/project-dashboard.css
app/static/js/project-dashboard.js

alembic/versions/
tests/
```

## 5. Completed work

### PATCH-001 to PATCH-003 — Foundation/deployment

Completed foundation includes:

- FastAPI application bootstrapping.
- PostgreSQL database connection.
- Alembic setup.
- Production deployment on `apisentry.ads-ai.in`.
- Apache reverse proxy and SSL.
- Application health endpoints working.
- Storage directories configured for uploaded projects and reports.

Known health/application paths:

```text
/
/api/v1/health
/api/v1/health/database
/api/docs
/api/redoc
```

### PATCH-004 — API discovery engine

Completed or substantially implemented:

- Secure archive/project source handling.
- Source code walking.
- Technology/language/framework detection.
- FastAPI AST discovery.
- Router parsing.
- Parameter parsing.
- Response parsing.
- Dependency parsing.
- HTTP status-code resolution.
- Discovered API persistence models.

There are many historical `.bak` files from PATCH-004 iterations. These should not be treated as active source and should eventually be removed after verification.

### PATCH-005 to PATCH-009 — Security analysis/reporting/remediation

Implemented modules include:

- General security analyzer orchestration.
- Authentication analysis.
- Authorization/ownership analysis.
- File-upload security analysis.
- Validation analysis.
- Scoring.
- Finding post-processing.
- Executive summary generation.
- Report generation/serialization/export.
- HTML report generation.
- Security knowledge registry and OWASP mapping.
- Framework-aware remediation engine.
- FastAPI remediation adapter/rules.
- Source-analysis registry/service.
- Python AST/configuration analyzers.
- FastAPI endpoint, authentication, and authorization analyzers.

The archive Git commit at handoff was:

```text
6576846 feat: complete framework remediation engine and FastAPI adapter
```

### PATCH-010 — Authentication foundation

Existing legacy/full HTTP authentication implementation is present in:

```text
app/api/v1/auth/__init__.py
app/services/auth_service.py
app/services/email_service.py
app/schemas/auth.py
app/core/security.py
```

Current auth endpoints already defined:

```text
POST /api/v1/auth/signup
POST /api/v1/auth/verify-email
POST /api/v1/auth/resend-verification
POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/forgot-password
POST /api/v1/auth/reset-password
GET  /api/v1/auth/me
POST /api/v1/auth/logout
```

Existing authentication capabilities include:

- Signup.
- Password hashing.
- Email verification token storage.
- Email verification activation.
- Resend verification.
- Login gating for inactive/unverified users.
- JWT access/refresh token handling.
- Forgot/reset password flow.
- Current-user dependency.
- User status model.

### PATCH-011 PART-1A to PART-1C — New email engine foundation

A newer modular mail/auth-email layer was added and tests passed.

Mail modules:

```text
app/services/mail/base.py
app/services/mail/message.py
app/services/mail/result.py
app/services/mail/exceptions.py
app/services/mail/smtp_provider.py
app/services/mail/provider_factory.py
app/services/mail/delivery_service.py
app/services/mail/template_renderer.py
app/services/mail/template_service.py
app/services/mail/utils.py
```

Auth email workflow modules:

```text
app/services/auth/email_workflow.py
app/services/auth/email_workflow_factory.py
```

Email templates:

```text
app/templates/emails/base.html
app/templates/emails/verify_email.html
app/templates/emails/verify_email.txt
app/templates/emails/verify_email.subject.txt
app/templates/emails/reset_password.html
app/templates/emails/reset_password.txt
app/templates/emails/reset_password.subject.txt
app/templates/emails/welcome.html
app/templates/emails/welcome.txt
app/templates/emails/welcome.subject.txt
app/templates/emails/project_uploaded.html
app/templates/emails/project_uploaded.txt
app/templates/emails/project_uploaded.subject.txt
app/templates/emails/scan_completed.html
app/templates/emails/scan_completed.txt
app/templates/emails/scan_completed.subject.txt
```

New signup foundation:

```text
app/services/auth/signup_service.py
app/services/auth/password.py
app/services/auth/token.py
app/services/auth/validators.py
app/services/auth/constants.py
app/services/auth/exceptions.py
app/repositories/signup_repository.py
app/schemas/signup.py
```

Verified behavior in tests:

- Name/email normalization.
- Strong password validation.
- bcrypt password hashing.
- Secure raw verification token generation.
- SHA-256 token hash storage.
- UTC expiry generation.
- Duplicate-email rejection.
- Terms acceptance validation.
- Password-confirmation validation.
- Transaction rollback behavior in the signup repository.
- Mail configuration/provider/delivery/template workflow tests.

The user reported the latest full suite result as:

```text
62 passed
```

Treat that as the regression baseline, but rerun the suite in the current checkout before editing.

## 6. Important architectural issue discovered

There are currently **two overlapping authentication/email implementations**:

### Existing integrated implementation

```text
app/services/auth_service.py
app/services/email_service.py
app/api/v1/auth/__init__.py
```

This implementation is already wired to HTTP endpoints and database flows.

### New modular implementation

```text
app/services/auth/signup_service.py
app/repositories/signup_repository.py
app/services/auth/email_workflow.py
app/services/auth/email_workflow_factory.py
app/services/mail/*
```

This implementation has cleaner separation and good unit tests, but is not yet fully integrated into the HTTP signup/verification/resend flows.

**Do not add a third implementation.** The next task must consolidate/integrate these layers carefully.

## 7. Immediate pending task — PATCH-011 PART-2A

### Objective

Integrate the new modular signup and email workflow into the existing HTTP authentication lifecycle while preserving existing endpoints and behavior.

### Required outcomes

1. Wire `SignupService` + `SignupRepository` into `POST /api/v1/auth/signup`.
2. Send the verification email through `AuthEmailWorkflow`, not the legacy hand-built SMTP HTML function.
3. Keep user creation and verification-record creation transaction-safe.
4. Decide and document email-delivery failure semantics:
   - Preferred: rollback user creation when synchronous signup email delivery fails, or
   - Commit pending user and return a retry-safe response, with resend support.
   - Whichever policy is selected must be tested and consistent.
5. Wire verification endpoint to the token hash/expiry/used-at model.
6. Ensure verification token is one-time use.
7. Reject invalid, expired, or already-used tokens safely.
8. Activate user and set `is_email_verified=True` atomically.
9. Send welcome email after successful verification. Welcome email failure should not undo a completed verification unless explicitly designed otherwise.
10. Wire resend verification through the modular email workflow.
11. Invalidate/supersede old unused verification tokens when resending.
12. Preserve generic resend responses to prevent account enumeration.
13. Keep login blocked until verification succeeds.
14. Add service, repository, and endpoint tests.
15. Preserve all current passing tests.

### Recommended implementation approach

- First inspect the full contents of:

```text
app/api/v1/auth/__init__.py
app/services/auth_service.py
app/services/email_service.py
app/services/auth/signup_service.py
app/services/auth/email_workflow.py
app/services/auth/email_workflow_factory.py
app/services/mail/*
app/repositories/signup_repository.py
app/models/user.py
app/models/email_verification.py
app/schemas/auth.py
app/schemas/signup.py
```

- Choose one canonical service layer.
- Prefer migrating endpoint internals to the modular services while keeping public endpoint schemas stable.
- Remove legacy email formatting only after all callers are migrated and tests pass.
- Avoid changing database schema unless genuinely required.
- Use timezone-aware UTC datetimes throughout.
- Never store raw verification/reset tokens.
- Hash tokens before database persistence.
- Use one transaction boundary per state-changing workflow.

## 8. Project API/upload state

Project routes already enforce current-user ownership through `get_current_user` and `user_id` filtering.

Current project endpoints:

```text
POST   /api/v1/projects/upload
GET    /api/v1/projects
GET    /api/v1/projects/{project_id}
DELETE /api/v1/projects/{project_id}
POST   /api/v1/projects/{project_id}/scan
GET    /api/v1/projects/{project_id}/status
```

Implemented project capabilities:

- Upload archive.
- Validate archive.
- Detect duplicate upload.
- Create project/upload records.
- List user-owned projects.
- Read user-owned project details.
- Delete user-owned project.
- Create scan job.
- Read latest scan/project status.

Pending here:

- Confirm whether scan jobs actually execute asynchronously or are only created.
- Connect discovery and security-analysis pipeline to scan execution.
- Persist findings/reports against project and scan job.
- Progress updates and failure handling.
- Scan-completed email notification.
- Project-uploaded email notification.

## 9. Larger pending roadmap

### PATCH-012 — Account security hardening

Although basic reset endpoints already exist, hardening remains:

- Full tests for forgot/reset flows.
- Rate limiting.
- Brute-force protection.
- Account lockout policy.
- Login audit trail.
- Security-event logging.
- Password history/reuse prevention.
- Refresh-token rotation/revocation.
- Logout token invalidation strategy.
- Optional MFA foundation.

### PATCH-013 — Organization/RBAC

- Organizations/workspaces.
- Memberships.
- Roles and permissions.
- Admin/member separation.
- Tenant isolation.

### PATCH-014 — API keys/tokens

- Personal access tokens.
- API keys.
- Scoped permissions.
- Rotation/revocation.
- Last-used metadata.

### PATCH-015 — End-to-end scan engine

- Background worker/task queue.
- Extract project safely.
- Detect framework/language.
- Discover endpoints.
- Run analyzers.
- Normalize/deduplicate findings.
- Calculate score.
- Produce remediation.
- Persist report.
- Update scan progress/status.
- Handle timeout/cancellation/failure.

### PATCH-016 — Dashboard/reporting

- Project dashboard completion.
- Scan history.
- Findings grouped by severity/category/file/API.
- Security-score trend.
- Report download/export.
- Remediation display.
- Code-fix preview.

## 10. Git repository status at handoff

The uploaded archive contains a `.git` directory with one visible commit, but most current source files appear untracked relative to that commit.

Before development, run:

```bash
cd /opt/apisentry
git status --short
git log --oneline --decorate -10
git remote -v
```

The archive showed no configured remote and many untracked project files. Do not push until secrets and generated files are excluded.

Recommended cleanup before first complete push:

```text
.env
venv/
__pycache__/
*.pyc
.pytest_cache/
storage/projects/
storage/reports/
*.bak
```

Review `.gitignore`, then stage only intended source:

```bash
git add .gitignore .env.example README.md alembic alembic.ini app requirements.txt tests
git status --short
git diff --cached --stat
```

Never stage `.env`.

Set HTTPS remote:

```bash
git remote remove origin 2>/dev/null || true
git remote add origin https://github.com/jey-kathirvel/apisentry.git
git branch -M main
```

Commit and push using a GitHub Personal Access Token with repository `Contents: Read and write` permission.

## 11. Configuration contract

`app/core/config.py` currently expects settings including:

```text
APP_NAME
APP_ENV
APP_DEBUG
APP_VERSION
APP_HOST
APP_PORT
APP_URL
FRONTEND_URL
SECRET_KEY
JWT_SECRET_KEY
JWT_ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS
DATABASE_URL
SMTP_HOST
SMTP_PORT
SMTP_USERNAME
SMTP_PASSWORD
SMTP_FROM_EMAIL
SMTP_FROM_NAME
SMTP_USE_SSL
EMAIL_VERIFICATION_EXPIRE_MINUTES
PASSWORD_RESET_EXPIRE_MINUTES
MAX_PROJECT_UPLOAD_MB
PROJECT_STORAGE_PATH
REPORT_STORAGE_PATH
```

Use `.env.example` with empty/non-secret sample values. Do not weaken minimum secret lengths in production.

## 12. Database migrations present

Current visible revisions:

```text
3fd05ee5aa5b_create_project_tables.py
aa789c9d234d_create_api_discovery_tables.py
ff0e93225e6a_create_authentication_tables.py
```

There were compiled references to older auth migration IDs, so verify the actual Alembic graph:

```bash
alembic heads
alembic history --verbose
alembic current
alembic upgrade head
```

Do not create a new migration until the graph is confirmed healthy.

## 13. Mandatory pre-change inspection for Codex

Run these first:

```bash
cd /opt/apisentry
source venv/bin/activate

git status --short
git log --oneline --decorate -10
git remote -v

python -m compileall app
pytest -q

alembic heads
alembic current

sed -n '1,320p' app/api/v1/auth/__init__.py
sed -n '1,520p' app/services/auth_service.py
sed -n '1,320p' app/services/auth/signup_service.py
sed -n '1,360p' app/services/auth/email_workflow.py
sed -n '1,320p' app/services/auth/email_workflow_factory.py
sed -n '1,360p' app/repositories/signup_repository.py
sed -n '1,320p' app/models/user.py
sed -n '1,320p' app/models/email_verification.py
sed -n '1,320p' app/schemas/auth.py
sed -n '1,320p' app/schemas/signup.py
```

Then report:

- Test count and failures.
- Alembic head/current revision.
- Exact duplication between legacy and modular auth/email flows.
- Proposed minimal integration plan.
- Files to modify.
- Whether a migration is required.

## 14. Acceptance criteria for PATCH-011 PART-2A

The patch is complete only when:

```text
[ ] Signup creates one pending user and one active verification record.
[ ] Password is hashed.
[ ] Raw token is returned only internally for email construction, never persisted.
[ ] Verification email uses the modular template/delivery engine.
[ ] Invalid token returns safe 400 response.
[ ] Expired token returns safe 400 response.
[ ] Used token cannot be reused.
[ ] Successful verification activates user atomically.
[ ] Login is blocked before verification and allowed afterward.
[ ] Resend does not reveal whether an account exists.
[ ] Resend does not create duplicate users.
[ ] Old tokens are invalidated/superseded.
[ ] Welcome email is attempted after activation.
[ ] Delivery failures follow a documented, tested policy.
[ ] Existing endpoints remain compatible.
[ ] `python -m compileall app` passes.
[ ] `pytest -q` passes with no regressions.
[ ] Service restarts successfully.
[ ] Production health endpoint returns success.
```

## 15. Initial Codex prompt

Use this prompt after opening the repository in Codex:

```text
Read CODEX_HANDOFF_API_SENTRY.md completely. Inspect the current repository before editing. First run git status, compileall, pytest, and Alembic head/current checks. Then analyze the duplicated legacy and modular authentication/email implementations. Implement only PATCH-011 PART-2A: integrate SignupService, SignupRepository, AuthEmailWorkflow, and the modular mail engine into the existing signup, verify-email, and resend-verification HTTP endpoints without changing the public API unnecessarily. Preserve all existing behavior and tests, add comprehensive integration tests, do not expose secrets, and do not create a third auth implementation. Show the exact files changed and test results before proposing a commit.
```

## 16. Source of truth

This handoff was prepared from the uploaded API Sentry project archive and the latest development conversation. The repository itself is the final source of truth. When this document conflicts with current code or test output, inspect and follow the current code, then update this handoff.
