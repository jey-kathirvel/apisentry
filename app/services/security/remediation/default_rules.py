from __future__ import annotations

from app.services.security.remediation.models import (
    RemediationEffort,
    RemediationGuidance,
    RemediationPriority,
)
from app.services.security.remediation.registry import (
    RemediationRegistry,
)


DEFAULT_REMEDIATION_RULES: tuple[
    RemediationGuidance,
    ...,
] = (
    RemediationGuidance(
        rule_id="AUTH-001",
        title="Require endpoint authentication",
        summary=(
            "The endpoint can be accessed without "
            "verifying the caller's identity."
        ),
        business_impact=(
            "Unauthenticated users may access "
            "sensitive data or invoke protected "
            "business operations."
        ),
        technical_impact=(
            "The route lacks a mandatory "
            "authentication control before request "
            "processing begins."
        ),
        recommended_fix=(
            "Require a validated authentication "
            "mechanism such as OAuth2, JWT bearer "
            "tokens, secure sessions, or an API key "
            "appropriate for the application."
        ),
        priority=(
            RemediationPriority.IMMEDIATE
        ),
        effort=RemediationEffort.SMALL,
        implementation_steps=[
            (
                "Identify the authentication "
                "mechanism used by the application."
            ),
            (
                "Apply authentication middleware, "
                "a dependency, filter, or route "
                "guard to the endpoint."
            ),
            (
                "Reject missing, invalid, expired, "
                "or revoked credentials."
            ),
            (
                "Add automated tests for anonymous "
                "and authenticated requests."
            ),
        ],
        validation_steps=[
            (
                "Call the endpoint without "
                "credentials and verify HTTP 401."
            ),
            (
                "Call the endpoint with invalid or "
                "expired credentials and verify "
                "access is denied."
            ),
            (
                "Call the endpoint with valid "
                "credentials and verify authorized "
                "access succeeds."
            ),
        ],
        references=[
            "OWASP API2:2023",
            "CWE-306",
        ],
        tags=[
            "authentication",
            "identity",
            "access-control",
        ],
        estimated_minutes_min=30,
        estimated_minutes_max=90,
        risk_reduction_percent=85.0,
        metadata={
            "recommended_http_status": 401,
            "control_type": "preventive",
        },
    ),
    RemediationGuidance(
        rule_id="AUTH-002",
        title="Enforce endpoint authorization",
        summary=(
            "The endpoint authenticates users but "
            "does not clearly enforce permission "
            "or ownership checks."
        ),
        business_impact=(
            "Authenticated users may access data "
            "or operations outside their permitted "
            "roles, tenants, or ownership scope."
        ),
        technical_impact=(
            "The endpoint does not verify that the "
            "current identity is authorized for the "
            "requested resource or action."
        ),
        recommended_fix=(
            "Add role, permission, tenant, and "
            "resource ownership checks before "
            "reading or modifying protected data."
        ),
        priority=RemediationPriority.HIGH,
        effort=RemediationEffort.MEDIUM,
        implementation_steps=[
            (
                "Define the roles, permissions, "
                "ownership rules, and tenant "
                "boundaries for the endpoint."
            ),
            (
                "Enforce authorization in a shared "
                "policy, guard, dependency, or "
                "service layer."
            ),
            (
                "Verify resource identifiers belong "
                "to the authenticated user or tenant."
            ),
            (
                "Apply deny-by-default behavior."
            ),
            (
                "Add horizontal and vertical "
                "privilege escalation tests."
            ),
        ],
        validation_steps=[
            (
                "Verify a permitted user can access "
                "the endpoint."
            ),
            (
                "Verify a user with the wrong role "
                "receives HTTP 403."
            ),
            (
                "Verify users cannot access another "
                "user's or tenant's resources."
            ),
        ],
        references=[
            "OWASP API5:2023",
            "CWE-285",
        ],
        tags=[
            "authorization",
            "rbac",
            "ownership",
            "multi-tenant",
        ],
        estimated_minutes_min=60,
        estimated_minutes_max=240,
        risk_reduction_percent=90.0,
        metadata={
            "recommended_http_status": 403,
            "control_type": "preventive",
        },
    ),
    RemediationGuidance(
        rule_id="VAL-001",
        title="Validate and constrain request input",
        summary=(
            "The endpoint accepts request data "
            "without a clear structured validation "
            "boundary."
        ),
        business_impact=(
            "Malformed or malicious input may cause "
            "data corruption, unexpected behavior, "
            "service instability, or injection "
            "vulnerabilities."
        ),
        technical_impact=(
            "Request fields may not be constrained "
            "by type, length, format, allowed values, "
            "or business rules."
        ),
        recommended_fix=(
            "Use framework-native request schemas "
            "and allowlist validation for every "
            "untrusted input field."
        ),
        priority=RemediationPriority.HIGH,
        effort=RemediationEffort.SMALL,
        implementation_steps=[
            (
                "Define a typed request schema for "
                "body, path, query, header, and form "
                "inputs."
            ),
            (
                "Apply minimum and maximum lengths, "
                "numeric ranges, formats, enums, and "
                "required-field constraints."
            ),
            (
                "Reject unknown fields when the "
                "business contract requires it."
            ),
            (
                "Keep validation separate from "
                "output encoding and database "
                "parameterization."
            ),
            (
                "Add negative tests for malformed "
                "and boundary input."
            ),
        ],
        validation_steps=[
            (
                "Submit missing required fields and "
                "verify validation fails."
            ),
            (
                "Submit invalid types, formats, and "
                "out-of-range values."
            ),
            (
                "Submit oversized payload values "
                "and verify they are rejected."
            ),
            (
                "Verify valid payloads continue to "
                "succeed."
            ),
        ],
        references=[
            "OWASP API8:2023",
            "CWE-20",
        ],
        tags=[
            "validation",
            "input",
            "schema",
            "allowlist",
        ],
        estimated_minutes_min=30,
        estimated_minutes_max=120,
        risk_reduction_percent=70.0,
        metadata={
            "recommended_http_status": 422,
            "control_type": "preventive",
        },
    ),
    RemediationGuidance(
        rule_id="FILE-001",
        title="Secure the file upload workflow",
        summary=(
            "The endpoint accepts uploaded files "
            "without sufficient evidence of type, "
            "size, name, storage, or content "
            "validation."
        ),
        business_impact=(
            "Attackers may upload malicious files, "
            "overwrite application data, consume "
            "storage, distribute malware, or achieve "
            "remote code execution."
        ),
        technical_impact=(
            "Uploaded content may be trusted based "
            "only on the client-provided filename or "
            "content type."
        ),
        recommended_fix=(
            "Apply strict allowlists, size limits, "
            "generated filenames, isolated storage, "
            "content inspection, and safe download "
            "handling."
        ),
        priority=(
            RemediationPriority.IMMEDIATE
        ),
        effort=RemediationEffort.MEDIUM,
        implementation_steps=[
            (
                "Allow only explicitly required file "
                "extensions and verified content "
                "types."
            ),
            (
                "Inspect file signatures instead of "
                "trusting only the supplied MIME type."
            ),
            (
                "Enforce request and per-file size "
                "limits."
            ),
            (
                "Generate server-side filenames and "
                "remove path components from user "
                "input."
            ),
            (
                "Store uploads outside executable "
                "web roots with least-privilege "
                "permissions."
            ),
            (
                "Scan files for malware where the "
                "risk profile requires it."
            ),
            (
                "Serve downloads with safe content "
                "disposition and content type headers."
            ),
        ],
        validation_steps=[
            (
                "Attempt to upload a disallowed file "
                "extension."
            ),
            (
                "Attempt MIME-type and file-signature "
                "mismatch uploads."
            ),
            (
                "Attempt oversized and empty file "
                "uploads."
            ),
            (
                "Attempt filenames containing path "
                "traversal sequences."
            ),
            (
                "Verify uploaded files cannot execute "
                "as application code."
            ),
        ],
        references=[
            "OWASP API8:2023",
            "CWE-434",
        ],
        tags=[
            "file-upload",
            "malware",
            "path-traversal",
            "storage",
        ],
        estimated_minutes_min=90,
        estimated_minutes_max=360,
        risk_reduction_percent=90.0,
        metadata={
            "control_type": "preventive",
            "requires_content_inspection": True,
        },
    ),
)


registry = RemediationRegistry(
    DEFAULT_REMEDIATION_RULES
)
