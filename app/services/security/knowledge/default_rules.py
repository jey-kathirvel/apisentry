from __future__ import annotations

from app.services.security.knowledge.models import (
    SecurityKnowledgeRecord,
)
from app.services.security.knowledge.registry import (
    SecurityKnowledgeRegistry,
)

DEFAULT_RULES = (
    SecurityKnowledgeRecord(
        rule_id="AUTH-001",
        title="Missing Authentication",
        category="Authentication",
        description=(
            "Endpoint does not require authentication."
        ),
        remediation=(
            "Require authenticated users before allowing access."
        ),
        owasp_api_categories=(
            "API2:2023",
        ),
        cwe_ids=(
            "CWE-306",
        ),
        references=(
            "https://owasp.org/API-Security/",
        ),
    ),
    SecurityKnowledgeRecord(
        rule_id="AUTH-002",
        title="Missing Authorization",
        category="Authorization",
        description=(
            "Endpoint lacks authorization checks."
        ),
        remediation=(
            "Enforce role or permission validation."
        ),
        owasp_api_categories=(
            "API5:2023",
        ),
        cwe_ids=(
            "CWE-285",
        ),
        references=(
            "https://owasp.org/API-Security/",
        ),
    ),
    SecurityKnowledgeRecord(
        rule_id="VAL-001",
        title="Input Validation",
        category="Validation",
        description=(
            "Input validation is missing or insufficient."
        ),
        remediation=(
            "Validate and sanitize all incoming data."
        ),
        owasp_api_categories=(
            "API8:2023",
        ),
        cwe_ids=(
            "CWE-20",
        ),
        references=(
            "https://owasp.org/API-Security/",
        ),
    ),
    SecurityKnowledgeRecord(
        rule_id="FILE-001",
        title="Unsafe File Upload",
        category="File Upload",
        description=(
            "Uploaded files are not sufficiently validated."
        ),
        remediation=(
            "Restrict file types, verify content and scan uploads."
        ),
        owasp_api_categories=(
            "API8:2023",
        ),
        cwe_ids=(
            "CWE-434",
        ),
        references=(
            "https://owasp.org/API-Security/",
        ),
    ),
)

registry = SecurityKnowledgeRegistry(
    DEFAULT_RULES
)
