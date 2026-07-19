from __future__ import annotations

from copy import deepcopy

import pytest

from app.services.security.models import (
    FindingCategory,
    SecurityConfidence,
    SecurityFinding,
    SecuritySeverity,
)
from app.services.security.remediation import (
    FrameworkContext,
    FrameworkRemediationService,
    RemediationEffort,
    RemediationGuidance,
    RemediationPriority,
)


SUPPORTED_RULES = (
    (
        "AUTH-001",
        "Protect the endpoint using Depends(get_current_user).",
        "JWT Authentication",
    ),
    (
        "AUTH-002",
        "Verify user roles before processing.",
        "Role Validation",
    ),
    (
        "VAL-001",
        "Use Pydantic request models.",
        "Pydantic Validation",
    ),
    (
        "FILE-001",
        "Validate MIME type.",
        "Secure Upload",
    ),
)


def build_finding(
    rule_id: str,
) -> SecurityFinding:
    return SecurityFinding(
        rule_id=rule_id,
        title=f"Finding for {rule_id}",
        description="Security weakness detected.",
        category=FindingCategory.AUTHENTICATION,
        severity=SecuritySeverity.HIGH,
        confidence=SecurityConfidence.HIGH,
        remediation="Apply secure remediation.",
        endpoint_method="POST",
        endpoint_path="/api/v1/example",
    )


def build_guidance(
    rule_id: str,
) -> RemediationGuidance:
    return RemediationGuidance(
        rule_id=rule_id,
        title=f"Remediation for {rule_id}",
        summary="Apply generic security controls.",
        business_impact="The weakness may expose protected resources.",
        technical_impact="The endpoint lacks a required security control.",
        recommended_fix="Apply the appropriate security control.",
        priority=RemediationPriority.IMMEDIATE,
        effort=RemediationEffort.SMALL,
        implementation_steps=[
            "Apply the generic security remediation.",
        ],
        validation_steps=[
            "Confirm the generic remediation is effective.",
        ],
        metadata={
            "source": {
                "type": "generic",
                "version": 1,
            },
        },
    )


def build_context(
    *,
    framework: str = "FastAPI",
    language: str = "Python",
) -> FrameworkContext:
    return FrameworkContext(
        framework=framework,
        language=language,
        project_name="API Sentry",
        project_id=1,
        endpoint_method="POST",
        endpoint_path="/api/v1/example",
        source_file="app/api/routes/example.py",
        function_name="example_endpoint",
        metadata={
            "test": True,
        },
    )


@pytest.mark.parametrize(
    (
        "rule_id",
        "expected_step",
        "expected_example_title",
    ),
    SUPPORTED_RULES,
)
def test_supported_fastapi_rule_end_to_end(
    rule_id: str,
    expected_step: str,
    expected_example_title: str,
) -> None:
    finding = build_finding(
        rule_id,
    )
    guidance = build_guidance(
        rule_id,
    )
    context = build_context()

    original_finding = deepcopy(
        finding,
    )
    original_guidance = deepcopy(
        guidance,
    )

    service = FrameworkRemediationService()

    result = service.enrich(
        finding=finding,
        guidance=guidance,
        context=context,
    )

    assert result is not guidance

    assert (
        guidance.to_dict()
        == original_guidance.to_dict()
    )

    assert (
        finding.to_dict()
        == original_finding.to_dict()
    )

    assert (
        "Apply the generic security remediation."
        in result.implementation_steps
    )

    assert (
        expected_step
        in result.implementation_steps
    )

    assert (
        "Confirm the generic remediation is effective."
        in result.validation_steps
    )

    assert len(
        result.code_examples,
    ) == 1

    assert (
        result.code_examples[0].title
        == expected_example_title
    )

    assert (
        result.metadata["source"]["type"]
        == "generic"
    )

    assert (
        result.metadata["framework_remediation"]["applied"]
        is True
    )

    assert (
        result.metadata["framework_remediation"]["adapter"]
        == "fastapi"
    )

    assert (
        result.metadata["framework_remediation"]["framework"]
        == "FastAPI"
    )

    assert (
        result.metadata["framework_remediation"]["language"]
        == "Python"
    )

    assert (
        result.metadata["framework_remediation"]["endpoint"]
        == "POST /api/v1/example"
    )

    assert (
        result.metadata["adapter"]
        == "fastapi"
    )

    assert (
        result.metadata["rule"]
        == rule_id
    )


def test_fastapi_alias_resolution() -> None:
    service = FrameworkRemediationService()

    finding = build_finding(
        "AUTH-001",
    )
    guidance = build_guidance(
        "AUTH-001",
    )

    result = service.enrich(
        finding=finding,
        guidance=guidance,
        context=build_context(
            framework="fast-api",
            language="python",
        ),
    )

    assert (
        result.metadata["framework_remediation"]["adapter"]
        == "fastapi"
    )

    assert len(
        result.code_examples,
    ) == 1


def test_python_language_fallback_resolution() -> None:
    service = FrameworkRemediationService()

    finding = build_finding(
        "VAL-001",
    )
    guidance = build_guidance(
        "VAL-001",
    )

    result = service.enrich(
        finding=finding,
        guidance=guidance,
        context=build_context(
            framework="",
            language="Python",
        ),
    )

    assert (
        result.metadata["framework_remediation"]["adapter"]
        == "fastapi"
    )

    assert (
        "Use Pydantic request models."
        in result.implementation_steps
    )


def test_unknown_rule_preserves_generic_guidance() -> None:
    service = FrameworkRemediationService()

    finding = build_finding(
        "UNKNOWN-001",
    )
    guidance = build_guidance(
        "UNKNOWN-001",
    )

    result = service.enrich(
        finding=finding,
        guidance=guidance,
        context=build_context(),
    )

    assert result is not guidance

    assert (
        result.implementation_steps
        == guidance.implementation_steps
    )

    assert (
        result.validation_steps
        == guidance.validation_steps
    )

    assert result.code_examples == []

    assert (
        result.metadata["framework_remediation"]["applied"]
        is True
    )

    assert (
        result.metadata["framework_remediation"]["adapter"]
        == "fastapi"
    )


def test_unsupported_framework_returns_independent_copy() -> None:
    service = FrameworkRemediationService()

    finding = build_finding(
        "AUTH-001",
    )
    guidance = build_guidance(
        "AUTH-001",
    )

    result = service.enrich(
        finding=finding,
        guidance=guidance,
        context=build_context(
            framework="Spring Boot",
            language="Java",
        ),
    )

    assert result is not guidance

    assert (
        result.to_dict()
        == guidance.to_dict()
    )

    result.implementation_steps.append(
        "Changed result only.",
    )

    assert (
        "Changed result only."
        not in guidance.implementation_steps
    )


def test_repeated_enrichment_deduplicates_steps_and_examples() -> None:
    service = FrameworkRemediationService()

    finding = build_finding(
        "AUTH-001",
    )
    guidance = build_guidance(
        "AUTH-001",
    )
    context = build_context()

    first_result = service.enrich(
        finding=finding,
        guidance=guidance,
        context=context,
    )

    second_result = service.enrich(
        finding=finding,
        guidance=first_result,
        context=context,
    )

    assert (
        second_result.implementation_steps.count(
            "Protect the endpoint using Depends(get_current_user).",
        )
        == 1
    )

    assert (
        second_result.validation_steps.count(
            "Verify anonymous requests return HTTP 401.",
        )
        == 1
    )

    assert len(
        second_result.code_examples,
    ) == 1


def test_framework_metadata_is_deeply_independent() -> None:
    service = FrameworkRemediationService()

    finding = build_finding(
        "FILE-001",
    )
    guidance = build_guidance(
        "FILE-001",
    )

    result = service.enrich(
        finding=finding,
        guidance=guidance,
        context=build_context(),
    )

    result.metadata["source"]["type"] = "modified"

    assert (
        guidance.metadata["source"]["type"]
        == "generic"
    )
