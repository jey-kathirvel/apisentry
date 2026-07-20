from __future__ import annotations

from fastapi import APIRouter

from app.services.security.executive_summary import (
    ExecutiveSummaryGenerator,
)
from app.services.security.models import (
    SecurityAnalysisResult,
)
from app.services.security.report_generator import (
    SecurityReportGenerator,
)

router = APIRouter(
    prefix="/api/v1/security",
    tags=["Security Reports"],
)


@router.get(
    "/report",
    summary="Security Report",
)
async def security_report():

    result = SecurityAnalysisResult()

    report = SecurityReportGenerator.generate(
        result
    )

    summary = ExecutiveSummaryGenerator.generate(
        result
    )

    return {
        "success": True,
        "report": report,
        "summary": summary,
    }
