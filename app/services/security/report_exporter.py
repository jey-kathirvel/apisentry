from __future__ import annotations

import json
from pathlib import Path

from app.services.security.html_report import (
    HtmlSecurityReport,
)
from app.services.security.models import (
    SecurityAnalysisResult,
)
from app.services.security.report_generator import (
    SecurityReportGenerator,
)


class SecurityReportExporter:

    @classmethod
    def export_json(
        cls,
        result: SecurityAnalysisResult,
        output_file: str | Path,
    ) -> Path:

        report = SecurityReportGenerator.generate(
            result
        )

        output = Path(output_file)

        output.write_text(
            json.dumps(
                report,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        return output

    @classmethod
    def export_html(
        cls,
        result: SecurityAnalysisResult,
        output_file: str | Path,
    ) -> Path:

        html = HtmlSecurityReport.generate(
            result
        )

        output = Path(output_file)

        output.write_text(
            html,
            encoding="utf-8",
        )

        return output
