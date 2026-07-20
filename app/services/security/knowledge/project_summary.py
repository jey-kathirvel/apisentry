from __future__ import annotations

from collections import Counter

from app.services.security.models import SecurityAnalysisResult


class ProjectKnowledgeSummary:

    @classmethod
    def enrich(
        cls,
        result: SecurityAnalysisResult,
    ) -> SecurityAnalysisResult:

        owasp = Counter()
        cwe = Counter()
        capec = Counter()

        cvss_scores = []

        enriched = 0
        total = 0

        unique_rules = set()

        for assessment in result.assessments:

            for finding in assessment.findings:

                total += 1

                knowledge = (
                    finding.metadata.get(
                        "knowledge",
                        {}
                    )
                )

                if knowledge:
                    enriched += 1

                unique_rules.add(
                    finding.rule_id
                )

                for item in knowledge.get(
                    "owasp_api_categories",
                    [],
                ):
                    owasp[item] += 1

                for item in knowledge.get(
                    "cwe_ids",
                    [],
                ):
                    cwe[item] += 1

                for item in knowledge.get(
                    "capec_ids",
                    [],
                ):
                    capec[item] += 1

                score = knowledge.get(
                    "cvss_score"
                )

                if isinstance(
                    score,
                    (int, float),
                ):
                    cvss_scores.append(
                        float(score)
                    )

        result.metadata[
            "knowledge_summary"
        ] = {
            "coverage_percent": (
                round(
                    enriched * 100 / total,
                    2,
                )
                if total
                else 0.0
            ),
            "finding_count": total,
            "knowledge_enriched": enriched,
            "unique_rule_count": len(
                unique_rules
            ),
            "owasp": dict(
                sorted(
                    owasp.items()
                )
            ),
            "cwe": dict(
                sorted(
                    cwe.items()
                )
            ),
            "capec": dict(
                sorted(
                    capec.items()
                )
            ),
            "cvss": {
                "count": len(
                    cvss_scores
                ),
                "average": (
                    round(
                        sum(cvss_scores)
                        / len(cvss_scores),
                        2,
                    )
                    if cvss_scores
                    else None
                ),
                "maximum": (
                    max(cvss_scores)
                    if cvss_scores
                    else None
                ),
            },
        }

        return result
