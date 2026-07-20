from __future__ import annotations

from collections.abc import Iterable

from app.services.security.knowledge.models import (
    SecurityKnowledgeRecord,
)


class SecurityKnowledgeRegistry:
    def __init__(
        self,
        records: Iterable[
            SecurityKnowledgeRecord
        ]
        | None = None,
    ) -> None:
        self._records: dict[
            str,
            SecurityKnowledgeRecord,
        ] = {}

        if records:
            self.register_many(
                records
            )

    def register(
        self,
        record: SecurityKnowledgeRecord,
        *,
        replace: bool = False,
    ) -> None:
        rule_id = self._normalize_rule_id(
            record.rule_id
        )

        if (
            not replace
            and rule_id in self._records
        ):
            raise ValueError(
                f"Knowledge record already "
                f"registered: {rule_id}"
            )

        self._records[
            rule_id
        ] = record

    def register_many(
        self,
        records: Iterable[
            SecurityKnowledgeRecord
        ],
        *,
        replace: bool = False,
    ) -> None:
        for record in records:
            self.register(
                record,
                replace=replace,
            )

    def get(
        self,
        rule_id: str,
    ) -> SecurityKnowledgeRecord | None:
        return self._records.get(
            self._normalize_rule_id(
                rule_id
            )
        )

    def require(
        self,
        rule_id: str,
    ) -> SecurityKnowledgeRecord:
        record = self.get(
            rule_id
        )

        if record is None:
            normalized = (
                self._normalize_rule_id(
                    rule_id
                )
            )

            raise KeyError(
                f"Knowledge record not found: "
                f"{normalized}"
            )

        return record

    def contains(
        self,
        rule_id: str,
    ) -> bool:
        return (
            self._normalize_rule_id(
                rule_id
            )
            in self._records
        )

    def all(
        self,
    ) -> tuple[
        SecurityKnowledgeRecord,
        ...,
    ]:
        return tuple(
            self._records[
                rule_id
            ]
            for rule_id in sorted(
                self._records
            )
        )

    def as_dict(
        self,
    ) -> dict[
        str,
        SecurityKnowledgeRecord,
    ]:
        return {
            rule_id: self._records[
                rule_id
            ]
            for rule_id in sorted(
                self._records
            )
        }

    @staticmethod
    def _normalize_rule_id(
        rule_id: str,
    ) -> str:
        normalized = str(
            rule_id or ""
        ).strip().upper()

        if not normalized:
            raise ValueError(
                "rule_id cannot be empty"
            )

        return normalized
