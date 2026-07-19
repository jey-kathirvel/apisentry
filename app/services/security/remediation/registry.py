from __future__ import annotations

from copy import deepcopy
from typing import Iterable

from app.services.security.remediation.models import (
    RemediationGuidance,
)


class RemediationRegistry:
    """
    Central registry for framework-independent
    remediation guidance.
    """

    def __init__(
        self,
        records: Iterable[
            RemediationGuidance
        ]
        | None = None,
    ) -> None:
        self._records: dict[
            str,
            RemediationGuidance,
        ] = {}

        if records is not None:
            self.register_many(
                records
            )

    def register(
        self,
        guidance: RemediationGuidance,
        *,
        replace: bool = False,
    ) -> None:
        rule_id = self._normalize_rule_id(
            guidance.rule_id
        )

        if not rule_id:
            raise ValueError(
                "Remediation rule_id "
                "cannot be empty."
            )

        if (
            rule_id in self._records
            and not replace
        ):
            raise ValueError(
                "Remediation guidance "
                f"already registered: {rule_id}"
            )

        stored = deepcopy(
            guidance
        )
        stored.rule_id = rule_id

        self._records[
            rule_id
        ] = stored

    def register_many(
        self,
        records: Iterable[
            RemediationGuidance
        ],
        *,
        replace: bool = False,
    ) -> None:
        for guidance in records:
            self.register(
                guidance,
                replace=replace,
            )

    def get(
        self,
        rule_id: str,
    ) -> RemediationGuidance | None:
        normalized = (
            self._normalize_rule_id(
                rule_id
            )
        )

        record = self._records.get(
            normalized
        )

        if record is None:
            return None

        return deepcopy(
            record
        )

    def require(
        self,
        rule_id: str,
    ) -> RemediationGuidance:
        guidance = self.get(
            rule_id
        )

        if guidance is None:
            raise KeyError(
                "No remediation guidance "
                f"registered for: {rule_id}"
            )

        return guidance

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
    ) -> list[
        RemediationGuidance
    ]:
        return [
            deepcopy(
                self._records[key]
            )
            for key in sorted(
                self._records
            )
        ]

    def as_dict(
        self,
    ) -> dict[
        str,
        dict,
    ]:
        return {
            guidance.rule_id: (
                guidance.to_dict()
            )
            for guidance in self.all()
        }

    def __len__(
        self,
    ) -> int:
        return len(
            self._records
        )

    def __contains__(
        self,
        rule_id: object,
    ) -> bool:
        if not isinstance(
            rule_id,
            str,
        ):
            return False

        return self.contains(
            rule_id
        )

    @staticmethod
    def _normalize_rule_id(
        rule_id: str,
    ) -> str:
        return str(
            rule_id or ""
        ).strip().upper()
