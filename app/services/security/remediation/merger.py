from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.services.security.remediation.models import (
    RemediationGuidance,
)
from app.services.security.remediation.patch import (
    RemediationPatch,
)


class RemediationMerger:

    @classmethod
    def merge(
        cls,
        guidance: RemediationGuidance,
        patch: RemediationPatch,
    ) -> RemediationGuidance:

        merged = deepcopy(
            guidance,
        )

        merged.implementation_steps = (
            cls._merge_list(
                merged.implementation_steps,
                patch.implementation_steps,
            )
        )

        merged.validation_steps = (
            cls._merge_list(
                merged.validation_steps,
                patch.validation_steps,
            )
        )

        for example in patch.code_examples:
            merged.add_code_example(
                deepcopy(example),
            )

        merged.metadata = (
            cls._deep_merge(
                merged.metadata,
                patch.metadata,
            )
        )

        return merged

    @staticmethod
    def _merge_list(
        original: list[str],
        incoming: list[str],
    ) -> list[str]:

        merged = list(
            original,
        )

        existing = {
            item.strip()
            for item in merged
        }

        for item in incoming:
            normalized = item.strip()

            if normalized not in existing:
                merged.append(item)
                existing.add(
                    normalized,
                )

        return merged

    @classmethod
    def _deep_merge(
        cls,
        original: dict[str, Any],
        incoming: dict[str, Any],
    ) -> dict[str, Any]:

        merged = deepcopy(
            original,
        )

        for key, value in incoming.items():

            if (
                key in merged
                and isinstance(
                    merged[key],
                    dict,
                )
                and isinstance(
                    value,
                    dict,
                )
            ):
                merged[key] = cls._deep_merge(
                    merged[key],
                    value,
                )
            else:
                merged[key] = deepcopy(
                    value,
                )

        return merged
