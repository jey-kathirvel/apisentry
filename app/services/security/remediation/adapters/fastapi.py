from __future__ import annotations

from app.services.security.models import (
    SecurityFinding,
)
from app.services.security.remediation.adapters.base import (
    FrameworkAdapter,
    FrameworkContext,
)
from app.services.security.remediation.models import (
    RemediationGuidance,
    SecureCodeExample,
)
from app.services.security.remediation.patch import (
    RemediationPatch,
)


class FastAPIAdapter(
    FrameworkAdapter,
):
    name = "fastapi"

    aliases = (
        "fast api",
        "fast-api",
    )

    languages = (
        "python",
    )

    priority = 10

    def decorate(
        self,
        *,
        finding: SecurityFinding,
        guidance: RemediationGuidance,
        context: FrameworkContext,
    ) -> RemediationPatch:

        builder = getattr(
            self,
            f"_build_{finding.rule_id.lower().replace('-','_')}",
            None,
        )

        if builder is None:
            return RemediationPatch()

        return builder(
            context,
        )

    def _build_auth_001(
        self,
        context: FrameworkContext,
    ) -> RemediationPatch:

        return RemediationPatch(
            implementation_steps=[
                "Protect the endpoint using Depends(get_current_user).",
                "Reject missing or invalid bearer tokens.",
            ],
            validation_steps=[
                "Verify anonymous requests return HTTP 401.",
            ],
            code_examples=[
                SecureCodeExample(
                    framework="FastAPI",
                    language="Python",
                    title="JWT Authentication",
                    code="""from fastapi import Depends

@router.get("/users")
async def users(
    current_user=Depends(get_current_user),
):
    return []""",
                    explanation="Require an authenticated user.",
                    file_hint="app/api/*.py",
                ),
            ],
            metadata={
                "adapter": "fastapi",
                "rule": "AUTH-001",
            },
        )

    def _build_auth_002(
        self,
        context: FrameworkContext,
    ) -> RemediationPatch:

        return RemediationPatch(
            implementation_steps=[
                "Verify user roles before processing.",
                "Perform ownership validation.",
            ],
            validation_steps=[
                "Verify unauthorized users receive HTTP 403.",
            ],
            code_examples=[
                SecureCodeExample(
                    framework="FastAPI",
                    language="Python",
                    title="Role Validation",
                    code="""@router.delete("/{id}")
async def delete(
    id:int,
    current_user=Depends(get_admin_user),
):
    ...""",
                    explanation="Allow only authorized users.",
                ),
            ],
            metadata={
                "adapter": "fastapi",
                "rule": "AUTH-002",
            },
        )

    def _build_val_001(
        self,
        context: FrameworkContext,
    ) -> RemediationPatch:

        return RemediationPatch(
            implementation_steps=[
                "Use Pydantic request models.",
                "Validate all input fields.",
            ],
            validation_steps=[
                "Submit malformed payloads.",
            ],
            code_examples=[
                SecureCodeExample(
                    framework="FastAPI",
                    language="Python",
                    title="Pydantic Validation",
                    code="""class UserRequest(BaseModel):
    name:str
    age:int = Field(ge=18, le=100)""",
                ),
            ],
            metadata={
                "adapter": "fastapi",
                "rule": "VAL-001",
            },
        )

    def _build_file_001(
        self,
        context: FrameworkContext,
    ) -> RemediationPatch:

        return RemediationPatch(
            implementation_steps=[
                "Validate MIME type.",
                "Validate file size.",
                "Store files outside the web root.",
            ],
            validation_steps=[
                "Upload executable files.",
                "Upload oversized files.",
            ],
            code_examples=[
                SecureCodeExample(
                    framework="FastAPI",
                    language="Python",
                    title="Secure Upload",
                    code="""@router.post("/upload")
async def upload(
    file: UploadFile,
):
    if file.content_type not in {
        "image/png",
        "image/jpeg",
    }:
        raise HTTPException(400)

    return {"ok":True}""",
                ),
            ],
            metadata={
                "adapter": "fastapi",
                "rule": "FILE-001",
            },
        )
