from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OwaspApiCategory:
    id: str
    title: str
    description: str


OWASP_API_TOP10_2023: dict[str, OwaspApiCategory] = {
    "API1:2023": OwaspApiCategory(
        id="API1:2023",
        title="Broken Object Level Authorization",
        description="Object-level authorization is not properly enforced.",
    ),
    "API2:2023": OwaspApiCategory(
        id="API2:2023",
        title="Broken Authentication",
        description="Authentication weaknesses allow attackers to compromise identities.",
    ),
    "API3:2023": OwaspApiCategory(
        id="API3:2023",
        title="Broken Object Property Level Authorization",
        description="Unauthorized access to sensitive object properties.",
    ),
    "API4:2023": OwaspApiCategory(
        id="API4:2023",
        title="Unrestricted Resource Consumption",
        description="Missing limits can lead to denial-of-service conditions.",
    ),
    "API5:2023": OwaspApiCategory(
        id="API5:2023",
        title="Broken Function Level Authorization",
        description="Functions are exposed without proper authorization.",
    ),
    "API6:2023": OwaspApiCategory(
        id="API6:2023",
        title="Unrestricted Access to Sensitive Business Flows",
        description="Business workflows can be abused without sufficient controls.",
    ),
    "API7:2023": OwaspApiCategory(
        id="API7:2023",
        title="Server Side Request Forgery",
        description="The API can be abused to make unintended server-side requests.",
    ),
    "API8:2023": OwaspApiCategory(
        id="API8:2023",
        title="Security Misconfiguration",
        description="Incorrect configuration exposes the API to attack.",
    ),
    "API9:2023": OwaspApiCategory(
        id="API9:2023",
        title="Improper Inventory Management",
        description="Deprecated or unmanaged API versions increase attack surface.",
    ),
    "API10:2023": OwaspApiCategory(
        id="API10:2023",
        title="Unsafe Consumption of APIs",
        description="Trusting external APIs without validation introduces risk.",
    ),
}
