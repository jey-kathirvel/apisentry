import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


IGNORED_DIRECTORIES = {
    ".git",
    ".svn",
    ".hg",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".next",
    ".nuxt",
    "node_modules",
    "vendor",
    "venv",
    ".venv",
    "dist",
    "build",
    "coverage",
    "target",
}


@dataclass
class TechnologyDetectionResult:
    primary_language: str | None = None
    primary_framework: str | None = None
    framework_version: str | None = None

    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)

    confidence: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "primary_language": self.primary_language,
            "primary_framework": self.primary_framework,
            "framework_version": self.framework_version,
            "languages": self.languages,
            "frameworks": self.frameworks,
            "tools": self.tools,
            "manifests": self.manifests,
            "confidence": self.confidence,
        }


def unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def safe_read_text(
    file_path: Path,
    max_bytes: int = 2 * 1024 * 1024,
) -> str:
    try:
        if not file_path.is_file():
            return ""

        if file_path.stat().st_size > max_bytes:
            return ""

        return file_path.read_text(
            encoding="utf-8",
            errors="ignore",
        )

    except OSError:
        return ""


def safe_read_json(file_path: Path) -> dict[str, Any]:
    try:
        content = safe_read_text(file_path)

        if not content:
            return {}

        parsed = json.loads(content)

        if isinstance(parsed, dict):
            return parsed

        return {}

    except (json.JSONDecodeError, OSError):
        return {}


def iter_project_files(project_root: Path):
    for path in project_root.rglob("*"):
        try:
            relative_parts = path.relative_to(
                project_root
            ).parts
        except ValueError:
            continue

        if any(
            part in IGNORED_DIRECTORIES
            for part in relative_parts
        ):
            continue

        if path.is_file():
            yield path


def collect_file_statistics(
    project_root: Path,
) -> tuple[dict[str, int], set[str]]:
    extension_counts: dict[str, int] = {}
    filenames: set[str] = set()

    for file_path in iter_project_files(project_root):
        filenames.add(file_path.name.lower())

        suffix = file_path.suffix.lower()

        if suffix:
            extension_counts[suffix] = (
                extension_counts.get(suffix, 0) + 1
            )

    return extension_counts, filenames


def detect_languages(
    extension_counts: dict[str, int],
    filenames: set[str],
) -> list[str]:
    scores: dict[str, int] = {
        "Python": (
            extension_counts.get(".py", 0) * 5
        ),
        "JavaScript": (
            extension_counts.get(".js", 0) * 4
            + extension_counts.get(".jsx", 0) * 5
            + extension_counts.get(".mjs", 0) * 4
            + extension_counts.get(".cjs", 0) * 4
        ),
        "TypeScript": (
            extension_counts.get(".ts", 0) * 5
            + extension_counts.get(".tsx", 0) * 5
        ),
        "Java": (
            extension_counts.get(".java", 0) * 5
        ),
        "Kotlin": (
            extension_counts.get(".kt", 0) * 5
            + extension_counts.get(".kts", 0) * 4
        ),
        "C#": (
            extension_counts.get(".cs", 0) * 5
        ),
        "PHP": (
            extension_counts.get(".php", 0) * 5
        ),
        "Go": (
            extension_counts.get(".go", 0) * 5
        ),
        "Ruby": (
            extension_counts.get(".rb", 0) * 5
        ),
        "Dart": (
            extension_counts.get(".dart", 0) * 5
        ),
        "Rust": (
            extension_counts.get(".rs", 0) * 5
        ),
        "C++": (
            extension_counts.get(".cpp", 0) * 5
            + extension_counts.get(".cc", 0) * 5
            + extension_counts.get(".hpp", 0) * 3
        ),
        "C": (
            extension_counts.get(".c", 0) * 5
            + extension_counts.get(".h", 0) * 2
        ),
    }

    if "requirements.txt" in filenames:
        scores["Python"] += 10

    if "pyproject.toml" in filenames:
        scores["Python"] += 10

    if "package.json" in filenames:
        scores["JavaScript"] += 6

    if "tsconfig.json" in filenames:
        scores["TypeScript"] += 15

    if "pom.xml" in filenames:
        scores["Java"] += 15

    if "build.gradle" in filenames:
        scores["Java"] += 10

    if "build.gradle.kts" in filenames:
        scores["Kotlin"] += 15

    if "composer.json" in filenames:
        scores["PHP"] += 15

    if "go.mod" in filenames:
        scores["Go"] += 15

    if "pubspec.yaml" in filenames:
        scores["Dart"] += 15

    if "cargo.toml" in filenames:
        scores["Rust"] += 15

    ranked = sorted(
        (
            (language, score)
            for language, score in scores.items()
            if score > 0
        ),
        key=lambda item: item[1],
        reverse=True,
    )

    return [
        language
        for language, _ in ranked
    ]


def dependency_version(
    dependencies: dict[str, Any],
    dependency_name: str,
) -> str | None:
    value = dependencies.get(dependency_name)

    if not isinstance(value, str):
        return None

    cleaned = re.sub(
        r"^[~^<>=\s]+",
        "",
        value,
    )

    return cleaned or None


def detect_node_frameworks(
    project_root: Path,
) -> tuple[list[str], dict[str, str]]:
    frameworks: list[str] = []
    versions: dict[str, str] = {}

    package_files = list(
        project_root.rglob("package.json")
    )

    for package_file in package_files:
        if any(
            part in IGNORED_DIRECTORIES
            for part in package_file.parts
        ):
            continue

        package_data = safe_read_json(
            package_file
        )

        dependencies: dict[str, Any] = {}

        for key in (
            "dependencies",
            "devDependencies",
            "peerDependencies",
        ):
            section = package_data.get(key, {})

            if isinstance(section, dict):
                dependencies.update(section)

        mappings = {
            "next": "Next.js",
            "express": "Express",
            "@nestjs/core": "NestJS",
            "react": "React",
            "@angular/core": "Angular",
            "vue": "Vue",
            "nuxt": "Nuxt",
            "svelte": "Svelte",
            "@sveltejs/kit": "SvelteKit",
            "fastify": "Fastify",
            "koa": "Koa",
            "hapi": "Hapi",
            "@hapi/hapi": "Hapi",
            "react-native": "React Native",
        }

        for dependency, framework in mappings.items():
            if dependency not in dependencies:
                continue

            frameworks.append(framework)

            version = dependency_version(
                dependencies,
                dependency,
            )

            if version:
                versions[framework] = version

    return unique(frameworks), versions


def detect_python_frameworks(
    project_root: Path,
) -> tuple[list[str], dict[str, str]]:
    frameworks: list[str] = []
    versions: dict[str, str] = {}

    dependency_files = [
        *project_root.rglob("requirements.txt"),
        *project_root.rglob("pyproject.toml"),
        *project_root.rglob("Pipfile"),
        *project_root.rglob("poetry.lock"),
    ]

    framework_patterns = {
        "FastAPI": r"(?im)^\s*fastapi\s*(?:==|>=|~=|\^)?\s*([0-9][^\s;,\"]*)?",
        "Flask": r"(?im)^\s*flask\s*(?:==|>=|~=|\^)?\s*([0-9][^\s;,\"]*)?",
        "Django": r"(?im)^\s*django\s*(?:==|>=|~=|\^)?\s*([0-9][^\s;,\"]*)?",
        "Starlette": r"(?im)^\s*starlette\s*(?:==|>=|~=|\^)?\s*([0-9][^\s;,\"]*)?",
        "Sanic": r"(?im)^\s*sanic\s*(?:==|>=|~=|\^)?\s*([0-9][^\s;,\"]*)?",
        "Tornado": r"(?im)^\s*tornado\s*(?:==|>=|~=|\^)?\s*([0-9][^\s;,\"]*)?",
    }

    for dependency_file in dependency_files:
        if any(
            part in IGNORED_DIRECTORIES
            for part in dependency_file.parts
        ):
            continue

        content = safe_read_text(
            dependency_file
        )

        for framework, pattern in framework_patterns.items():
            match = re.search(
                pattern,
                content,
            )

            if not match:
                continue

            frameworks.append(framework)

            if match.lastindex:
                version = match.group(1)

                if version:
                    versions[framework] = (
                        version.strip()
                    )

    python_files = list(
        project_root.rglob("*.py")
    )

    import_markers = {
        "FastAPI": (
            "from fastapi import",
            "import fastapi",
        ),
        "Flask": (
            "from flask import",
            "import flask",
        ),
        "Django": (
            "from django",
            "import django",
        ),
    }

    for python_file in python_files[:500]:
        if any(
            part in IGNORED_DIRECTORIES
            for part in python_file.parts
        ):
            continue

        content = safe_read_text(
            python_file,
            max_bytes=512 * 1024,
        )

        for framework, markers in import_markers.items():
            if any(
                marker in content
                for marker in markers
            ):
                frameworks.append(framework)

    return unique(frameworks), versions


def detect_java_frameworks(
    project_root: Path,
) -> tuple[list[str], dict[str, str]]:
    frameworks: list[str] = []
    versions: dict[str, str] = {}

    pom_files = list(
        project_root.rglob("pom.xml")
    )

    for pom_file in pom_files:
        if any(
            part in IGNORED_DIRECTORIES
            for part in pom_file.parts
        ):
            continue

        content = safe_read_text(
            pom_file
        )

        if "spring-boot" in content.lower():
            frameworks.append("Spring Boot")

        try:
            root = ET.fromstring(content)

            for element in root.iter():
                tag = element.tag.split("}")[-1]

                if (
                    tag == "spring-boot.version"
                    and element.text
                ):
                    versions["Spring Boot"] = (
                        element.text.strip()
                    )

        except ET.ParseError:
            pass

    gradle_files = [
        *project_root.rglob("build.gradle"),
        *project_root.rglob("build.gradle.kts"),
    ]

    for gradle_file in gradle_files:
        content = safe_read_text(
            gradle_file
        )

        if (
            "org.springframework.boot"
            in content
        ):
            frameworks.append("Spring Boot")

            match = re.search(
                r'org\.springframework\.boot["\']?\s+version\s+["\']([^"\']+)',
                content,
            )

            if match:
                versions["Spring Boot"] = (
                    match.group(1)
                )

    return unique(frameworks), versions


def detect_php_frameworks(
    project_root: Path,
) -> tuple[list[str], dict[str, str]]:
    frameworks: list[str] = []
    versions: dict[str, str] = {}

    for composer_file in project_root.rglob(
        "composer.json"
    ):
        composer_data = safe_read_json(
            composer_file
        )

        dependencies: dict[str, Any] = {}

        for key in ("require", "require-dev"):
            section = composer_data.get(key, {})

            if isinstance(section, dict):
                dependencies.update(section)

        mappings = {
            "laravel/framework": "Laravel",
            "symfony/framework-bundle": "Symfony",
            "slim/slim": "Slim",
        }

        for dependency, framework in mappings.items():
            if dependency not in dependencies:
                continue

            frameworks.append(framework)

            version = dependency_version(
                dependencies,
                dependency,
            )

            if version:
                versions[framework] = version

    return unique(frameworks), versions


def detect_dotnet_frameworks(
    project_root: Path,
) -> tuple[list[str], dict[str, str]]:
    frameworks: list[str] = []
    versions: dict[str, str] = {}

    for project_file in project_root.rglob(
        "*.csproj"
    ):
        content = safe_read_text(
            project_file
        )

        if (
            "Microsoft.NET.Sdk.Web"
            in content
            or "Microsoft.AspNetCore"
            in content
        ):
            frameworks.append("ASP.NET Core")

        match = re.search(
            r"<TargetFramework>([^<]+)</TargetFramework>",
            content,
        )

        if match:
            versions["ASP.NET Core"] = (
                match.group(1)
            )

    return unique(frameworks), versions


def detect_dart_frameworks(
    project_root: Path,
) -> tuple[list[str], dict[str, str]]:
    frameworks: list[str] = []
    versions: dict[str, str] = {}

    for pubspec_file in project_root.rglob(
        "pubspec.yaml"
    ):
        content = safe_read_text(
            pubspec_file
        )

        if re.search(
            r"(?m)^\s*flutter\s*:",
            content,
        ):
            frameworks.append("Flutter")

        sdk_match = re.search(
            r"(?ms)environment\s*:\s*.*?sdk\s*:\s*[\"']?([^\"'\n]+)",
            content,
        )

        if sdk_match:
            versions["Flutter"] = (
                sdk_match.group(1).strip()
            )

    return unique(frameworks), versions


def detect_tools(
    project_root: Path,
    filenames: set[str],
) -> list[str]:
    tools: list[str] = []

    if (
        "dockerfile" in filenames
        or "docker-compose.yml" in filenames
        or "docker-compose.yaml" in filenames
        or "compose.yml" in filenames
        or "compose.yaml" in filenames
    ):
        tools.append("Docker")

    if any(
        path.name.lower() in {
            "deployment.yaml",
            "deployment.yml",
            "service.yaml",
            "service.yml",
            "ingress.yaml",
            "ingress.yml",
        }
        for path in iter_project_files(project_root)
    ):
        tools.append("Kubernetes")

    if any(
        path.suffix.lower() == ".tf"
        for path in iter_project_files(project_root)
    ):
        tools.append("Terraform")

    if (
        project_root / ".github" / "workflows"
    ).exists():
        tools.append("GitHub Actions")

    if "jenkinsfile" in filenames:
        tools.append("Jenkins")

    if any(
        name in filenames
        for name in {
            "openapi.json",
            "openapi.yaml",
            "openapi.yml",
            "swagger.json",
            "swagger.yaml",
            "swagger.yml",
        }
    ):
        tools.append("OpenAPI")

    if any(
        file_path.name.lower().endswith(
            ".postman_collection.json"
        )
        for file_path in iter_project_files(
            project_root
        )
    ):
        tools.append("Postman Collection")

    return unique(tools)


def detect_manifests(
    filenames: set[str],
) -> list[str]:
    known_manifests = [
        "requirements.txt",
        "pyproject.toml",
        "pipfile",
        "poetry.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "composer.json",
        "go.mod",
        "cargo.toml",
        "pubspec.yaml",
        "gemfile",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
    ]

    return [
        manifest
        for manifest in known_manifests
        if manifest in filenames
    ]


def select_primary_framework(
    frameworks: list[str],
) -> str | None:
    priority = [
        "FastAPI",
        "Django",
        "Flask",
        "Spring Boot",
        "NestJS",
        "Next.js",
        "Express",
        "Laravel",
        "Symfony",
        "ASP.NET Core",
        "Flutter",
        "React Native",
        "Angular",
        "Vue",
        "Nuxt",
        "React",
        "Fastify",
        "Koa",
        "Hapi",
        "SvelteKit",
        "Svelte",
        "Starlette",
        "Sanic",
        "Tornado",
        "Slim",
    ]

    for framework in priority:
        if framework in frameworks:
            return framework

    return frameworks[0] if frameworks else None


def calculate_confidence(
    primary_language: str | None,
    primary_framework: str | None,
    manifests: list[str],
    tools: list[str],
) -> int:
    confidence = 0

    if primary_language:
        confidence += 35

    if primary_framework:
        confidence += 45

    if manifests:
        confidence += min(
            len(manifests) * 4,
            12,
        )

    if tools:
        confidence += min(
            len(tools) * 2,
            8,
        )

    return min(confidence, 100)


def detect_project_technology(
    project_root: str | Path,
) -> TechnologyDetectionResult:
    root = Path(project_root).resolve()

    if not root.exists():
        raise FileNotFoundError(
            f"Project path does not exist: {root}"
        )

    if not root.is_dir():
        raise NotADirectoryError(
            f"Project path is not a directory: {root}"
        )

    extension_counts, filenames = (
        collect_file_statistics(root)
    )

    languages = detect_languages(
        extension_counts,
        filenames,
    )

    frameworks: list[str] = []
    versions: dict[str, str] = {}

    detectors = [
        detect_python_frameworks,
        detect_node_frameworks,
        detect_java_frameworks,
        detect_php_frameworks,
        detect_dotnet_frameworks,
        detect_dart_frameworks,
    ]

    for detector in detectors:
        detected_frameworks, detected_versions = (
            detector(root)
        )

        frameworks.extend(
            detected_frameworks
        )
        versions.update(
            detected_versions
        )

    frameworks = unique(frameworks)

    tools = detect_tools(
        root,
        filenames,
    )

    manifests = detect_manifests(
        filenames,
    )

    primary_language = (
        languages[0]
        if languages
        else None
    )

    primary_framework = (
        select_primary_framework(
            frameworks
        )
    )

    framework_version = (
        versions.get(primary_framework)
        if primary_framework
        else None
    )

    confidence = calculate_confidence(
        primary_language=primary_language,
        primary_framework=primary_framework,
        manifests=manifests,
        tools=tools,
    )

    return TechnologyDetectionResult(
        primary_language=primary_language,
        primary_framework=primary_framework,
        framework_version=framework_version,
        languages=languages,
        frameworks=frameworks,
        tools=tools,
        manifests=manifests,
        confidence=confidence,
    )
