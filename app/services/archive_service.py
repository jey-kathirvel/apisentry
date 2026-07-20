import hashlib
import shutil
import tarfile
import uuid
import zipfile
from pathlib import Path

from fastapi import UploadFile

from app.core.config import settings


class ArchiveValidationError(Exception):
    pass


ALLOWED_EXTENSIONS = {
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
}

IGNORED_NAMES = {
    "__MACOSX",
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
}


def get_archive_suffix(filename: str) -> str:
    lower_name = filename.lower()

    if lower_name.endswith(".tar.gz"):
        return ".tar.gz"

    if lower_name.endswith(".tgz"):
        return ".tgz"

    if lower_name.endswith(".tar"):
        return ".tar"

    if lower_name.endswith(".zip"):
        return ".zip"

    raise ArchiveValidationError(
        "Unsupported archive format. Use ZIP, TAR, TAR.GZ or TGZ."
    )


def ensure_safe_member_path(
    destination: Path,
    member_name: str,
) -> Path:
    member_path = destination / member_name

    resolved_destination = destination.resolve()
    resolved_member = member_path.resolve()

    if (
        resolved_member != resolved_destination
        and resolved_destination not in resolved_member.parents
    ):
        raise ArchiveValidationError(
            "Archive contains an unsafe file path."
        )

    return member_path


def should_ignore_member(member_name: str) -> bool:
    path_parts = Path(member_name).parts

    return any(
        part in IGNORED_NAMES
        for part in path_parts
    )


def calculate_sha256(file_path: Path) -> str:
    digest = hashlib.sha256()

    with file_path.open("rb") as file_handle:
        for chunk in iter(
            lambda: file_handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def validate_archive_file_size(file_size: int) -> None:
    max_size_bytes = (
        settings.max_project_upload_mb
        * 1024
        * 1024
    )

    if file_size <= 0:
        raise ArchiveValidationError(
            "Uploaded archive is empty."
        )

    if file_size > max_size_bytes:
        raise ArchiveValidationError(
            (
                "Uploaded archive exceeds the maximum "
                f"size of {settings.max_project_upload_mb} MB."
            )
        )


def extract_zip(
    archive_path: Path,
    destination: Path,
) -> None:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                if should_ignore_member(member.filename):
                    continue

                target_path = ensure_safe_member_path(
                    destination,
                    member.filename,
                )

                if member.is_dir():
                    target_path.mkdir(
                        parents=True,
                        exist_ok=True,
                    )
                    continue

                target_path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                with archive.open(member) as source:
                    with target_path.open("wb") as target:
                        shutil.copyfileobj(
                            source,
                            target,
                        )

    except zipfile.BadZipFile as exc:
        raise ArchiveValidationError(
            "Invalid or corrupted ZIP archive."
        ) from exc


def extract_tar(
    archive_path: Path,
    destination: Path,
) -> None:
    try:
        with tarfile.open(
            archive_path,
            mode="r:*",
        ) as archive:
            for member in archive.getmembers():
                if should_ignore_member(member.name):
                    continue

                ensure_safe_member_path(
                    destination,
                    member.name,
                )

                if member.issym() or member.islnk():
                    raise ArchiveValidationError(
                        "Archive symbolic links are not allowed."
                    )

            archive.extractall(
                path=destination,
                filter="data",
            )

    except tarfile.TarError as exc:
        raise ArchiveValidationError(
            "Invalid or corrupted TAR archive."
        ) from exc


def extract_archive(
    archive_path: Path,
    destination: Path,
    archive_suffix: str,
) -> None:
    destination.mkdir(
        parents=True,
        exist_ok=True,
    )

    if archive_suffix == ".zip":
        extract_zip(
            archive_path=archive_path,
            destination=destination,
        )
        return

    extract_tar(
        archive_path=archive_path,
        destination=destination,
    )


def find_project_root(
    extracted_path: Path,
) -> Path:
    children = [
        child
        for child in extracted_path.iterdir()
        if child.name not in IGNORED_NAMES
    ]

    directories = [
        child
        for child in children
        if child.is_dir()
    ]

    files = [
        child
        for child in children
        if child.is_file()
    ]

    if len(directories) == 1 and not files:
        return directories[0]

    return extracted_path


def cleanup_path(path: Path) -> None:
    if path.exists():
        shutil.rmtree(
            path,
            ignore_errors=True,
        )


def save_and_extract_upload(
    upload: UploadFile,
    user_id: int,
) -> dict[str, str | int]:
    original_filename = Path(
        upload.filename or ""
    ).name

    if not original_filename:
        raise ArchiveValidationError(
            "Uploaded filename is missing."
        )

    archive_suffix = get_archive_suffix(
        original_filename,
    )

    storage_root = Path(
        settings.project_storage_path
    )

    user_root = storage_root / str(user_id)
    upload_id = uuid.uuid4().hex
    upload_root = user_root / upload_id
    archive_root = upload_root / "archive"
    extracted_root = upload_root / "source"

    archive_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    stored_filename = (
        f"{uuid.uuid4().hex}{archive_suffix}"
    )

    archive_path = (
        archive_root / stored_filename
    )

    file_size = 0

    try:
        with archive_path.open("wb") as destination:
            while True:
                chunk = upload.file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                file_size += len(chunk)

                validate_archive_file_size(
                    file_size,
                )

                destination.write(chunk)

        validate_archive_file_size(
            file_size,
        )

        checksum = calculate_sha256(
            archive_path,
        )

        extract_archive(
            archive_path=archive_path,
            destination=extracted_root,
            archive_suffix=archive_suffix,
        )

        project_root = find_project_root(
            extracted_root,
        )

        return {
            "original_filename": original_filename,
            "stored_filename": stored_filename,
            "archive_path": str(archive_path),
            "extracted_path": str(extracted_root),
            "project_root": str(project_root),
            "sha256_checksum": checksum,
            "file_size": file_size,
            "upload_id": upload_id,
        }

    except Exception:
        cleanup_path(
            upload_root,
        )
        raise

    finally:
        upload.file.close()
