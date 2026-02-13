"""Archive extraction helpers."""

from __future__ import annotations

import os
import posixpath
import re
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import List

from ..errors import CLIError


def extract_archive(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)

    def normalize_member_path(member: str) -> str:
        normalized = (member or "").replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        if not normalized:
            return ""
        if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
            raise CLIError(
                f"archive entry contains an absolute path: {member!r} ({archive.name})"
            )
        parts = [part for part in normalized.split("/") if part not in {"", "."}]
        if any(part == ".." for part in parts):
            raise CLIError(
                f"archive entry attempts path traversal: {member!r} ({archive.name})"
            )
        return "/".join(parts)

    def ensure_safe_parents(parts: List[str]) -> Path:
        current = dest
        for part in parts:
            current = current / part
            if current.exists():
                if current.is_symlink():
                    raise CLIError(
                        f"refusing to extract into symlinked directory {current} ({archive.name})"
                    )
                if not current.is_dir():
                    raise CLIError(
                        f"refusing to extract into non-directory {current} ({archive.name})"
                    )
                continue
            current.mkdir()
        return current

    def validate_within_dest(relative_posix: str) -> Path:
        rel_path = Path(*[p for p in relative_posix.split("/") if p])
        target = dest / rel_path
        dest_real = dest.resolve()
        try:
            target_real = target.resolve()
        except FileNotFoundError:
            # Resolve the parent that does exist (best-effort). Path traversal is
            # already prevented by normalize_member_path.
            target_real = dest_real / rel_path
        if dest_real != target_real and dest_real not in target_real.parents:
            raise CLIError(
                f"archive entry escapes destination: {relative_posix!r} ({archive.name})"
            )
        return target

    suffix = archive.name.lower()
    if suffix.endswith(".zip"):
        try:
            with zipfile.ZipFile(archive) as zf:
                for info in zf.infolist():
                    entry = normalize_member_path(info.filename)
                    if not entry:
                        continue
                    if info.is_dir() or info.filename.endswith("/"):
                        ensure_safe_parents(entry.split("/"))
                        continue
                    target = validate_within_dest(entry)
                    ensure_safe_parents(entry.split("/")[:-1])
                    if target.exists() and target.is_symlink():
                        raise CLIError(
                            f"refusing to overwrite symlink {target} ({archive.name})"
                        )
                    with zf.open(info, "r") as src, target.open("wb") as out:
                        shutil.copyfileobj(src, out)
                    mode = (info.external_attr >> 16) & 0o777
                    if mode:
                        try:
                            os.chmod(target, mode)
                        except OSError:
                            pass
            return
        except zipfile.BadZipFile as exc:
            raise CLIError(f"unsupported archive format for {archive.name}") from exc

    if any(suffix.endswith(ext) for ext in (".tar.gz", ".tgz", ".tar")):
        try:
            with tarfile.open(archive, mode="r:*") as tf:
                for member in tf.getmembers():
                    entry = normalize_member_path(member.name)
                    if not entry:
                        continue
                    target = validate_within_dest(entry)
                    parent_parts = entry.split("/")[:-1]
                    ensure_safe_parents(parent_parts)

                    if member.isdir():
                        ensure_safe_parents(entry.split("/"))
                        continue

                    if member.issym():
                        linkname = (member.linkname or "").replace("\\", "/").strip()
                        if not linkname:
                            continue
                        if linkname.startswith("/") or re.match(r"^[A-Za-z]:", linkname):
                            raise CLIError(
                                f"refusing to extract absolute symlink target {linkname!r} ({archive.name})"
                            )
                        combined = posixpath.normpath(
                            posixpath.join(posixpath.dirname(entry), linkname)
                        )
                        if combined.startswith("..") or combined == "..":
                            raise CLIError(
                                f"refusing to extract symlink escaping destination: {entry!r} -> {linkname!r} ({archive.name})"
                            )
                        if target.exists():
                            target.unlink()
                        try:
                            os.symlink(linkname, target)
                        except (NotImplementedError, OSError) as exc:
                            raise CLIError(
                                f"failed to create symlink for {entry!r}: {exc}"
                            ) from exc
                        continue

                    if member.islnk():
                        linkname = (member.linkname or "").replace("\\", "/").strip()
                        if not linkname:
                            continue
                        if linkname.startswith("/") or re.match(r"^[A-Za-z]:", linkname):
                            raise CLIError(
                                f"refusing to extract absolute hardlink target {linkname!r} ({archive.name})"
                            )
                        combined = posixpath.normpath(linkname)
                        if combined.startswith("..") or combined == "..":
                            raise CLIError(
                                f"refusing to extract hardlink escaping destination: {entry!r} -> {linkname!r} ({archive.name})"
                            )
                        source = validate_within_dest(combined)
                        if not source.exists():
                            raise CLIError(
                                f"hardlink target missing while extracting {entry!r} ({archive.name})"
                            )
                        if target.exists():
                            target.unlink()
                        try:
                            os.link(source, target)
                        except OSError as exc:
                            raise CLIError(
                                f"failed to create hardlink for {entry!r}: {exc}"
                            ) from exc
                        continue

                    if not member.isreg():
                        raise CLIError(
                            f"unsupported archive entry type for {entry!r} ({archive.name})"
                        )

                    if target.exists() and target.is_symlink():
                        raise CLIError(
                            f"refusing to overwrite symlink {target} ({archive.name})"
                        )
                    file_obj = tf.extractfile(member)
                    if file_obj is None:
                        continue
                    with file_obj as src, target.open("wb") as out:
                        shutil.copyfileobj(src, out)
                    if member.mode:
                        try:
                            os.chmod(target, member.mode & 0o777)
                        except OSError:
                            pass
            return
        except tarfile.TarError as exc:
            raise CLIError(f"unsupported archive format for {archive.name}") from exc

    raise CLIError(f"unsupported archive format for {archive.name}")
