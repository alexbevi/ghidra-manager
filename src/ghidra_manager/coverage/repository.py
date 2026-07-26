"""Git repository identities and deterministic source access."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

from ghidra_manager.errors import ManagerError


def git(repository: Path, *arguments: str, text: bool = True) -> str | bytes:
    command = ["git", "-C", str(repository), *arguments]
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=text,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        raise ManagerError(f"Git command failed in {repository}: {detail}") from exc
    output = result.stdout
    if text:
        assert isinstance(output, str)
        return output
    assert isinstance(output, bytes)
    return output


def repository_root(path: Path) -> Path:
    value = str(git(path.expanduser().resolve(), "rev-parse", "--show-toplevel")).strip()
    return Path(value).resolve()


def ensure_locally_ignored(repository: Path, relative: Path) -> None:
    """Ignore coverage locally without changing the tracked .gitignore."""
    relative_text = relative.as_posix().strip("/")
    check = subprocess.run(
        ["git", "-C", str(repository), "check-ignore", "-q", "--", relative_text],
        check=False,
        capture_output=True,
    )
    if check.returncode == 0:
        return
    git_dir = Path(str(git(repository, "rev-parse", "--git-dir")).strip())
    if not git_dir.is_absolute():
        git_dir = repository / git_dir
    exclude = git_dir / "info" / "exclude"
    exclude.parent.mkdir(parents=True, exist_ok=True)
    entry = f"/{relative_text}/"
    existing = exclude.read_text(encoding="utf-8") if exclude.exists() else ""
    if entry not in {line.strip() for line in existing.splitlines()}:
        separator = "" if not existing or existing.endswith("\n") else "\n"
        with exclude.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"{separator}{entry}\n")


def repository_identity(repository: Path, *, allow_dirty: bool = False) -> dict[str, object]:
    root = repository_root(repository)
    head = str(git(root, "rev-parse", "HEAD")).strip()
    tree = str(git(root, "rev-parse", "HEAD^{tree}")).strip()
    status = str(git(root, "status", "--porcelain=v1", "--untracked-files=all"))
    dirty = bool(status)
    if dirty and not allow_dirty:
        raise ManagerError(
            f"Reimplementation repository is dirty: {root}. "
            "Commit/stash changes or pass --allow-dirty."
        )
    remote_result = subprocess.run(
        ["git", "-C", str(root), "remote", "get-url", "origin"],
        check=False,
        capture_output=True,
        text=True,
    )
    remote = remote_result.stdout.strip() if remote_result.returncode == 0 else None
    digest = hashlib.sha256()
    digest.update(head.encode())
    digest.update(b"\0")
    digest.update(tree.encode())
    if dirty:
        digest.update(status.encode())
        tracked_diff = git(root, "diff", "--binary", "HEAD", text=False)
        assert isinstance(tracked_diff, bytes)
        digest.update(tracked_diff)
        for line in status.splitlines():
            if not line.startswith("?? "):
                continue
            relative = line[3:]
            path = root / relative
            if path.is_file():
                digest.update(relative.encode())
                digest.update(path.read_bytes())
    return {
        "root": str(root),
        "remote": remote,
        "revision": head,
        "tree": tree,
        "dirty": dirty,
        "content_fingerprint": f"sha256:{digest.hexdigest()}",
    }


def relative_posix(path: Path, repository: Path) -> str:
    try:
        return path.resolve().relative_to(repository.resolve()).as_posix()
    except ValueError as exc:
        raise ManagerError(f"Coverage path is outside repository: {path}") from exc


def atomic_directory_create(staged: Path, target: Path) -> None:
    try:
        os.replace(staged, target)
    except OSError as exc:
        raise ManagerError(f"Unable to create coverage workspace {target}: {exc}") from exc
