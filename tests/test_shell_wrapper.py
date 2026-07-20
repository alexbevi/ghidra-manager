from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

WRAPPER = Path(__file__).resolve().parents[1] / "ghidra-manager"


@pytest.mark.skipif(os.name == "nt", reason="the convenience wrapper is a POSIX shell script")
def test_shell_wrapper_uses_locked_project_and_forwards_arguments(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    capture = tmp_path / "uv-arguments"
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$@" > "$GHIDRA_MANAGER_WRAPPER_CAPTURE"\n'
        "exit 23\n",
        encoding="utf-8",
    )
    fake_uv.chmod(fake_uv.stat().st_mode | stat.S_IXUSR)
    environment = dict(os.environ)
    environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
    environment["GHIDRA_MANAGER_WRAPPER_CAPTURE"] = str(capture)

    result = subprocess.run(
        [str(WRAPPER), "doctor", "ripper", "--program", "RIPPER.LE"],
        cwd=tmp_path,
        env=environment,
        check=False,
    )

    assert WRAPPER.stat().st_mode & stat.S_IXUSR
    assert result.returncode == 23
    assert capture.read_text(encoding="utf-8").splitlines() == [
        "run",
        "--project",
        str(WRAPPER.parent),
        "--locked",
        "ghidra-manager",
        "doctor",
        "ripper",
        "--program",
        "RIPPER.LE",
    ]
