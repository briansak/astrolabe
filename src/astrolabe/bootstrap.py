"""Install this checkout into .venv when pyproject or the server package changes."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

INSTALL_NOTICE = (
    "Installing this checkout contacts PyPI for Python dependencies, including torch and transformers.\n"
)


def source_hash(root: Path) -> str:
    """Hash the files that should trigger a reinstall."""
    digest = hashlib.sha256()
    paths = [
        root / "pyproject.toml",
        root / "services" / "antares-server" / "pyproject.toml",
    ]
    server = root / "services" / "antares-server" / "antares_server"
    if server.is_dir():
        paths.extend(
            sorted(
                path
                for path in server.rglob("*")
                if path.is_file() and "__pycache__" not in path.parts
            )
        )
    for path in paths:
        if not path.is_file():
            continue
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def install_checkout(root: Path) -> None:
    """Install the checkout and the local inference server.

    The server tree is the package named by the inference extra. Installing it
    from this checkout avoids fetching that package from PyPI.
    """
    pip = root / ".venv" / "bin" / "pip"
    server = root / "services" / "antares-server"
    subprocess.run(
        [str(pip), "install", "-e", str(root), "-e", str(server)],
        check=True,
    )


def ensure_installed(root: Path) -> None:
    """Install when the stamp in .venv does not match the checkout."""
    stamp = root / ".venv" / ".astrolabe-install-hash"
    digest = source_hash(root)
    if stamp.is_file() and stamp.read_text(encoding="utf-8").strip() == digest:
        return
    print(INSTALL_NOTICE, end="")
    install_checkout(root)
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(digest + "\n", encoding="utf-8")


def main() -> int:
    ensure_installed(Path.cwd())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
