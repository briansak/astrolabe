"""Shared socket and token-directory paths for the server, the runner, and status."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from astrolabe.engagement import engagements_root

SOCKET_VARIABLES = ("ANTARES_SOCKET", "ASTROLABE_INFERENCE_SOCKET")
TOKEN_VARIABLES = ("ANTARES_TOKEN_DIR", "ASTROLABE_TOKEN_DIR")


class SocketDirectoryError(Exception):
    """A runtime directory is unsafe, the two paths disagree, or the socket path is too long."""


def sun_path_limit() -> int:
    """sockaddr_un.sun_path size, including the terminating NUL."""
    if sys.platform == "darwin":
        return 104
    return 108


def default_socket_directory() -> Path:
    """Per-user directory that holds only the socket. No engagement is required."""
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Astrolabe" / "run"
    return _linux_runtime_directory() / "astrolabe"


def default_token_directory() -> Path:
    """Per-user token directory outside the socket directory."""
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Astrolabe" / "tokens"
    return _linux_runtime_directory() / "astrolabe-tokens"


def _linux_runtime_directory() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR", "").strip()
    if runtime:
        return Path(runtime)
    return Path(f"/run/user/{os.getuid()}")


def socket_override_mismatch() -> tuple[str, str] | None:
    return _override_mismatch(*SOCKET_VARIABLES)


def token_override_mismatch() -> tuple[str, str] | None:
    return _override_mismatch(*TOKEN_VARIABLES)


def resolved_inference_socket() -> Path:
    """The shared socket path. A mismatch raises. Length is not checked."""
    mismatch = socket_override_mismatch()
    if mismatch is not None:
        server, runner = mismatch
        raise SocketDirectoryError(f"{server} and {runner}")
    return _chosen_path(*SOCKET_VARIABLES, default=default_socket_directory() / "inference.sock")


def configured_inference_socket() -> Path:
    """The shared socket. One set variable supplies the other. A mismatch or overlong path raises."""
    path = resolved_inference_socket()
    if _override_is_set(SOCKET_VARIABLES):
        default = default_socket_directory() / "inference.sock"
        _refuse_inside_engagements(path.parent, label="Socket directory", default=default)
        _refuse_inside_engagements(path, label="Socket directory", default=default)
    _require_sun_path(path)
    return path


def configured_token_directory() -> Path:
    """The shared token directory. One set variable supplies the other."""
    mismatch = token_override_mismatch()
    if mismatch is not None:
        server, runner = mismatch
        raise SocketDirectoryError(f"{server} and {runner}")
    directory = _chosen_path(*TOKEN_VARIABLES, default=default_token_directory())
    if _override_is_set(TOKEN_VARIABLES):
        _refuse_inside_engagements(
            directory,
            label="Token directory",
            default=default_token_directory(),
        )
    try:
        socket_dir = resolved_inference_socket().parent
    except SocketDirectoryError:
        return directory
    if _is_inside(directory, socket_dir):
        raise SocketDirectoryError(
            f"Token directory {directory} is inside the socket directory {socket_dir}."
        )
    return directory


def require_private_directory(directory: Path, variables: tuple[str, str]) -> None:
    problem = _privacy_problem(directory, variables)
    if problem is not None:
        raise problem


def ensure_private_directory(directory: Path, variables: tuple[str, str]) -> None:
    """Create a missing directory at mode 0700. An existing loose directory is refused."""
    if not directory.exists():
        _refuse_missing_user_runtime(directory)
        directory.mkdir(parents=True, mode=0o700)
        os.chmod(directory, 0o700)
    require_private_directory(directory, variables)


def ensure_private_socket_dir(socket_path: Path) -> None:
    _require_sun_path(socket_path)
    ensure_private_directory(socket_path.parent, SOCKET_VARIABLES)


def ensure_private_token_dir(directory: Path | None = None) -> Path:
    path = directory if directory is not None else configured_token_directory()
    ensure_private_directory(path, TOKEN_VARIABLES)
    return path


def prepare_listen_socket() -> Path:
    path = configured_inference_socket()
    ensure_private_socket_dir(path)
    replace_existing_socket(path)
    return path


def replace_existing_socket(path: Path) -> None:
    """Remove an existing socket only when this user owns it."""
    if not os.path.lexists(path):
        return
    info = path.lstat()
    if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid():
        path.unlink()
        return
    raise SocketDirectoryError(f"{path} is not a socket owned by the current user. Refusing to replace it.")


def prepare_token_directory() -> Path:
    return ensure_private_token_dir()


def _refuse_missing_user_runtime(directory: Path) -> None:
    """Do not create /run/user/<uid> when XDG_RUNTIME_DIR is unset and that directory is absent."""
    if sys.platform == "darwin":
        return
    if os.environ.get("XDG_RUNTIME_DIR", "").strip():
        return
    base = Path(f"/run/user/{os.getuid()}")
    if base.is_dir():
        return
    if directory != base and base not in directory.parents:
        return
    raise SocketDirectoryError(
        f"{base} does not exist and XDG_RUNTIME_DIR is unset. "
        "Set XDG_RUNTIME_DIR, or set ANTARES_SOCKET or ASTROLABE_INFERENCE_SOCKET "
        "and ANTARES_TOKEN_DIR or ASTROLABE_TOKEN_DIR."
    )


def _override_mismatch(server_var: str, runner_var: str) -> tuple[str, str] | None:
    server = os.environ.get(server_var, "").strip()
    runner = os.environ.get(runner_var, "").strip()
    if server and runner and Path(server).expanduser() != Path(runner).expanduser():
        return server, runner
    return None


def _chosen_path(server_var: str, runner_var: str, *, default: Path) -> Path:
    server = os.environ.get(server_var, "").strip()
    runner = os.environ.get(runner_var, "").strip()
    chosen = server or runner
    if chosen:
        return Path(chosen).expanduser()
    return default


def _require_sun_path(path: Path) -> None:
    encoded = os.fsencode(os.fspath(path))
    limit = sun_path_limit()
    if len(encoded) >= limit:
        raise SocketDirectoryError(
            f"Socket path {path} is {len(encoded)} bytes and exceeds the {limit}-byte sun_path limit."
        )


def _privacy_problem(directory: Path, variables: tuple[str, str]) -> SocketDirectoryError | None:
    info = directory.stat()
    if info.st_uid != os.getuid():
        reason = "not owned by the current user"
    elif info.st_mode & 0o077:
        reason = "group or world accessible"
    else:
        return None
    names = [name for name in variables if os.environ.get(name, "").strip()]
    unset = ""
    if len(names) == 1:
        unset = f" or unset {names[0]}"
    elif len(names) > 1:
        unset = f" or unset {names[0]} or {names[1]}"
    return SocketDirectoryError(f"{directory} is {reason}. chmod 700 {directory}{unset}.")


def _is_inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _override_is_set(variables: tuple[str, str]) -> bool:
    return any(os.environ.get(name, "").strip() for name in variables)


def _refuse_inside_engagements(path: Path, *, label: str, default: Path) -> None:
    """Refuse a configured runtime path that resolves inside the engagements root."""
    root = engagements_root()
    if not _is_inside(path, root):
        return
    raise SocketDirectoryError(
        f"{label} {path.resolve()} is inside the engagements directory {root.resolve()}. "
        f"Use {default} instead."
    )
