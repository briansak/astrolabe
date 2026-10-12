"""Wheel and sdist contents. The server install test uses PyPI for third-party dependencies."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OMITTED = (
    "docs/HANDOFF.md",
    "/engagements/",
    "/var/",
    "/models/",
    "data/advisories/",
    "/build/",
    ".egg-info",
    "validation/",
)


def _wheel(outdir: Path) -> Path:
    subprocess.check_call(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(outdir), str(ROOT)],
    )
    found = list(outdir.glob("astrolabe-0.1.0-*.whl"))
    assert len(found) == 1
    return found[0]


def _sdist(outdir: Path) -> Path:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "build"], stdout=subprocess.DEVNULL)
    subprocess.check_call(
        [sys.executable, "-m", "build", "--sdist", "--outdir", str(outdir), str(ROOT)],
    )
    found = list(outdir.glob("astrolabe-0.1.0.tar.gz"))
    assert len(found) == 1
    return found[0]


def test_wheels_contain_the_apache_license(tmp_path: Path) -> None:
    out = tmp_path / "wheels"
    out.mkdir()
    subprocess.check_call(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(out), str(ROOT)],
    )
    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "-w",
            str(out),
            str(ROOT / "services" / "antares-server"),
        ],
    )
    wheels = sorted(out.glob("*.whl"))
    assert [path.name for path in wheels] == [
        "astrolabe-0.1.0-py3-none-any.whl",
        "astrolabe_antares_server-0.1.0-py3-none-any.whl",
    ]
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
        assert any(name.endswith("licenses/LICENSE") for name in names), wheel.name


def test_sdist_omits_private_trees(tmp_path: Path) -> None:
    archive = _sdist(tmp_path)
    with tarfile.open(archive) as tar:
        names = tar.getnames()
    joined = "\n".join(names)
    for fragment in OMITTED:
        assert fragment not in joined
    assert any(name.endswith("docs/install.md") for name in names)
    assert any(name.endswith("README.md") for name in names)
    assert any(name.endswith("astrolabe/data/cwe/cwe-dictionary.json") for name in names)
    assert any(name.endswith("astrolabe/data/cwe/CWE_NOTICE.txt") for name in names)


def test_installed_wheel_loads_cwe_data_and_home_defaults(tmp_path: Path) -> None:
    wheel = _wheel(tmp_path / "wheels")
    venv = tmp_path / "venv"
    home = tmp_path / "home"
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    subprocess.check_call([sys.executable, "-m", "venv", str(venv)])
    pip = venv / "bin" / "pip"
    python = venv / "bin" / "python"
    subprocess.check_call([str(pip), "install", "--no-deps", str(wheel)])
    script = tmp_path / "check_defaults.py"
    script.write_text(
        textwrap.dedent(
            """
            import os
            from pathlib import Path

            from astrolabe.cwe import cwe_name, displayed_mitigations
            from astrolabe.engagement import advisory_cache_dir, durable_audit_path, engagements_root

            home = Path(os.environ["HOME"]).resolve()
            assert os.getcwd() != str(home)
            name = cwe_name("CWE-89")
            assert name
            mitigations = displayed_mitigations("CWE-89")
            assert mitigations
            assert mitigations != ["No MITRE mitigation available for this weakness"]
            root = engagements_root()
            assert root == home / "Astrolabe" / "engagements"
            assert advisory_cache_dir() == home / "Astrolabe" / "advisories"
            assert durable_audit_path(root) == home / "Astrolabe" / "var" / "audit.jsonl"
            """
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["HOME"] = str(home)
    for key in list(env):
        if key.startswith(("ASTROLABE_", "ANTARES_")):
            del env[key]
    subprocess.check_call([str(python), str(script)], cwd=unrelated, env=env)


def test_both_wheels_install_and_the_stubbed_server_starts(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    subprocess.check_call([sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(dist), str(ROOT)])
    subprocess.check_call(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(dist), str(ROOT / "services" / "antares-server")],
    )
    venv = tmp_path / "venv"
    home = tmp_path / "home"
    runtime = Path(tempfile.mkdtemp(prefix="asrv", dir="/tmp"))
    tokens = Path(tempfile.mkdtemp(prefix="astok", dir="/tmp"))
    weights = tmp_path / "weights"
    weights.mkdir()
    subprocess.check_call([sys.executable, "-m", "venv", str(venv)])
    pip = venv / "bin" / "pip"
    python = venv / "bin" / "python"
    wheel = next(dist.glob("astrolabe-0.1.0-*.whl"))
    subprocess.check_call(
        [str(pip), "install", "--find-links", str(dist), f"{wheel}[inference]"],
    )
    socket_path = runtime / "inference.sock"
    token_dir = tokens
    launcher = tmp_path / "stub_server.py"
    launcher.write_text(
        textwrap.dedent(
            """
            import importlib

            inference = importlib.import_module("antares_server.inference")
            server = importlib.import_module("antares_server.main")

            class StubEngine:
                def __init__(self, model_dir):
                    self.model_dir = model_dir
                    self.model_id = "fdtn-ai/antares-1b"

                def verify(self):
                    return "stub"

                def load(self):
                    return None

                def unload(self):
                    return None

                def status(self):
                    return {"model": self.model_id}

            inference.AntaresEngine = StubEngine
            server.AntaresEngine = StubEngine
            server.main()
            """
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "ANTARES_MODEL_PATH": str(weights),
            "ANTARES_SOCKET": str(socket_path),
            "ASTROLABE_INFERENCE_SOCKET": str(socket_path),
            "ANTARES_TOKEN_DIR": str(token_dir),
            "ASTROLABE_TOKEN_DIR": str(token_dir),
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
        }
    )
    process = subprocess.Popen([str(python), str(launcher)], env=env)
    try:
        deadline = __import__("time").monotonic() + 180
        healthy = False
        while __import__("time").monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(f"server exited {process.returncode}")
            if socket_path.exists():
                probe = __import__("socket").socket(__import__("socket").AF_UNIX, __import__("socket").SOCK_STREAM)
                probe.settimeout(2)
                try:
                    probe.connect(str(socket_path))
                    probe.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    raw = probe.recv(65536)
                except OSError:
                    raw = b""
                finally:
                    probe.close()
                if b'"status":"ok"' in raw.replace(b" ", b"") or b'"status": "ok"' in raw:
                    healthy = True
                    break
            __import__("time").sleep(0.5)
        assert healthy
    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
        shutil.rmtree(runtime, ignore_errors=True)
        shutil.rmtree(tokens, ignore_errors=True)
