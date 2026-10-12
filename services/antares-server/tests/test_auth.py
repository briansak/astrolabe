from pathlib import Path

from antares_server.auth import bearer_token, token_is_active


def test_bearer_parse() -> None:
    assert bearer_token("Bearer secret-value") == "secret-value"
    assert bearer_token("bearer secret-value") == "secret-value"
    assert bearer_token(None) is None
    assert bearer_token("Basic secret-value") is None


def test_only_a_live_run_token_matches(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANTARES_TOKEN_DIR", str(tmp_path))
    (tmp_path / "run").write_text("token-one\n", encoding="utf-8")
    assert token_is_active("token-one")
    assert not token_is_active("token-two")
    assert not token_is_active("")
