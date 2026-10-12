"""Sentinel and stream formatting. The completions route must not apply a chat template."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from antares_server.generation import (
    DEFAULT_STOP_STRINGS,
    count_prompt_tokens,
    format_sse_text,
    stop_token_ids,
)
from antares_server.inference import resolve_model_dir
from antares_server.main import completions

SENTINEL = "alpha beta gamma delta epsilon zeta eta theta"


def test_completions_route_does_not_apply_a_chat_template() -> None:
    source = inspect.getsource(completions)
    assert "apply_chat_template" not in source
    module = Path(__file__).resolve().parents[1] / "antares_server" / "main.py"
    assert "apply_chat_template" not in module.read_text(encoding="utf-8")


def test_sse_chunk_matches_the_cli_contract() -> None:
    chunk = format_sse_text("hello")
    assert chunk == 'data: {"choices": [{"text": "hello"}]}\n\n'


def _tokenizer():
    try:
        model_dir = resolve_model_dir()
    except FileNotFoundError as exc:
        pytest.skip(str(exc))
    if not (model_dir / "tokenizer.json").is_file():
        pytest.skip(f"tokenizer not staged at {model_dir}")
    from transformers import AutoTokenizer

    return AutoTokenizer.from_pretrained(str(model_dir), local_files_only=True)


def test_raw_prompt_is_nine_tokens_and_chat_template_is_forty_one() -> None:
    tokenizer = _tokenizer()
    assert count_prompt_tokens(tokenizer, SENTINEL) == 9
    templated = tokenizer.apply_chat_template(
        [{"role": "user", "content": SENTINEL}],
        tokenize=False,
        add_generation_prompt=True,
    )
    assert count_prompt_tokens(tokenizer, templated) == 41


def test_default_stop_strings_are_single_tokens() -> None:
    tokenizer = _tokenizer()
    ids = stop_token_ids(tokenizer, list(DEFAULT_STOP_STRINGS))
    assert len(ids) == 2
    assert stop_token_ids(tokenizer, []) == set()
