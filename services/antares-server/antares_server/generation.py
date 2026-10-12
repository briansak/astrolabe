"""Token-level streaming, frequency penalty, and stop criteria for raw completions."""

from __future__ import annotations

import threading
from typing import Any

import torch
from transformers import LogitsProcessor, StoppingCriteria, TextIteratorStreamer


DEFAULT_STOP_STRINGS = ("<|end_of_text|>", "<|start_of_role|>")
SERVED_MODEL_ID = "fdtn-ai/antares-1b"


class FrequencyPenaltyLogitsProcessor(LogitsProcessor):
    """Subtract penalty times how often each token has been generated.

    The count starts after the prompt. Counting the instruction as well suppresses
    the commands that prompt tells the model to use.
    """

    def __init__(self, penalty: float, prompt_length: int) -> None:
        self.penalty = float(penalty)
        self.prompt_length = prompt_length

    def __call__(self, input_ids: torch.LongTensor, scores: torch.FloatTensor) -> torch.FloatTensor:
        if self.penalty == 0.0:
            return scores
        for batch_index in range(input_ids.shape[0]):
            tokens = input_ids[batch_index, self.prompt_length :]
            if tokens.numel() == 0:
                continue
            unique, counts = torch.unique(tokens, return_counts=True)
            scores[batch_index, unique] -= self.penalty * counts.to(dtype=scores.dtype)
        return scores


class CancelCriteria(StoppingCriteria):
    """Stop on the next token after the HTTP client has gone away."""

    def __init__(self, cancel: threading.Event) -> None:
        self.cancel = cancel

    def __call__(self, input_ids: torch.LongTensor, scores: torch.FloatTensor, **kwargs: Any) -> torch.BoolTensor:
        if self.cancel.is_set():
            return torch.ones(input_ids.shape[0], dtype=torch.bool, device=input_ids.device)
        return torch.zeros(input_ids.shape[0], dtype=torch.bool, device=input_ids.device)


class StopTokenCriteria(StoppingCriteria):
    """Stop while generating, when the newest token is one of the stop ids."""

    def __init__(self, stop_ids: set[int]) -> None:
        self.stop_ids = set(stop_ids)

    def __call__(self, input_ids: torch.LongTensor, scores: torch.FloatTensor, **kwargs: Any) -> torch.BoolTensor:
        if not self.stop_ids or input_ids.shape[-1] < 1:
            return torch.zeros(input_ids.shape[0], dtype=torch.bool, device=input_ids.device)
        last = input_ids[:, -1]
        hit = torch.zeros(input_ids.shape[0], dtype=torch.bool, device=input_ids.device)
        for stop_id in self.stop_ids:
            hit |= last.eq(stop_id)
        return hit


class TokenIteratorStreamer(TextIteratorStreamer):
    """TextIteratorStreamer that queues every new token instead of waiting for a space."""

    def __init__(self, tokenizer: Any, on_token: Any = None, **kwargs: Any) -> None:
        super().__init__(tokenizer, **kwargs)
        self._on_token = on_token

    def put(self, value: torch.Tensor) -> None:
        if len(value.shape) > 1 and value.shape[0] > 1:
            raise ValueError("Token streaming supports batch size 1")
        if len(value.shape) > 1:
            value = value[0]
        if self.skip_prompt and self.next_tokens_are_prompt:
            self.next_tokens_are_prompt = False
            return
        token_ids = value.tolist()
        if not token_ids:
            return
        if self._on_token is not None:
            for _token_id in token_ids:
                self._on_token()
        text = self.tokenizer.decode(token_ids, **self.decode_kwargs)
        self.on_finalized_text(text)


def stop_token_ids(tokenizer: Any, stop_strings: list[str] | None) -> set[int]:
    """Map stop strings to single token ids. Multi-token strings are not a stop."""
    strings = list(DEFAULT_STOP_STRINGS if stop_strings is None else stop_strings)
    found: set[int] = set()
    for stop in strings:
        if not stop:
            continue
        encoded = tokenizer.encode(stop, add_special_tokens=False)
        if len(encoded) == 1:
            found.add(int(encoded[0]))
            continue
        token_id = tokenizer.convert_tokens_to_ids(stop)
        unk = getattr(tokenizer, "unk_token_id", None)
        if isinstance(token_id, int) and token_id != unk:
            found.add(token_id)
    return found


def count_prompt_tokens(tokenizer: Any, prompt: str) -> int:
    """Count tokens the completions route will feed the model. No chat template."""
    return len(tokenizer.encode(prompt, add_special_tokens=False))


def format_sse_text(text: str) -> str:
    import json

    payload = {"choices": [{"text": text}]}
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


SSE_DONE = "data: [DONE]\n\n"
