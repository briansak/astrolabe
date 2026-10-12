"""Local Antares-1B loader. Completions are raw prompts; the CLI applies the chat template."""

from __future__ import annotations

import logging
import os
import platform
import threading
from collections.abc import Iterator
from pathlib import Path
from queue import Queue
from typing import Any

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, LogitsProcessorList, StoppingCriteriaList

from antares_server.activity import GenerationActivity
from antares_server.generation import (
    DEFAULT_STOP_STRINGS,
    SERVED_MODEL_ID,
    CancelCriteria,
    FrequencyPenaltyLogitsProcessor,
    StopTokenCriteria,
    TokenIteratorStreamer,
    count_prompt_tokens,
    stop_token_ids,
)

logger = logging.getLogger(__name__)
from antares_server.weights import verify_weights


def _install_cache_compat() -> None:
    """Transformers 5.14 raises when a hybrid cache has no linear-attention layer yet.

    Granite's recurrent mask calls ``Cache.has_previous_state`` on the first
    forward. That method raises ``ValueError`` if the cache only holds attention
    layers, which aborts generation before the first token. No previous linear
    state is the right answer there.
    """
    from transformers.cache_utils import Cache

    if getattr(Cache.has_previous_state, "_astrolabe_compat", False):
        return
    original = Cache.has_previous_state

    def has_previous_state(self, layer_idx=None, state_idx=None):  # type: ignore[no-untyped-def]
        try:
            return original(self, layer_idx=layer_idx, state_idx=state_idx)
        except ValueError:
            return False

    has_previous_state._astrolabe_compat = True  # type: ignore[attr-defined]
    Cache.has_previous_state = has_previous_state  # type: ignore[method-assign]


def resolve_model_dir() -> Path:
    from astrolabe.user_config import model_path

    found = model_path()
    if found is None:
        raise FileNotFoundError(
            "Antares model path is not configured. Run astrolabe setup --model-path DIR, "
            "or set ANTARES_MODEL_PATH."
        )
    return found


class AntaresEngine:
    def __init__(self, model_dir: Path) -> None:
        self.model_dir = model_dir
        self.model_id = os.environ.get("ANTARES_SERVED_MODEL_ID", SERVED_MODEL_ID)
        self._lock = threading.RLock()
        self._tokenizer: Any | None = None
        self._model: Any | None = None
        self._device = self._select_device()
        self._dtype = self._select_dtype(self._device)
        self.weights_sha256: str | None = None
        self.activity = GenerationActivity()

    @staticmethod
    def _select_device() -> str:
        requested = os.environ.get("ANTARES_DEVICE", "auto")
        if requested != "auto":
            return requested
        if torch.backends.mps.is_available():
            return "mps"
        if torch.cuda.is_available():
            return "cuda"
        return "cpu"

    @staticmethod
    def _select_dtype(device: str) -> torch.dtype:
        if device == "mps":
            return torch.bfloat16
        if device == "cuda":
            return torch.float16
        return torch.float32

    def assert_offline(self) -> None:
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
        os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")

    def verify(self) -> str:
        self.weights_sha256 = verify_weights(self.model_dir)
        return self.weights_sha256

    def load(self) -> None:
        with self._lock:
            if self._model is not None:
                return
            self.assert_offline()
            if self.weights_sha256 is None:
                self.verify()
            self._tokenizer = AutoTokenizer.from_pretrained(
                str(self.model_dir),
                local_files_only=True,
            )
            self._model = AutoModelForCausalLM.from_pretrained(
                str(self.model_dir),
                local_files_only=True,
                torch_dtype=self._dtype,
            )
            self._model.to(self._device)
            self._model.eval()

    def unload(self) -> None:
        with self._lock:
            self._model = None
            self._tokenizer = None
            if self._device == "cuda":
                torch.cuda.empty_cache()
            elif self._device == "mps" and hasattr(torch, "mps"):
                torch.mps.empty_cache()

    def prompt_tokens(self, prompt: str) -> int:
        self.load()
        assert self._tokenizer is not None
        return count_prompt_tokens(self._tokenizer, prompt)

    def stream_completion(
        self,
        prompt: str,
        *,
        max_new_tokens: int,
        temperature: float,
        top_p: float,
        frequency_penalty: float,
        stop_strings: list[str] | None,
    ) -> Iterator[str]:
        """Yield decoded tokens as they are generated.

        Starlette resumes this generator on whichever threadpool thread is free.
        The generation lock has to be taken and released on one thread, so the
        model work runs there and this generator only reads a queue.
        """
        _install_cache_compat()
        cancel = threading.Event()
        chunks: Queue[object] = Queue()
        finished = object()
        self.activity.begin()

        def _locked_generate() -> None:
            try:
                with self._lock:
                    self.load()
                    assert self._model is not None and self._tokenizer is not None
                    stop_ids = stop_token_ids(self._tokenizer, stop_strings)
                    inputs = self._tokenizer(prompt, return_tensors="pt")
                    inputs = {key: value.to(self._device) for key, value in inputs.items()}
                    streamer = TokenIteratorStreamer(
                        self._tokenizer,
                        on_token=self.activity.token,
                        skip_prompt=True,
                        skip_special_tokens=False,
                    )
                    sample = temperature > 0.0
                    prompt_length = int(inputs["input_ids"].shape[-1])
                    generate_kwargs: dict[str, Any] = {
                        **inputs,
                        "max_new_tokens": max_new_tokens,
                        "do_sample": sample,
                        "pad_token_id": self._tokenizer.pad_token_id,
                        "logits_processor": LogitsProcessorList(
                            [
                                FrequencyPenaltyLogitsProcessor(
                                    frequency_penalty,
                                    prompt_length=prompt_length,
                                )
                            ]
                        ),
                        "stopping_criteria": StoppingCriteriaList(
                            [StopTokenCriteria(stop_ids), CancelCriteria(cancel)]
                        ),
                        "streamer": streamer,
                    }
                    if sample:
                        generate_kwargs["temperature"] = temperature
                        generate_kwargs["top_p"] = top_p
                    if stop_ids:
                        generate_kwargs["eos_token_id"] = sorted(stop_ids)
                    else:
                        # Explicit empty stop list: run until max_new_tokens. Used by the long-stream probe.
                        generate_kwargs["eos_token_id"] = []

                    error: list[BaseException] = []

                    def _generate() -> None:
                        try:
                            with torch.no_grad():
                                self._model.generate(**generate_kwargs)
                        except BaseException as exc:  # noqa: BLE001 — surfaced to the SSE consumer
                            error.append(exc)
                            logger.exception(
                                "generation failed after prompt_tokens=%s max_new_tokens=%s",
                                prompt_length,
                                max_new_tokens,
                            )
                            streamer.on_finalized_text("", stream_end=True)

                    worker = threading.Thread(target=_generate, name="antares-generate", daemon=True)
                    worker.start()
                    hidden = set(DEFAULT_STOP_STRINGS if stop_strings is None else stop_strings)
                    try:
                        for text in streamer:
                            if not text:
                                continue
                            for stop in hidden:
                                if stop:
                                    text = text.replace(stop, "")
                            if text:
                                chunks.put(text)
                    finally:
                        cancel.set()
                        worker.join()
                    if error:
                        raise error[0]
            except BaseException as exc:  # noqa: BLE001 — the request thread re-raises this
                chunks.put(exc)
            else:
                chunks.put(finished)

        threading.Thread(target=_locked_generate, name="antares-completion", daemon=True).start()
        try:
            while True:
                item = chunks.get()
                if item is finished:
                    return
                if isinstance(item, BaseException):
                    raise item
                yield str(item)
        finally:
            self.activity.end()
            cancel.set()

    def activity_snapshot(self) -> dict[str, object]:
        return self.activity.snapshot()

    def status(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "weights_path": str(self.model_dir.resolve()),
            "weights_sha256": self.weights_sha256,
            "device": self._device,
            "dtype": str(self._dtype).removeprefix("torch."),
            "loaded": self._model is not None,
            "platform": platform.platform(),
        }
