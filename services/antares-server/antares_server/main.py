"""Host inference API for the official Antares CLI."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from antares_server.activity import activity_response
from antares_server.auth import bearer_token, token_directory, token_is_active
from antares_server.generation import SSE_DONE, format_sse_text
from antares_server.inference import AntaresEngine, resolve_model_dir

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class CompletionRequest(BaseModel):
    model: str = ""
    prompt: str
    max_tokens: int = Field(default=1024, ge=1)
    temperature: float = 0.3
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    stream: bool = True
    stop: list[str] | None = None


def _engine() -> AntaresEngine:
    engine = app.state.engine
    if not isinstance(engine, AntaresEngine):
        raise HTTPException(status_code=503, detail="Antares engine is not loaded")
    return engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    model_dir = resolve_model_dir()
    engine = AntaresEngine(model_dir)
    logger.info("Verifying Antares weights at %s", model_dir)
    engine.verify()
    engine.load()
    app.state.engine = engine
    socket_path = os.environ.get("ANTARES_SOCKET", "").strip()
    if socket_path:
        _chmod_socket(Path(socket_path))
    logger.info("Antares ready: %s", engine.status())
    yield
    engine.unload()


app = FastAPI(
    title="Astrolabe Antares inference",
    version="0.1.0",
    description="Raw streaming completions for the official Antares CLI. No chat template on this route.",
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict[str, object]:
    engine = _engine()
    return {"status": "ok", **engine.status()}


@app.get("/v1/activity")
def activity() -> dict[str, object]:
    return activity_response(_engine())


def _require_run_token(authorization: str | None) -> None:
    if token_directory() is None:
        raise HTTPException(status_code=401, detail="Bearer token required")
    presented = bearer_token(authorization)
    if presented is None or not token_is_active(presented):
        raise HTTPException(status_code=401, detail="Bearer token rejected")


@app.post("/v1/completions")
def completions(
    request: CompletionRequest,
    authorization: str | None = Header(default=None),
) -> StreamingResponse:
    _require_run_token(authorization)
    engine = _engine()
    if request.model and request.model != engine.model_id:
        raise HTTPException(
            status_code=400,
            detail=f"Served model is {engine.model_id}",
        )
    if not request.stream:
        raise HTTPException(status_code=400, detail="This route only streams token SSE")

    def events() -> Iterator[str]:
        try:
            for text in engine.stream_completion(
                request.prompt,
                max_new_tokens=request.max_tokens,
                temperature=request.temperature,
                top_p=request.top_p,
                frequency_penalty=request.frequency_penalty,
                stop_strings=request.stop,
            ):
                yield format_sse_text(text)
        except Exception as exc:  # noqa: BLE001 — the CLI treats an SSE error object as a stream failure
            import json

            logger.exception("completion stream failed")
            message = str(exc)
            yield f"data: {json.dumps({'error': {'message': message}})}\n\n"
            return
        yield SSE_DONE

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _chmod_socket(path: Path) -> None:
    try:
        path.chmod(0o666)
    except OSError:
        logger.warning("Could not widen permissions on %s", path)


def main() -> None:
    listen = os.environ.get("ANTARES_LISTEN", "unix").strip().lower()
    if listen == "tcp":
        host = os.environ.get("ANTARES_BIND_HOST", "127.0.0.1")
        if host not in LOOPBACK_HOSTS:
            raise SystemExit(f"TCP listen is loopback-only, refused host {host}")
        port = int(os.environ.get("ANTARES_PORT", "8090"))
        uvicorn.run(app, host=host, port=port, reload=False, timeout_keep_alive=1200)
        return

    from astrolabe.inference_socket import SocketDirectoryError, prepare_listen_socket, prepare_token_directory

    try:
        socket_path = prepare_listen_socket()
        token_dir = prepare_token_directory()
    except SocketDirectoryError as exc:
        raise SystemExit(str(exc)) from exc
    os.environ["ANTARES_SOCKET"] = str(socket_path)
    os.environ["ANTARES_TOKEN_DIR"] = str(token_dir)
    config = uvicorn.Config(app, uds=str(socket_path), reload=False, timeout_keep_alive=1200)
    server = uvicorn.Server(config)

    def _widen() -> None:
        import time

        # Model load can take longer than the socket bind, so keep trying.
        for _ in range(600):
            if socket_path.exists():
                _chmod_socket(socket_path)
                return
            time.sleep(0.1)

    import threading

    threading.Thread(target=_widen, name="antares-socket-mode", daemon=True).start()
    server.run()


if __name__ == "__main__":
    main()
