from contextlib import asynccontextmanager
import json
import os

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from config import HOST, PORT, DEFAULT_MAX_NEW_TOKENS, DEFAULT_TEMPERATURE, DEFAULT_TOP_P
import model as llm
from cve_lookup import ground_response


# ── Startup / shutdown ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    llm.load_model()
    yield


app = FastAPI(title="SecureLLM API", lifespan=lifespan)

CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ── Schemas ───────────────────────────────────────────────────────────────────

class HistoryEntry(BaseModel):
    role: str
    content: str


class QueryRequest(BaseModel):
    message: str
    history: list[HistoryEntry] = Field(default_factory=list)
    max_new_tokens: int = DEFAULT_MAX_NEW_TOKENS
    temperature: float = DEFAULT_TEMPERATURE
    top_p: float = DEFAULT_TOP_P
    stream: bool = False


class QueryResponse(BaseModel):
    response: str
    latency_ms: float


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "model": "Meta-Llama-3.1-8B-Instruct + LoRA CVE adapter"}


@app.post("/query", response_model=QueryResponse)
async def query(req: QueryRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="message must not be empty")

    history = [{"role": h.role, "content": h.content} for h in req.history]

    response, latency_ms = llm.generate(
        message=req.message,
        history=history,
        max_new_tokens=req.max_new_tokens,
        temperature=req.temperature,
        top_p=req.top_p,
    )

    response = ground_response(req.message, response)
    return QueryResponse(response=response, latency_ms=latency_ms)


@app.post("/query/stream")
async def query_stream(req: QueryRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="message must not be empty")

    history = [{"role": h.role, "content": h.content} for h in req.history]

    def event_generator():
        # Yield the verified NVD header first so the client sees grounded facts
        # immediately, before model tokens begin arriving.
        header = ground_response(req.message, "").rstrip("\n")
        if header:
            yield f"data: {json.dumps({'token': header + chr(10)})}\n\n"

        try:
            for token in llm.generate_stream(
                message=req.message,
                history=history,
                max_new_tokens=req.max_new_tokens,
                temperature=req.temperature,
                top_p=req.top_p,
            ):
                yield f"data: {json.dumps({'token': token})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        finally:
            yield "data: [DONE]\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("main:app", host=HOST, port=PORT, log_level="info")
