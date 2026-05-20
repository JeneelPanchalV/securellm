# SecureLLM Backend

FastAPI server serving the fine-tuned Llama-3.1-8B + LoRA CVE adapter.

## Setup

### 1. Install dependencies

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu121
pip install -r requirements.txt
```

### 2. Configure environment

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

| Variable | Description | Default |
|---|---|---|
| `ADAPTER_PATH` | Path to the LoRA adapter checkpoint directory | `./securellm-final` |
| `HUGGINGFACE_TOKEN` | HuggingFace token for gated model access | — |
| `CORS_ORIGINS` | Comma-separated list of allowed frontend origins | `*` (all) |

Set `ADAPTER_PATH` to wherever your trained adapter lives, for example:

```bash
# .env
ADAPTER_PATH=/path/to/your/securellm-final
HUGGINGFACE_TOKEN=hf_...
CORS_ORIGINS=*
```

> **Production note:** Change `CORS_ORIGINS` from `*` to your actual frontend URL before deploying. For example, if hosting the frontend on Hugging Face Spaces:
> ```
> CORS_ORIGINS=https://your-app.hf.space
> ```
> Multiple origins can be comma-separated:
> ```
> CORS_ORIGINS=https://your-app.hf.space,https://your-other-domain.com
> ```

Load the `.env` file before starting the server:

```bash
# macOS / Linux
export $(cat .env | xargs) && python main.py

# Windows PowerShell
Get-Content .env | ForEach-Object { $k,$v = $_ -split '=',2; [System.Environment]::SetEnvironmentVariable($k,$v) }
python main.py
```

### 3. Start the server

```bash
python main.py
```

Server starts on `http://0.0.0.0:8000`. Check `/health` to verify.

## API

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness check |
| `/query` | POST | Send a message, get a response |

### `/query` request body

```json
{
  "message": "What is CVE-2024-3400?",
  "history": [],
  "max_new_tokens": 384,
  "temperature": 0.7,
  "top_p": 0.9
}
```

---

## Known Limitations

### LoRA Over-fitting on Severity

The fine-tuned LoRA adapter exhibits over-fitting on the severity classification task — for novel/unseen CVEs, the base model defaults to predicting **CRITICAL** with **CVSS 10.0** regardless of actual severity.

**Root cause:** The training dataset of 9,992 NVD CVE records was severity-imbalanced (HIGH 45%, MEDIUM 44%, LOW 8%, CRITICAL ~0.5%). Despite this, the model failed to learn the actual severity distribution and instead memorized a single high-severity output pattern.

**Mitigation:** A dual-layer RAG grounding pipeline overrides the model's severity prediction with authoritative NVD values:

1. **Prompt-time injection** — Before generation, the live NVD API is queried for CVEs in the user's message and `[VERIFIED NVD FACTS]` blocks are injected into the system prompt with strict instructions that the model must not override these values.

2. **Post-generation grounding** — After the model responds, a markdown fact table with verified NVD severity/CVSS is prepended to the output, ensuring the displayed values are always NVD-authoritative.

**Impact:** For the 7-CVE benchmark suite (all publicly known CVEs in NVD), this mitigation achieves 100% severity accuracy. For novel or private CVEs not in NVD, severity predictions remain unreliable and should not be trusted without external validation.

### Future Improvements

1. **Rebalance training data** — Resample the dataset to achieve roughly equal severity distribution before the next training run.
2. **Add severity-aware loss** — Use class-weighted loss during fine-tuning to penalize over-prediction of dominant classes.
3. **Expand threat intel KB** — Currently covers 15 threat actor profiles; queries about other actors fall back to base model knowledge.
4. **Streaming + batch optimization** — Current latency at ~80s/query (384 tokens) could be reduced further with vLLM or TGI deployment.

### Performance Benchmark

| Metric | Result |
|---|---|
| Severity accuracy (with RAG) | 100% (7/7) |
| CVSS accuracy ±0.5 (with RAG) | 100% (7/7) |
| Severity accuracy (without RAG, novel CVE) | ~0% (always CRITICAL/10.0) |
| Avg latency (384 tokens) | ~80s |
| Throughput | ~4.1 tokens/sec |

### Lessons Learned

- Always validate trained models on out-of-distribution examples — benchmarks on in-distribution data hide failure modes
- RAG grounding can effectively mask fine-tuning weaknesses for known facts, but doesn't replace proper training
- Class imbalance must be addressed at the dataset level, not just relied upon during training
- Honest documentation of limitations is more valuable than hidden bugs
