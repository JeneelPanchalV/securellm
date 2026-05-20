import inspect
import json
import os
import shutil
import threading
import time

import torch
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    GenerationConfig,
    TextIteratorStreamer,
)
from peft import PeftModel, LoraConfig

from config import BASE_MODEL, ADAPTER_PATH, SYSTEM_PROMPT
from cve_lookup import build_rag_context
from threat_intel import build_threat_intel_context

_tokenizer = None
_model = None


def _bnb_config() -> BitsAndBytesConfig:
    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
        llm_int8_enable_fp32_cpu_offload=True,
    )


def _load_adapter(base_model, adapter_path: str):
    """Load LoRA adapter, stripping config fields unknown to the installed PEFT version.

    The adapter was saved with peft 0.18.0; this env may have an older version.
    We temporarily write a cleaned adapter_config.json, load, then restore.
    """
    config_file = os.path.join(adapter_path, "adapter_config.json")
    backup_file = config_file + ".bak"

    with open(config_file, "r") as f:
        raw_cfg = json.load(f)

    valid_params = set(inspect.signature(LoraConfig.__init__).parameters.keys())
    valid_params.discard("self")

    unknown = set(raw_cfg.keys()) - valid_params
    if unknown:
        print(f"[SecureLLM] Adapter config compat: stripping {len(unknown)} unknown fields {unknown}")

    clean_cfg = {k: v for k, v in raw_cfg.items() if k in valid_params}

    shutil.copy2(config_file, backup_file)
    try:
        with open(config_file, "w") as f:
            json.dump(clean_cfg, f, indent=2)
        model = PeftModel.from_pretrained(base_model, adapter_path)
    finally:
        shutil.move(backup_file, config_file)

    return model


def load_model():
    global _tokenizer, _model

    print(f"[SecureLLM] Loading tokenizer from {BASE_MODEL}…")
    _tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    if _tokenizer.pad_token is None:
        _tokenizer.pad_token = _tokenizer.eos_token

    print(f"[SecureLLM] Loading base model in 4-bit NF4 (this may take 2–5 min)…")
    max_memory = {0: "5500MiB", "cpu": "24GiB"}
    bnb_cfg = _bnb_config()
    try:
        base = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            quantization_config=bnb_cfg,
            device_map="auto",
            max_memory=max_memory,
            torch_dtype=torch.float16,
            attn_implementation="flash_attention_2",
        )
        print("[SecureLLM] Flash Attention 2 enabled")
    except Exception:
        print("[SecureLLM] Flash Attention 2 unavailable, using SDPA")
        base = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            quantization_config=bnb_cfg,
            device_map="auto",
            max_memory=max_memory,
            torch_dtype=torch.float16,
            attn_implementation="sdpa",
        )

    print(f"[SecureLLM] Applying LoRA adapter from {ADAPTER_PATH}…")
    _model = _load_adapter(base, ADAPTER_PATH)
    _model.config.use_cache = True
    _model.eval()


    print("[SecureLLM] Model ready.")


def _build_prompt(message: str, history: list[dict]) -> str:
    # Fetch verified NVD facts for any CVE IDs in the message
    rag_context = build_rag_context(message)
    # Fetch verified threat actor / campaign facts
    threat_context = build_threat_intel_context(message)

    context_parts = [p for p in [threat_context, rag_context] if p]
    combined_context = "\n\n".join(context_parts)
    grounded_message = f"{combined_context}\n\n{message}" if combined_context else message

    if threat_context:
        print(f"[SecureLLM] RAG: injected threat intel facts into prompt")
    if rag_context:
        print(f"[SecureLLM] RAG: injected NVD facts into prompt")

    turns = [{"role": "system", "content": SYSTEM_PROMPT}]
    for turn in history:
        role = turn.get("role", "user")
        if role not in ("user", "assistant"):
            role = "user"
        turns.append({"role": role, "content": turn.get("content", "")})
    turns.append({"role": "user", "content": grounded_message})

    return _tokenizer.apply_chat_template(
        turns,
        tokenize=False,
        add_generation_prompt=True,
    )


def generate(
    message: str,
    history: list[dict],
    max_new_tokens: int,
    temperature: float,
    top_p: float,
) -> tuple[str, float]:
    """Return (response_text, latency_ms)."""
    prompt = _build_prompt(message, history)

    inputs = _tokenizer(prompt, return_tensors="pt").to(_model.device)
    input_len = inputs["input_ids"].shape[1]

    eot_id = _tokenizer.convert_tokens_to_ids("<|eot_id|>")
    stop_ids = [_tokenizer.eos_token_id]
    if eot_id and eot_id != _tokenizer.eos_token_id:
        stop_ids.append(eot_id)

    gen_cfg = GenerationConfig(
        max_new_tokens=max_new_tokens,
        temperature=max(temperature, 1e-4),
        top_p=top_p,
        do_sample=temperature > 0.01,
        eos_token_id=stop_ids,
        pad_token_id=_tokenizer.eos_token_id,
        repetition_penalty=1.1,
        use_cache=True,
        num_beams=1,
        early_stopping=False,
    )

    t0 = time.perf_counter()
    with torch.inference_mode():
        output_ids = _model.generate(**inputs, generation_config=gen_cfg)
    latency_ms = (time.perf_counter() - t0) * 1000

    new_ids = output_ids[0][input_len:]
    response = _tokenizer.decode(new_ids, skip_special_tokens=True).strip()

    return response, round(latency_ms, 1)


def generate_stream(
    message: str,
    history: list[dict],
    max_new_tokens: int,
    temperature: float,
    top_p: float,
):
    """Yield response tokens one at a time via TextIteratorStreamer."""
    prompt = _build_prompt(message, history)
    inputs = _tokenizer(prompt, return_tensors="pt").to(_model.device)

    streamer = TextIteratorStreamer(
        _tokenizer,
        skip_prompt=True,
        skip_special_tokens=True,
        timeout=60.0,
    )

    eot_id = _tokenizer.convert_tokens_to_ids("<|eot_id|>")
    stop_ids = [_tokenizer.eos_token_id]
    if eot_id and eot_id != _tokenizer.eos_token_id:
        stop_ids.append(eot_id)

    gen_cfg = GenerationConfig(
        max_new_tokens=max_new_tokens,
        temperature=max(temperature, 1e-4),
        top_p=top_p,
        do_sample=temperature > 0.01,
        eos_token_id=stop_ids,
        pad_token_id=_tokenizer.eos_token_id,
        repetition_penalty=1.1,
        use_cache=True,
        num_beams=1,
        early_stopping=False,
    )

    generate_kwargs = {**inputs, "generation_config": gen_cfg, "streamer": streamer}
    thread = threading.Thread(target=_model.generate, kwargs=generate_kwargs, daemon=True)
    thread.start()

    for token in streamer:
        if token:
            yield token

    thread.join()
