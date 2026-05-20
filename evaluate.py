# -*- coding: utf-8 -*-
"""
SecureLLM Accuracy Evaluator
Queries the live backend on known CVEs and scores responses
against NVD ground truth.
"""

import re
import json
import time
import sys
import requests

# Force UTF-8 output on Windows
sys.stdout.reconfigure(encoding="utf-8")

BACKEND_URL = "http://localhost:8000/query"

# Ground truth from NVD
TEST_CASES = [
    {"id": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0, "keywords": ["log4j", "jndi", "log4shell"]},
    {"id": "CVE-2024-3400",  "severity": "CRITICAL", "cvss": 10.0, "keywords": ["pan-os", "palo alto", "globalprotect"]},
    {"id": "CVE-2023-44487", "severity": "HIGH",     "cvss": 7.5,  "keywords": ["http/2", "rapid reset", "rst_stream"]},
    {"id": "CVE-2022-0847",  "severity": "HIGH",     "cvss": 7.8,  "keywords": ["dirty pipe", "pipe", "overlayfs", "log4j"]},
    {"id": "CVE-2021-26855", "severity": "CRITICAL", "cvss": 9.1,  "keywords": ["exchange", "proxylogon", "ssrf"]},
    {"id": "CVE-2023-23397", "severity": "CRITICAL", "cvss": 9.8,  "keywords": ["outlook", "ntlm", "calendar"]},
    {"id": "CVE-2023-0386",  "severity": "HIGH",     "cvss": 7.8,  "keywords": ["overlayfs", "overlay", "privilege"]},
]


def query_model(cve_id: str) -> dict:
    payload = {
        "message": f"What is {cve_id}? Include severity, CVSS score, affected products, and remediation.",
        "history": [],
        "max_new_tokens": 400,
        "temperature": 0.1,
        "top_p": 0.9,
        "stream": False,
    }
    r = requests.post(BACKEND_URL, json=payload, timeout=180)
    r.raise_for_status()
    return r.json()


def extract_severity(text: str):
    # Prefer bracketed form [HIGH] etc — find first occurrence by position
    m = re.search(r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]', text, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    # Fallback: find first plain word occurrence
    for match in re.finditer(r'\b(CRITICAL|HIGH|MEDIUM|LOW)\b', text, re.IGNORECASE):
        return match.group(1).upper()
    return None


def extract_cvss(text: str):
    # Prefer explicit "CVSS Score: X.X" — avoids matching version "3.1" in vectors
    patterns = [
        r'CVSS\s*Score[:\s]+\**(\d+\.\d)\**',
        r'\|\s*\*\*CVSS Score\*\*\s*\|\s*\**(\d+\.\d)',
        r'\*\*(\d+\.\d)\*\*\s*\(',           # **10.0** (CVSS:...
        r'(\d+\.\d)\s*/\s*10',
        r'(?:score|rating)\s*(?:of\s*|is\s*)?(\d+\.\d)',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            val = float(m.group(1))
            if 0.0 <= val <= 10.0:
                return val
    return None


def score_response(response: str, gt: dict) -> dict:
    sev  = extract_severity(response)
    cvss = extract_cvss(response)
    diff = round(abs(cvss - gt["cvss"]), 1) if cvss is not None else None
    kw_hit = any(k.lower() in response.lower() for k in gt["keywords"])

    return {
        "cve_id":           gt["id"],
        "severity_correct": sev == gt["severity"],
        "got_severity":     sev,
        "exp_severity":     gt["severity"],
        "cvss_correct":     diff is not None and diff <= 0.5,
        "got_cvss":         cvss,
        "exp_cvss":         gt["cvss"],
        "cvss_diff":        diff,
        "cve_mentioned":    gt["id"].upper() in response.upper(),
        "keyword_hit":      kw_hit,
        "has_structure":    any(k in response.lower() for k in
                                ["severity", "cvss", "affected", "remediat", "patch", "fix"]),
        "response_preview": response[:200].replace("\n", " "),
    }


def run():
    print()
    print("=" * 62)
    print("   SecureLLM Accuracy Evaluation")
    print(f"   Backend : {BACKEND_URL}")
    print(f"   CVEs    : {len(TEST_CASES)}")
    print("=" * 62)
    print()

    results = []

    for i, tc in enumerate(TEST_CASES, 1):
        cid = tc["id"]
        print(f"  [{i}/{len(TEST_CASES)}] {cid} ... ", end="", flush=True)
        t0 = time.time()
        try:
            resp    = query_model(cid)
            elapsed = round(time.time() - t0, 1)
            text    = resp.get("response", "")
            s       = score_response(text, tc)
            s["latency_s"] = elapsed
            results.append(s)

            sev_ok  = "OK" if s["severity_correct"] else "MISS"
            cvss_ok = "OK" if s["cvss_correct"]     else "MISS"
            print(f"done ({elapsed}s) | "
                  f"Severity [{sev_ok}] {str(s['got_severity'] or '?'):<8} | "
                  f"CVSS [{cvss_ok}] {str(s['got_cvss'] or '?')}")

        except Exception as e:
            elapsed = round(time.time() - t0, 1)
            print(f"FAILED ({elapsed}s): {e}")
            results.append({"cve_id": cid, "error": str(e), "latency_s": elapsed})

        if i < len(TEST_CASES):
            time.sleep(1)

    # ── Summary ─────────────────────────────────────────────────────
    valid = [r for r in results if "error" not in r]
    n     = len(valid)

    print()
    print("=" * 62)
    print("   RESULTS")
    print("=" * 62)
    print(f"   CVEs tested            : {len(TEST_CASES)}")
    print(f"   Successful queries     : {n}")
    print()

    if n == 0:
        print("   No valid results -- is the backend running?")
        return

    sev_n    = sum(r["severity_correct"] for r in valid)
    cvss_n   = sum(r["cvss_correct"]     for r in valid)
    cve_n    = sum(r["cve_mentioned"]    for r in valid)
    kw_n     = sum(r["keyword_hit"]      for r in valid)
    str_n    = sum(r["has_structure"]    for r in valid)
    avg_lat  = sum(r["latency_s"]        for r in valid) / n
    overall  = (sev_n + cvss_n + cve_n + str_n) / (4 * n)

    print(f"   Severity accuracy      : {sev_n/n:>6.1%}   ({sev_n}/{n})")
    print(f"   CVSS accuracy  (+-0.5) : {cvss_n/n:>6.1%}   ({cvss_n}/{n})")
    print(f"   CVE ID mentioned       : {cve_n/n:>6.1%}   ({cve_n}/{n})")
    print(f"   Keyword coverage       : {kw_n/n:>6.1%}   ({kw_n}/{n})")
    print(f"   Structured output      : {str_n/n:>6.1%}   ({str_n}/{n})")
    print(f"   Avg latency            : {avg_lat:>5.1f}s")
    print()
    print(f"   -- OVERALL SCORE ------: {overall:>6.1%}")
    print("=" * 62)

    out = "eval_results.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n   Full results saved -> {out}\n")


if __name__ == "__main__":
    run()
