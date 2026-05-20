"""
NVD CVE lookup — fetches verified facts to ground model responses.
"""

import re
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_cache: dict[str, dict] = {}


def extract_cve_ids(text: str) -> list[str]:
    return list(dict.fromkeys(
        m.upper() for m in re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
    ))


def fetch_cve(cve_id: str) -> dict | None:
    cve_id = cve_id.upper()
    if cve_id in _cache:
        return _cache[cve_id]

    try:
        r = requests.get(NVD_API, params={"cveId": cve_id}, timeout=8)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            _cache[cve_id] = None
            return None

        cve = vulns[0]["cve"]
        metrics = cve.get("metrics", {})

        severity = cvss_score = cvss_vector = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                d = m.get("cvssData", {})
                cvss_score  = d.get("baseScore")
                cvss_vector = d.get("vectorString", "")
                severity    = (m.get("baseSeverity") or d.get("baseSeverity", "")).upper()
                break

        descriptions = cve.get("descriptions", [])
        description  = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

        published = (cve.get("published") or "")[:10]

        result = {
            "id":          cve_id,
            "severity":    severity,
            "cvss_score":  cvss_score,
            "cvss_vector": cvss_vector,
            "description": description[:600],
            "published":   published,
        }
        _cache[cve_id] = result
        return result

    except Exception:
        _cache[cve_id] = None
        return None


def build_rag_context(message: str) -> str:
    """Return a factual context block for any CVE IDs found in the message."""
    cve_ids = extract_cve_ids(message)
    if not cve_ids:
        return ""

    blocks = []
    for cve_id in cve_ids[:3]:
        data = fetch_cve(cve_id)
        if not data:
            continue
        blocks.append(
            f"[VERIFIED NVD FACTS — {data['id']}]\n"
            f"Severity : {data['severity']}\n"
            f"CVSS     : {data['cvss_score']} ({data['cvss_vector']})\n"
            f"Published: {data['published']}\n"
            f"Summary  : {data['description']}\n"
            f"[END VERIFIED FACTS]"
        )

    return "\n\n".join(blocks)


def ground_response(query: str, response: str) -> str:
    """Prepend a verified NVD fact block to the model response for any CVEs in the query."""
    cve_ids = extract_cve_ids(query)
    if not cve_ids:
        return response

    headers = []
    for cve_id in cve_ids[:3]:
        data = fetch_cve(cve_id)
        if not data:
            continue
        sev = data["severity"] or "UNKNOWN"
        score = data["cvss_score"] or "N/A"
        vec = data["cvss_vector"] or ""
        pub = data["published"] or "N/A"

        headers.append(
            f"## {cve_id} — NVD Verified\n\n"
            f"| Field | Value |\n"
            f"|---|---|\n"
            f"| **Severity** | [{sev}] |\n"
            f"| **CVSS Score** | **{score}** ({vec}) |\n"
            f"| **Published** | {pub} |\n\n"
            f"---\n"
        )

    if not headers:
        return response

    return "\n".join(headers) + "\n" + response
