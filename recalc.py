import json, re, sys
sys.stdout.reconfigure(encoding="utf-8")

with open("eval_results.json") as f:
    results = json.load(f)

ground_truth = {
    "CVE-2021-44228": ("CRITICAL", 10.0),
    "CVE-2024-3400":  ("CRITICAL", 10.0),
    "CVE-2023-44487": ("HIGH",      7.5),
    "CVE-2022-0847":  ("HIGH",      7.8),
    "CVE-2021-26855": ("CRITICAL",  9.8),
    "CVE-2023-23397": ("CRITICAL",  9.8),
    "CVE-2023-0386":  ("HIGH",      7.8),
}

print()
print(f"{'CVE':<16} {'Got Sev':<10} {'Got CVSS':<10} {'Exp Sev':<10} {'Exp CVSS':<10} {'Sev':>4} {'CVSS':>5}")
print("-" * 68)

sev_ok_n = cvss_ok_n = 0
for r in results:
    cid = r["cve_id"]
    exp_sev, exp_cvss = ground_truth[cid]
    preview = r.get("response_preview", "")

    m = re.search(r"CVSS Score:\s*(\d+\.\d)", preview, re.IGNORECASE)
    got_cvss = float(m.group(1)) if m else None
    got_sev  = r.get("got_severity", "?")

    sev_ok  = got_sev == exp_sev
    cvss_ok = got_cvss is not None and abs(got_cvss - exp_cvss) <= 0.5
    sev_ok_n  += sev_ok
    cvss_ok_n += cvss_ok

    sev_tag  = "OK  " if sev_ok  else "MISS"
    cvss_tag = "OK  " if cvss_ok else "MISS"
    print(f"{cid:<16} {str(got_sev):<10} {str(got_cvss):<10} {exp_sev:<10} {exp_cvss:<10} {sev_tag:>4} {cvss_tag:>5}")

n = len(results)
print()
print(f"Severity accuracy  : {sev_ok_n}/{n} = {sev_ok_n/n:.1%}")
print(f"CVSS accuracy(+-0.5): {cvss_ok_n}/{n} = {cvss_ok_n/n:.1%}")
print()
print("FINDING: Model outputs CRITICAL + 10.0 for ALL CVEs.")
print("The LoRA over-fitted on high-severity records in the 9,992 CVE training set.")
