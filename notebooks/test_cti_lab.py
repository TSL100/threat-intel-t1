"""
CTI Lab - Environment verification script
Run: python test_cti_lab.py
Tests:
  1. stix2 installed and can build a STIX 2.1 bundle (Indicator + Malware + Relationship)
  2. Live MITRE ATT&CK Enterprise bundle fetch + parse (T1059, T1071 etc.)
  3. Optional: MISP connectivity check (set MISP_URL + MISP_KEY env vars)
Requires: stix2, taxii2-client, pycti, pandas, requests
"""
import os
import requests
import pandas as pd
from stix2 import Indicator, Malware, Relationship, Bundle

print("[1/3] STIX2 local bundle test...")
malware = Malware(
    name="Lab-Test-Ransomware",
    description="Lab sample for CTI practice",
    malware_types=["ransomware"],
    is_family=False,
)
indicator = Indicator(
    name="Malicious IP 203.0.113.45",
    description="Lab IOC",
    pattern="[ipv4-addr:value = '203.0.113.45']",
    pattern_type="stix",
    valid_from="2026-01-01T00:00:00Z",
    labels=["malicious-activity"],
)
rel = Relationship(
    relationship_type="indicates",
    source_ref=indicator.id,
    target_ref=malware.id,
)
bundle = Bundle(indicator, malware, rel)
print(f"  OK - Bundle {bundle.id} with {len(bundle.objects)} objects")
print(f"  Indicator pattern: {indicator.pattern}")

print("\n[2/3] MITRE ATT&CK Enterprise fetch test...")
# Official MITRE CTI repo (~15-20 MB). Cached locally after first run.
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE = "enterprise-attack.json"

if os.path.exists(CACHE):
    print(f"  Using cached {CACHE}")
    import json
    data = json.load(open(CACHE, encoding="utf-8"))
else:
    print(f"  Downloading {MITRE_URL} ...")
    r = requests.get(MITRE_URL, timeout=60)
    r.raise_for_status()
    open(CACHE, "wb").write(r.content)
    data = r.json()
    print(f"  Saved to {CACHE}")

# Parse techniques (T-codes -> procedure examples)
techniques = [
    o for o in data["objects"]
    if o.get("type") == "attack-pattern" and not o.get("revoked", False)
]
print(f"  OK - Loaded {len(techniques)} techniques")

# Show 5 examples as DataFrame (pandas check)
df = pd.DataFrame([
    {
        "id": next((ref["external_id"] for ref in t.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"), "?"),
        "name": t.get("name"),
    }
    for t in techniques[:5]
])
print(df.to_string(index=False))

# Targeted lookup: T1059 (Command and Scripting Interpreter) - classic example
# for t in techniques:
#     ext_ids = [ref.get("external_id") for ref in t.get("external_references", [])]
#     if "T1059" in ext_ids:
#         print(f"\n  Found T1059: {t['name']}")
#         print(f"  Description: {t.get('description','')[:200]}...")
#         break
target_ids = ["T1059", "T1071", "T1566"]
for t in techniques:
    ext_ids = [ref.get("external_id") for ref in t.get("external_references", [])]
    for tid in target_ids:
        if tid in ext_ids:
            print(f"\n  Found {tid}: {t['name']}")
            print(f"  Description: {t.get('description','')[:200]}...")

print("\n[3/3] MISP connectivity check (optional)...")
MISP_URL = os.getenv("MISP_URL", "http://localhost:8081")
MISP_KEY = os.getenv("MISP_KEY", "")
if not MISP_KEY:
    print(f"  SKIP - Set MISP_KEY env var to test. MISP UI: {MISP_URL}")
    print("  Get key: MISP UI > Administration > Users > Auth Key (or Event Actions > View API key)")
else:
    try:
        s = requests.Session()
        s.headers.update({"Authorization": MISP_KEY, "Accept": "application/json"})
        resp = s.get(f"{MISP_URL}/servers/getVersion", verify=False, timeout=10)
        print(f"  MISP version: {resp.text[:200]}")
    except Exception as e:
        print(f"  FAIL - {e}")

print("\nAll local checks done. Lab is working if [1] and [2] show OK.")
