"""
CTI Integration - Jupyter ready
File: notebooks/cti_misp_taxii_lab.py
Run as script:  python cti_misp_taxii_lab.py
Run in Jupyter: %run cti_misp_taxii_lab.py  OR copy cell-by-cell

Covers:
  [A] MISP REST via requests -> create Event + push STIX-mapped IOCs (ip, hash, domain)
  [B] TAXII 2.1 via taxii2client -> list MITRE collections + pull techniques (with mock fallback)
  [C] STIX 2.1 bundle build for the same IOCs

Needs in container (already installed): requests, stix2, taxii2-client, pandas
PyMISP NOT required - pure requests used for transparency.
"""
import os
import json
import urllib3
import requests
import pandas as pd
from stix2 import Indicator, Malware, Relationship, Bundle

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------------------------------------------
# 0. CONFIG - API key via env var (never hardcode in git)
# ------------------------------------------------------------------
# Inside Jupyter container, MISP hostname is "misp" (docker network cti-lab).
# Use https (MISP redirects http->https, which breaks POSTs).
# On Windows host python, use "http://localhost:8081".
# Logic: default to env, else auto-pick based on whether /home/jovyan exists.
def _default_misp_url():
    if os.path.exists("/home/jovyan"):
        return "https://misp"  # Jupyter -> MISP internal HTTPS (self-signed, VERIFY_SSL=False)
    return "http://localhost:8081"  # host python -> mapped port

MISP_URL = os.getenv("MISP_URL", _default_misp_url()).rstrip("/")
MISP_KEY = os.getenv("MISP_KEY", "")  # <-- set this, see step-by-step below
VERIFY_SSL = False  # lab uses self-signed cert on :8443; False is fine locally

print(f"MISP_URL  = {MISP_URL}")
print(f"MISP_KEY  = {'SET (' + str(len(MISP_KEY)) + ' chars)' if MISP_KEY else 'NOT SET - see instructions below'}")

HEADERS = {
    "Authorization": MISP_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json",
}

# Sample incident IOCs (TEST-NET / example hashes - safe for lab)
SAMPLE_IP = "203.0.113.45"
SAMPLE_DOMAIN = "evil-cti-example.com"
SAMPLE_HASH = "44d88612fea8a8f36de82e1278abb02f36f5ba38d69b3a3406f2323ea3a3c8b8"  # sha256 of empty-ish test
SAMPLE_TAG = 'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059"'

# ------------------------------------------------------------------
# 1. MISP API helpers (pure requests)
# ------------------------------------------------------------------
def misp_version():
    """GET /servers/getVersion - fastest auth check."""
    r = requests.get(f"{MISP_URL}/servers/getVersion",
                     headers={"Authorization": MISP_KEY, "Accept": "application/json"},
                     verify=VERIFY_SSL, timeout=15)
    r.raise_for_status()
    return r.json()


def misp_create_event(info="Lab Incident - Ransomware C2",
                      distribution=0, threat_level_id=2, analysis=0):
    """POST /events/add -> returns event dict with id + uuid."""
    payload = {"Event": {
        "info": info,
        "distribution": distribution,   # 0 = org only (safe default for lab)
        "threat_level_id": threat_level_id,  # 1 High, 2 Medium, 3 Low
        "analysis": analysis,           # 0 Initial, 1 Ongoing, 2 Completed
    }}
    r = requests.post(f"{MISP_URL}/events/add", headers=HEADERS,
                      data=json.dumps(payload), verify=VERIFY_SSL, timeout=15)
    r.raise_for_status()
    return r.json()["Event"]


def misp_add_attribute(event_id, category, attr_type, value,
                       to_ids=True, comment="", distribution=5):
    """POST /attributes/add/<event_id> -> push one IOC to an event.
    NOTE: event ID must be in the URL path (MISP throws 'No event ID set' otherwise).
    distribution 5 = inherit event. to_ids=True = usable for IDS export.
    """
    payload = {"Attribute": {
        "event_id": str(event_id),
        "category": category,   # e.g. "Network activity", "Payload delivery"
        "type": attr_type,      # e.g. "ip-dst", "domain", "sha256"
        "value": value,
        "to_ids": bool(to_ids),
        "distribution": distribution,
        "comment": comment,
    }}
    r = requests.post(f"{MISP_URL}/attributes/add/{event_id}", headers=HEADERS,
                      data=json.dumps(payload), verify=VERIFY_SSL, timeout=15)
    r.raise_for_status()
    return r.json()["Attribute"]


def misp_add_tag(event_uuid, tag_name):
    """POST /events/addTag -> attach MITRE technique tag to event."""
    payload = {"Event": {"uuid": event_uuid}, "Tag": {"name": tag_name}}
    # MISP accepts /events/addTag/:id with {"name": tag}
    # Try event-id route first (works on 2.4.x / 2.5.x)
    r = requests.post(f"{MISP_URL}/events/addTag/{event_uuid}",
                      headers=HEADERS, data=json.dumps({"name": tag_name}),
                      verify=VERIFY_SSL, timeout=15)
    r.raise_for_status()
    return r.json()


def demo_misp_push():
    """Full flow: version -> create event -> push 3 IOCs -> tag T1059."""
    if not MISP_KEY:
        print("\n[SKIP] MISP_KEY not set. Set it first (see instructions), then re-run.")
        return None
    print("\n[A1] MISP version check...")
    ver = misp_version()
    print(f"  OK - {ver}")

    print("\n[A2] Creating Event...")
    ev = misp_create_event()
    print(f"  Event id={ev['id']} uuid={ev['uuid']} info={ev['info']!r}")

    # STIX-mapped IOCs: pattern shown in comment for analyst traceability
    print("\n[A3] Pushing STIX-mapped IOCs...")
    stix_ip_pattern = f"[ipv4-addr:value = '{SAMPLE_IP}']"
    a1 = misp_add_attribute(ev["id"], "Network activity", "ip-dst", SAMPLE_IP,
                            comment=f"STIX pattern {stix_ip_pattern} | T1071 C2")
    print(f"  ip-dst      -> attribute id={a1['id']} uuid={a1['uuid']}")

    stix_hash_pattern = f"[file:hashes.'SHA-256' = '{SAMPLE_HASH}']"
    a2 = misp_add_attribute(ev["id"], "Payload delivery", "sha256", SAMPLE_HASH,
                            comment=f"STIX pattern {stix_hash_pattern} | ransomware payload")
    print(f"  sha256      -> attribute id={a2['id']}")

    a3 = misp_add_attribute(ev["id"], "Network activity", "domain", SAMPLE_DOMAIN,
                            comment="STIX pattern [domain-name:value = '...'] | T1071")
    print(f"  domain      -> attribute id={a3['id']}")

    print("\n[A4] Tagging with MITRE ATT&CK (best-effort, tag must exist)...")
    try:
        misp_add_tag(ev["uuid"], 'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059"')
        print("  Tagged T1059")
    except Exception as e:
        print(f"  Tag skipped (galaxy not loaded yet): {str(e)[:150]}")

    print(f"\n  DONE - View: {MISP_URL}/events/view/{ev['id']}")
    return ev

# ------------------------------------------------------------------
# 2. STIX 2.1 bundle for the same IOCs (what you'd export/share)
# ------------------------------------------------------------------
def demo_stix_bundle():
    print("\n[C] Building STIX 2.1 bundle...")
    mal = Malware(name="Lab-Test-Ransomware", malware_types=["ransomware"], is_family=False)
    ind_ip = Indicator(name=f"Malicious IP {SAMPLE_IP}",
                       pattern=f"[ipv4-addr:value = '{SAMPLE_IP}']",
                       pattern_type="stix", valid_from="2026-01-01T00:00:00Z",
                       labels=["malicious-activity"])
    ind_hash = Indicator(name="Ransomware payload hash",
                         pattern=f"[file:hashes.'SHA-256' = '{SAMPLE_HASH}']",
                         pattern_type="stix", valid_from="2026-01-01T00:00:00Z",
                         labels=["malicious-activity"])
    bundle = Bundle(ind_ip, ind_hash, mal,
                    Relationship(relationship_type="indicates",
                                 source_ref=ind_ip.id, target_ref=mal.id),
                    Relationship(relationship_type="indicates",
                                 source_ref=ind_hash.id, target_ref=mal.id))
    print(f"  Bundle {bundle.id} with {len(bundle.objects)} objects")
    open("cti-push-bundle.json", "w").write(bundle.serialize(pretty=True))
    print("  Saved -> cti-push-bundle.json (importable in MISP: Event > Import STIX)")
    return bundle

# ------------------------------------------------------------------
# 3. TAXII 2.1 bonus (correct import is taxii2client, no underscore)
# ------------------------------------------------------------------
def demo_taxii():
    print("\n[B] TAXII 2.1 - MITRE public collections...")
    try:
        from taxii2client.v20 import Server  # v2.0 API; for 2.1 use taxii2client.v21
        server = Server("https://cti-taxii.mitre.org/taxii/", verify=VERIFY_SSL)
        print(f"  Title: {server.title}")
        api_root = server.api_roots[0]
        print(f"  API root: {api_root.url} ({len(api_root.collections)} collections)")
        rows = [{"title": c.title, "id": c.id, "can_read": c.can_read} for c in api_root.collections]
        df = pd.DataFrame(rows)
        print(df.to_string(index=False))
        # Pull first readable collection, first page only (lab-friendly)
        coll = next(c for c in api_root.collections if c.can_read)
        print(f"\n  Pulling from: {coll.title} ...")
        envelope = coll.get_objects()
        print(f"  Got {len(envelope.get('objects', []))} STIX objects (page 1)")
        return df
    except Exception as e:
        print(f"  Live TAXII failed ({str(e)[:200]}), using MOCK fallback...")
        mock = pd.DataFrame([
            {"title": "Enterprise Attack (mock)", "id": "mock-enterprise", "can_read": True},
            {"title": "Mobile Attack (mock)", "id": "mock-mobile", "can_read": True},
        ])
        print(mock.to_string(index=False))
        print("  Mock envelope: 2 attack-pattern objects (T1059, T1071) - see STIX bundle above.")
        return mock


if __name__ == "__main__":
    demo_stix_bundle()   # works with no key
    demo_taxii()         # works with no key (live or mock)
    demo_misp_push()     # needs MISP_KEY
    print("\nDone. If [A] was SKIP, set MISP_KEY and re-run demo_misp_push().")
