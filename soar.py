#!/usr/bin/env python3
"""
soar.py - Small SOAR engine for CTI Dashboard (updated)

Changes / improvements:
- cloudflare_block_ip -> cloudflare_block (auto-detects IP vs hostname and uses correct Cloudflare firewall API payload)
- added verify_cloudflare_credentials() to test the API token & zone
- more robust mongo_client derivation and ensure_collections()
- better logging of adapter errors and sanitized audit insertion fallback
- unchanged dry-run default behavior
"""

import os
import time
import json
import traceback
from datetime import datetime, timezone

import requests

# Import collections from db.py (ioc_feed, enrichment_cache, alerts, ensure_indexes)
# We will derive mongo_client from one of the collections instead of relying on db.py exporting it.
from db import ioc_feed, enrichment_cache, alerts, ensure_indexes

# Run ensure_indexes if available (non-fatal)
try:
    ensure_indexes()
except Exception:
    pass

# Load config
_cfg_path = os.path.join(os.path.dirname(__file__), "config.json")
if not os.path.exists(_cfg_path):
    raise SystemExit("Missing config.json — create it or copy config.example.json and set necessary keys.")
with open(_cfg_path, "r", encoding="utf-8") as fh:
    cfg = json.load(fh)

# Try to derive a MongoClient from an existing collection (ioc_feed)
mongo_client = None
try:
    mongo_client = ioc_feed.database.client
except Exception:
    mongo_client = None

# Lazy-create DB handles if client available
db = None
automation_logs = None
playbooks_col = None

def ensure_collections():
    """
    Ensure automation_logs and playbooks_col exist, creating them lazily if needed.
    Returns (automation_logs, playbooks_col). Throws useful error if no mongo_client.
    """
    global automation_logs, playbooks_col, db, mongo_client
    if automation_logs is None or playbooks_col is None:
        if not mongo_client:
            raise RuntimeError("No mongo_client available. Ensure db.py exposes collections or ioc_feed is a valid collection.")
        db = mongo_client[cfg.get("DB_NAME")]
        automation_logs = db.get_collection("automation_logs")
        playbooks_col = db.get_collection("playbooks")
    return automation_logs, playbooks_col

# Helpers
def now_utc():
    return datetime.now(timezone.utc)

def _safe_insert_log(col, doc):
    """
    Insert doc into collection, converting datetimes to ISO strings and ObjectIds to str when necessary.
    This avoids JSON serialization issues later.
    """
    try:
        # small recursive sanitizer
        def _sanitize(v):
            try:
                from bson.objectid import ObjectId
            except Exception:
                ObjectId = None
            if v is None or isinstance(v, (bool, int, float, str)):
                return v
            if ObjectId and isinstance(v, ObjectId):
                return str(v)
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, dict):
                return {k: _sanitize(val) for k, val in v.items()}
            if isinstance(v, (list, tuple)):
                return [_sanitize(x) for x in v]
            try:
                return str(v)
            except Exception:
                return None
        safe_doc = _sanitize(doc)
        col.insert_one(safe_doc)
    except Exception as e:
        # fallback to printing if insert fails
        print("AUTOMATION LOG INSERT FAILED:", e)
        print("DOC (sanitized-ish):", doc)

def log_action(playbook_name, action, indicator, success, dry_run, details=None):
    """
    Insert an audit row into automation_logs. If automation_logs not available, print to console.
    """
    details = details or {}
    doc = {
        "playbook": playbook_name,
        "action": action,
        "indicator": indicator,
        "success": bool(success),
        "dry_run": bool(dry_run),
        "details": details,
        "timestamp": now_utc()
    }
    try:
        al, _ = ensure_collections()
        _safe_insert_log(al, doc)
    except Exception:
        # fallback: print to stdout for debugging
        print("AUTOMATION LOG (fallback):", doc)
    return doc

# ---------- Adapters ----------
def is_ip_address(addr):
    try:
        import ipaddress
        ipaddress.ip_address(addr)
        return True
    except Exception:
        return False

def verify_cloudflare_credentials(api_token=None, zone_id=None, timeout=10):
    """
    Verify Cloudflare API token and (optionally) zone_id by calling /zones and checking access.
    Returns dict {ok: bool, reason: str, zones: [...]}.
    """
    api_token = api_token or cfg.get("CLOUDFLARE_API_TOKEN")
    zone_id = zone_id or cfg.get("CLOUDFLARE_ZONE_ID")
    if not api_token:
        return {"ok": False, "reason": "no api token configured"}

    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        r = requests.get("https://api.cloudflare.com/client/v4/zones", headers=headers, timeout=timeout)
        r.raise_for_status()
        j = r.json()
        zones = j.get("result", [])
        if zone_id:
            found = [z for z in zones if z.get("id") == zone_id or z.get("name") == zone_id]
            if not found:
                return {"ok": False, "reason": f"zone_id {zone_id} not found in token's accessible zones", "zones_count": len(zones)}
        return {"ok": True, "zones_count": len(zones)}
    except Exception as e:
        return {"ok": False, "reason": str(e)}

def cloudflare_block(indicator, zone_id=None, api_token=None, dry_run=True):
    """
    Generic Cloudflare block adapter. Detects if `indicator` is IP or hostname.
    Uses firewall access rules API to create a block rule.

    Returns dict result or raises.
    """
    api_token = api_token or cfg.get("CLOUDFLARE_API_TOKEN")
    zone_id = zone_id or cfg.get("CLOUDFLARE_ZONE_ID")
    if not api_token or not zone_id:
        raise RuntimeError("Cloudflare credentials/zone not configured in config.json")

    target_type = "ip" if is_ip_address(indicator) else "hostname"
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

    payload = {
        "mode": "block",
        "configuration": {"target": target_type, "value": indicator},
        "notes": f"Blocked by CTI Dashboard (automated) at {now_utc().isoformat()}"
    }

    # dry-run: return payload for inspection
    if dry_run:
        return {"dry_run": True, "payload": payload, "zone_id": zone_id}

    # attempt create
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    r.raise_for_status()
    return r.json()

def iptables_block_ip_local(ip, dry_run=True):
    """
    Add an iptables drop rule for the IP. Requires running as root.
    Safety: refuse private/reserved IPs.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_reserved:
            raise RuntimeError("Refusing to block private/reserved IP for safety")
    except Exception as e:
        raise RuntimeError(f"Invalid/safe-check failed for IP {ip}: {e}")

    if dry_run:
        return {"dry_run": True, "cmd": f"iptables -I INPUT -s {ip} -j DROP"}

    import subprocess
    cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}

def thehive_create_case(title, summary, tags=None, thehive_url=None, api_key=None, dry_run=True):
    thehive_url = thehive_url or cfg.get("THEHIVE_URL")
    api_key = api_key or cfg.get("THEHIVE_API_KEY")
    if not thehive_url or not api_key:
        raise RuntimeError("TheHive not configured in config.json")

    payload = {
        "title": title,
        "description": summary,
        "tags": tags or [],
        "severity": 2
    }
    if dry_run:
        return {"dry_run": True, "payload": payload}

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    r = requests.post(f"{thehive_url}/api/case", headers=headers, json=payload, timeout=30)
    r.raise_for_status()
    return r.json()

# ---------- Executor ----------
def execute_playbook(playbook, indicator, dry_run=True):
    """
    Execute a playbook dict against an indicator (string).
    """
    name = playbook.get("name", "unnamed-playbook")
    results = []

    # Allowlist check
    allow = playbook.get("allowlist", []) or []
    for a in allow:
        if indicator.startswith(a):
            details = {"reason": "indicator in allowlist", "allow": a}
            log_action(name, "skip", indicator, True, dry_run, details)
            return {"skipped": True, "reason": details}

    steps = playbook.get("steps", []) or []
    for step in steps:
        stype = step.get("type")
        params = step.get("params", {}) or {}
        try:
            if stype in ("cloudflare_block", "cloudflare_block_ip", "cloudflare_block_hostname", "cloudflare_block_any"):
                # unified cloudflare adapter
                res = cloudflare_block(indicator, zone_id=params.get("zone_id"), api_token=params.get("api_token"), dry_run=dry_run)
                log_action(name, "cloudflare_block", indicator, True, dry_run, {"result": res})
                results.append({"step": stype, "result": res})
            elif stype == "iptables_block_local":
                res = iptables_block_ip_local(indicator, dry_run=dry_run)
                log_action(name, "iptables_block_local", indicator, True, dry_run, {"result": res})
                results.append({"step": stype, "result": res})
            elif stype == "thehive_create_case":
                title = params.get("title") or f"Automated case for {indicator}"
                summary = params.get("summary") or f"Auto-generated case for indicator {indicator}"
                tags = params.get("tags", [])
                res = thehive_create_case(title, summary, tags=tags, dry_run=dry_run)
                log_action(name, "thehive_create_case", indicator, True, dry_run, {"result": res})
                results.append({"step": stype, "result": res})
            else:
                details = {"reason": "unknown step type", "step": stype}
                log_action(name, "unknown_step", indicator, False, dry_run, details)
                results.append({"step": stype, "error": "unknown step"})
        except Exception as e:
            tb = traceback.format_exc()
            # log error and continue to next step
            log_action(name, stype or "unknown", indicator, False, dry_run, {"error": str(e), "trace": tb})
            results.append({"step": stype, "error": str(e)})
    return {"playbook": name, "indicator": indicator, "dry_run": dry_run, "results": results}

# ---------- Poller ----------
def poll_alerts_and_run(playbook_name, poll_interval=30, dry_run=True, score_threshold=None):
    """
    Poll alerts collection for new/unhandled alerts and run playbook on matching ones.
    Marks alerts.handled_by_soar = True when processed and stores soar_result.
    """
    print("SOAR poller starting for playbook:", playbook_name)
    while True:
        try:
            # ensure playbooks collection available
            _, pcol = ensure_collections()
            playbook = pcol.find_one({"name": playbook_name})
            if not playbook:
                print("Playbook not found:", playbook_name)
                time.sleep(poll_interval)
                continue

            query = {"handled_by_soar": {"$ne": True}}
            if score_threshold:
                query["alert_score"] = {"$gte": score_threshold}
            docs = list(alerts.find(query).sort("created_at", 1).limit(100))
            for a in docs:
                indicator = a.get("indicator")
                if not indicator:
                    alerts.update_one({"_id": a["_id"]}, {"$set": {"handled_by_soar": True, "soar_note": "no indicator"}})
                    continue
                res = execute_playbook(playbook, indicator, dry_run=dry_run)
                alerts.update_one({"_id": a["_id"]}, {"$set": {"handled_by_soar": True, "soar_result": res, "soar_run_at": now_utc()}})
            time.sleep(poll_interval)
        except KeyboardInterrupt:
            print("SOAR poller interrupted by user")
            break
        except Exception:
            traceback.print_exc()
            time.sleep(poll_interval)

# ---------- Helpers: sample playbook ----------
def ensure_sample_playbook():
    """
    Insert a conservative sample playbook (dry-run friendly) if one doesn't already exist.
    """
    try:
        _, pcol = ensure_collections()
        sample = {
            "name": "block_ip_cloudflare_and_case",
            "description": "Block IP/hostname in Cloudflare zone and create TheHive case",
            "steps": [
                {"type": "cloudflare_block", "params": {}},
                {"type": "thehive_create_case", "params": {"title": "Auto case", "summary": "Blocked by automated playbook"}}
            ],
            "allowlist": ["10.", "192.168.", "127.0.0.1"]
        }
        existing = pcol.find_one({"name": sample["name"]})
        if not existing:
            pcol.insert_one(sample)
            print("Inserted sample playbook:", sample["name"])
    except Exception as e:
        print("Could not ensure sample playbook (no DB available):", e)

# ---------- CLI demo ----------
if __name__ == "__main__":
    print("SOAR module test run (dry-run). This will not perform real blocking unless you call execute_playbook with dry_run=False and have configured credentials.")
    try:
        ensure_sample_playbook()
        # attempt a dry-run execution using local DB playbook if DB is available
        if playbooks_col:
            pb = playbooks_col.find_one({"name": "block_ip_cloudflare_and_case"})
            if pb:
                print("Executing sample playbook in dry-run for 1.2.3.4")
                print(json.dumps(execute_playbook(pb, "1.2.3.4", dry_run=True), indent=2))
            else:
                print("Sample playbook not found in DB")
        else:
            print("No playbooks_col available (DB not configured). Create playbooks in Mongo to use SOAR.")
    except Exception:
        traceback.print_exc()
        print("SOAR demo finished with errors.")
