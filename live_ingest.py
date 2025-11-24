#!/usr/bin/env python3
"""
live_ingest.py - Live ingest + optional auto-block (SOAR) for CTI Dashboard

Behavior:
 - Periodically pulls feeds via feeds.ingest_all()
 - Upserts indicators into ioc_feed
 - Performs simple tag-based scoring (configurable)
 - Emits alerts if score >= ALERT_THRESHOLD
 - If AUTO_BLOCK_ENABLE is true, triggers soar.playbook on high-score indicators
 - Dry-run by default (AUTO_BLOCK_REAL=false), but logs all actions

Drop in as the service ExecStart target (you already have systemd unit).
"""

import os
import sys
import time
import json
import traceback
from datetime import datetime, timezone

# local modules (project)
from db import ioc_feed, enrichment_cache, alerts, relations, playbooks, automation_logs, mongo_client, ensure_indexes
import feeds
import attack_graph
import soar

# load config
_cfg_path = os.path.join(os.path.dirname(__file__), "config.json")
if not os.path.exists(_cfg_path):
    print("Missing config.json; create from config.example.json")
    sys.exit(1)
with open(_cfg_path, "r", encoding="utf-8") as fh:
    cfg = json.load(fh)

# basic settings
INGEST_INTERVAL = int(cfg.get("INGEST_INTERVAL_SECONDS", cfg.get("INGEST_INTERVAL", 900)))
INGEST_LIMIT = int(cfg.get("INGEST_LIMIT", 200))
ALERT_THRESHOLD = int(cfg.get("ALERT_THRESHOLD", cfg.get("AUTO_BLOCK_THRESHOLD", 80)))

AUTO_BLOCK_ENABLE = bool(cfg.get("AUTO_BLOCK_ENABLE", False))
AUTO_BLOCK_PLAYBOOK = cfg.get("AUTO_BLOCK_PLAYBOOK", "block_cloudflare_and_create_case")
AUTO_BLOCK_REAL = bool(cfg.get("AUTO_BLOCK_REAL", False))  # false -> dry-run

OTX_KEY = cfg.get("OTX_API_KEY", "") or os.environ.get("OTX_API_KEY", "")

# scoring tag weights (simple heuristic). You can edit to match TAG_WEIGHTS elsewhere.
TAG_WEIGHTS = {
    "malware": 50, "phishing": 40, "c2": 30, "command-and-control": 30,
    "botnet": 30, "crypto-mining": 20, "ransomware": 60, "exploit": 25,
    "credential theft": 30, "trojan": 35, "backdoor": 30, "scanner": 10,
    "suspicious": 15, "urlhaus": 40, "threatfox": 40, "otx": 20
}

# helper utilities
def now_utc():
    return datetime.now(timezone.utc)

def score_from_tags(tags, ind_type=None):
    s = 0
    if not tags:
        return 0
    tset = [t.lower() for t in tags]
    for k, w in TAG_WEIGHTS.items():
        for t in tset:
            if k in t:
                s += w
    # small bonus for IPs
    if ind_type and ind_type.lower() == "ip":
        s += 5
    return min(100, int(s))

def level_from_score(score):
    if score <= 30:
        return "Safe"
    if score <= 70:
        return "Suspicious"
    return "Malicious"

def upsert_ioc_simple(indicator, ind_type="domain", tags=None, src=None):
    """
    Upsert a document into ioc_feed with minimal fields and return the stored doc.
    """
    doc = {
        "indicator": indicator,
        "type": ind_type,
        "tags": list(set(tags or [])),
        "source": src or "feeds",
        "updated_at": now_utc()
    }
    qry = {"indicator": indicator}
    # Use upsert; if exists, merge tags and increment hit_count
    existing = ioc_feed.find_one(qry)
    if existing:
        merged_tags = list(set(existing.get("tags", []) + doc["tags"]))
        doc["tags"] = merged_tags
        # increment hit_count if exists
        ioc_feed.update_one(qry, {"$set": doc, "$inc": {"hit_count": 1}})
    else:
        doc["created_at"] = now_utc()
        doc["hit_count"] = 1
        ioc_feed.insert_one(doc)
    return ioc_feed.find_one(qry)

def create_alert_if_needed(indicator, score, level):
    """
    Insert into alerts collection if above threshold (and not duplicate for same score).
    """
    try:
        if score >= ALERT_THRESHOLD:
            exists = alerts.find_one({"indicator": indicator, "alert_score": score})
            if not exists:
                alerts.insert_one({
                    "indicator": indicator,
                    "alert_score": score,
                    "level": level,
                    "created_at": now_utc(),
                    "handled_by_soar": False
                })
                return True
    except Exception:
        traceback.print_exc()
    return False

def trigger_auto_block(indicator, real_action=False):
    """
    Execute the configured playbook via soar. Returns response dict.
    real_action: if False -> dry-run (playbook executed with dry_run=True)
    """
    try:
        soar.ensure_collections()
        pb = soar.playbooks_col.find_one({"name": AUTO_BLOCK_PLAYBOOK})
        if not pb:
            return {"error": "playbook not found", "playbook": AUTO_BLOCK_PLAYBOOK}
        res = soar.execute_playbook(pb, indicator, dry_run=(not real_action))
        # log action into automation_logs collection
        try:
            soar.log_action(pb.get("name", "auto-block"), "auto_block_execution", indicator, success=True, dry_run=(not real_action), details={"result": res})
        except Exception:
            # fallback logging if soar.log_action isn't present or errors
            try:
                automation_logs.insert_one({
                    "playbook": pb.get("name", "auto-block"),
                    "action": "auto_block_execution",
                    "indicator": indicator,
                    "success": True,
                    "dry_run": (not real_action),
                    "details": res,
                    "timestamp": now_utc()
                })
            except Exception:
                pass
        return {"ok": True, "result": res}
    except Exception as e:
        traceback.print_exc()
        # ensure we also log failures
        try:
            automation_logs.insert_one({
                "playbook": AUTO_BLOCK_PLAYBOOK,
                "action": "auto_block_error",
                "indicator": indicator,
                "success": False,
                "dry_run": (not real_action),
                "details": {"error": str(e)},
                "timestamp": now_utc()
            })
        except Exception:
            pass
        return {"error": str(e)}

# ensure indexes and collections prepared
ensure_indexes()
soar.ensure_collections()

def process_items(items):
    """
    items: list of dicts returned by feeds.ingest_all() -> {"indicator","type","tags", "src"}
    For each: upsert, score, set level, create alert record, optionally trigger SOAR.
    Returns summary dict.
    """
    inserted = 0
    updated = 0
    blocked = 0
    dry_run_executions = 0
    entries = []

    for it in items:
        try:
            ind = it.get("indicator")
            ind_type = it.get("type") or ("ip" if looks_like_ip(ind) else "domain")
            tags = it.get("tags") or []
            src = it.get("src", "feeds")
            if not ind:
                continue

            # upsert
            before = ioc_feed.find_one({"indicator": ind})
            stored = upsert_ioc_simple(ind, ind_type=ind_type, tags=tags, src=src)
            if before:
                updated += 1
            else:
                inserted += 1

            # score
            score = score_from_tags(tags, ind_type)
            level = level_from_score(score)

            # write score/level to DB
            ioc_feed.update_one({"indicator": ind}, {"$set": {"score": int(score), "level": level, "updated_at": now_utc()}})

            # create alert if needed
            alerted = create_alert_if_needed(ind, score, level)

            # auto-block if enabled and above threshold
            if AUTO_BLOCK_ENABLE and score >= ALERT_THRESHOLD:
                # safety: don't auto-block private IPs or localhost
                if ind_type == "ip":
                    try:
                        import ipaddress
                        ipobj = ipaddress.ip_address(ind)
                        if ipobj.is_private or ipobj.is_loopback or ipobj.is_reserved:
                            # skip blocking internal addresses
                            entries.append({"indicator": ind, "score": score, "blocked": False, "reason": "private_or_reserved"})
                            continue
                    except Exception:
                        pass

                # run the playbook (dry-run unless AUTO_BLOCK_REAL True)
                res = trigger_auto_block(ind, real_action=AUTO_BLOCK_REAL)
                entries.append({"indicator": ind, "score": score, "action": res})
                if AUTO_BLOCK_REAL and not res.get("error"):
                    blocked += 1
                else:
                    dry_run_executions += 1
            else:
                entries.append({"indicator": ind, "score": score, "level": level, "alerted": alerted})

        except Exception:
            traceback.print_exc()
            continue

    return {
        "inserted": inserted,
        "updated": updated,
        "blocked": blocked,
        "dry_run_executions": dry_run_executions,
        "items": entries
    }

def looks_like_ip(val):
    if not isinstance(val, str):
        return False
    if ":" in val:
        return True
    parts = val.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return False

def run_once():
    print(f"[live_ingest] Starting ingest (limit={INGEST_LIMIT}) at {now_utc().isoformat()}")
    try:
        # relations collection used by feeds for feed_state/circuit breaker
        rel_col = relations

        res = feeds.ingest_all(ioc_feed, rel_col, limit=INGEST_LIMIT, api_key=OTX_KEY)
        items = res.get("items", []) if isinstance(res, dict) else []

        print(f"[live_ingest] fetched {len(items)} items from feeds")
        if not items:
            return {"status": "no_items"}

        # process -> upsert + score + alerts + optional blocking
        summary = process_items(items)
        print("[live_ingest] summary:", summary)
        return summary

    except Exception:
        traceback.print_exc()
        return {"error": "exception"}

def main_loop():
    print(f"[live_ingest] live_ingest started. interval={INGEST_INTERVAL} seconds, AUTO_BLOCK_ENABLE={AUTO_BLOCK_ENABLE}, AUTO_BLOCK_REAL={AUTO_BLOCK_REAL}")
    try:
        while True:
            run_once()
            time.sleep(INGEST_INTERVAL)
    except KeyboardInterrupt:
        print("Interrupted, exiting.")
    except Exception:
        traceback.print_exc()

if __name__ == "__main__":
    main_loop()
