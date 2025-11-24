#!/usr/bin/env python3
"""
collector.py - improved and robust with GeoIP enrichment

- Uses timezone-aware datetimes
- Adds request timeouts and raise_for_status
- Uses Mongo upsert to avoid find_one loops
- Handles KeyboardInterrupt gracefully
- Loads GeoLite2 DB (if available) to enrich IPs with country
- Caches GeoIP lookups in enrichment_cache collection
"""

import os
import json
import time
import traceback
import requests
from datetime import datetime, timezone
from pymongo import errors
from db import ioc_feed, enrichment_cache, alerts, ensure_indexes

# try/except import geoip2 (optional dependency)
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except Exception:
    GEOIP_AVAILABLE = False

# Load config
_cfg_path = os.path.join(os.path.dirname(__file__), 'config.json')
if not os.path.exists(_cfg_path):
    raise SystemExit("Missing config.json - copy config.example.json to config.json and update keys")

with open(_cfg_path) as f:
    cfg = json.load(f)

OTX_KEY = cfg.get("OTX_API_KEY")
BASE_URL = "https://otx.alienvault.com/api/v1"
HEADERS = {'X-OTX-API-KEY': OTX_KEY}
MAX_PULSES = int(os.environ.get("MAX_PULSES", "50"))
BATCH_SLEEP = float(os.environ.get("BATCH_SLEEP", "0.01"))  # small pause between DB writes

# GeoIP DB path (place GeoLite2-Country.mmdb here)
GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), "geoip", "GeoLite2-Country.mmdb")
_geo_reader = None
if GEOIP_AVAILABLE and os.path.exists(GEOIP_DB_PATH):
    try:
        _geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        print("GeoIP DB loaded:", GEOIP_DB_PATH)
    except Exception as e:
        print("GeoIP DB load error:", e)
        _geo_reader = None
else:
    if not GEOIP_AVAILABLE:
        print("geoip2 library not installed. GeoIP enrichment disabled. (pip install geoip2)")
    else:
        print("GeoIP DB not found at", GEOIP_DB_PATH, "- GeoIP enrichment disabled.")

# ensure Mongo is available (ensure_indexes will exercise it)
try:
    ensure_indexes()
except errors.ServerSelectionTimeoutError as e:
    print("MongoDB unavailable (server selection timeout). Check MONGO_URI and that mongod is running.")
    raise

# Tag weights (same as before) - you can edit TAG_WEIGHTS in your main collector if needed
TAG_WEIGHTS = {
    "malware": 50, "phishing": 40, "c2": 30, "command-and-control": 30,
    "botnet": 30, "crypto-mining": 20, "ransomware": 60, "exploit": 25,
    "credential theft": 30, "trojan": 35, "backdoor": 30, "scanner": 10,
    "suspicious": 15
}

def now_utc():
    return datetime.now(timezone.utc)

def score_indicator(tags, indicator_type=None):
    score = 0
    t = set([t.lower() for t in (tags or [])])
    for key, w in TAG_WEIGHTS.items():
        for tag in t:
            if key in tag:
                score += w
    score = min(score, 80)
    if indicator_type and indicator_type.lower() == 'ip':
        score += 5
    return min(100, int(score))

def normalize_indicator(ind):
    return {
        "type": ind.get("type"),
        "indicator": ind.get("indicator"),
        "description": ind.get("description") or "",
        "tags": ind.get("tags", []),
        "asn": ind.get("asn", None),
        "country": ind.get("country", None),
        "created": ind.get("created"),
        "first_seen": ind.get("first_seen", None),
        "last_seen": ind.get("last_seen", None),
        "date_added_local": now_utc()
    }

def upsert_indicator(doc):
    """
    Single-call upsert: set fields from doc on insert and update updated_at/hit_count on modify.
    """
    qry = {"indicator": doc["indicator"], "type": doc["type"]}
    update = {
        "$set": {**doc, "updated_at": now_utc()},
        "$setOnInsert": {"created_at": now_utc()},
        "$inc": {"hit_count": 1}
    }
    # upsert will create or update; return the upserted/updated doc
    _ = ioc_feed.update_one(qry, update, upsert=True)
    # fetch the document once (cheap read) to continue enrichment
    return ioc_feed.find_one(qry)

# --- GeoIP helper functions --------------------------------
def get_country_for_ip(ip):
    """
    Return ISO country code (e.g. 'US', 'IN') for an IPv4 string.
    Uses enrichment_cache to avoid repeated GeoIP lookups.
    """
    if not ip:
        return "Unknown"
    # check cache
    cached = enrichment_cache.find_one({"indicator": ip, "type": "geoip"})
    if cached:
        return cached.get("data", {}).get("country", "Unknown")
    country = "Unknown"
    if _geo_reader:
        try:
            resp = _geo_reader.country(ip)
            country = resp.country.iso_code or "Unknown"
        except Exception:
            country = "Unknown"
    # cache result
    enrichment_cache.update_one(
        {"indicator": ip, "type": "geoip"},
        {"$set": {"data": {"country": country, "ts": now_utc()}}},
        upsert=True
    )
    return country

# -----------------------------------------------------------

def enrich_and_score(doc):
    """
    Enrich and compute score, then update the document.
    Adds GeoIP country for IPs if possible.
    """
    try:
        # if doc is None, skip
        if not doc:
            return None, None

        # 1) GeoIP: if this is an IP and country not set or unknown, try to get it
        doc_country = doc.get("country")
        if doc.get("type", "").lower() == "ip" and (not doc_country or doc_country in [None, "", "Unknown"]):
            country = get_country_for_ip(doc.get("indicator"))
            # update doc in DB with country
            ioc_feed.update_one(
                {"indicator": doc["indicator"], "type": doc["type"]},
                {"$set": {"country": country, "updated_at": now_utc()}}
            )
            # refresh doc reference
            doc = ioc_feed.find_one({"indicator": doc["indicator"], "type": doc["type"]})

        # 2) Scoring
        tags = doc.get("tags", [])
        indicator_type = doc.get("type")
        base_score = score_indicator(tags, indicator_type)
        freq = doc.get("hit_count", 1)
        freq_bonus = min(10, int(freq / 3))
        final_score = min(100, base_score + freq_bonus)

        if final_score <= 30:
            level = "Safe"
        elif final_score <= 70:
            level = "Suspicious"
        else:
            level = "Malicious"

        ioc_feed.update_one(
            {"indicator": doc["indicator"], "type": doc["type"]},
            {"$set": {
                "score": final_score,
                "level": level,
                "updated_at": now_utc()
            }}
        )

        # create alert doc if threshold exceeded (avoid duplicates by checking same alert_score)
        if final_score >= cfg.get("ALERT_THRESHOLD", 80):
            exists = alerts.find_one({"indicator": doc["indicator"], "alert_score": final_score})
            if not exists:
                alerts.insert_one({
                    "indicator": doc["indicator"],
                    "type": doc.get("type"),
                    "alert_score": final_score,
                    "level": level,
                    "created_at": now_utc()
                })

        return final_score, level
    except Exception:
        traceback.print_exc()
        return None, None

def fetch_otx_pulses(limit=MAX_PULSES):
    url = f"{BASE_URL}/pulses/subscribed"
    try:
        r = requests.get(url, headers=HEADERS, params={"limit": limit}, timeout=30)
        r.raise_for_status()
        data = r.json()
        return data.get("results", [])
    except requests.RequestException as e:
        print("OTX fetch error:", e)
        # optionally fallback to public pulses endpoint
        try:
            r2 = requests.get(f"{BASE_URL}/pulses", headers=HEADERS, params={"limit": limit}, timeout=30)
            r2.raise_for_status()
            return r2.json().get("results", [])
        except Exception as e2:
            print("OTX fallback also failed:", e2)
            return []

def ingest_once(limit=MAX_PULSES):
    ensure_indexes()
    pulses = fetch_otx_pulses(limit=limit)
    print(f"[{now_utc()}] Fetched {len(pulses)} pulses")
    processed = 0

    for p in pulses:
        indicators = p.get("indicators", [])
        pulse_tags = p.get("tags", []) or []
        for ind in indicators:
            try:
                doc = normalize_indicator(ind)
                doc["tags"] = list(set(doc.get("tags", []) + pulse_tags))
                doc["description"] = doc.get("description") or p.get("description", "")
                upserted = upsert_indicator(doc)
                # re-load to get hit_count and ensure country enrichment & scoring
                target = ioc_feed.find_one({"indicator": doc["indicator"], "type": doc["type"]})
                enrich_and_score(target)
                processed += 1
                if BATCH_SLEEP:
                    time.sleep(BATCH_SLEEP)
            except Exception:
                traceback.print_exc()
                continue
    print(f"[{now_utc()}] Ingest finished. Processed {processed} indicators.")
    return processed

def main_loop():
    try:
        ingest_once()
        # If you want continuous ingest on an interval, uncomment next lines:
        # while True:
        #     ingest_once()
        #     time.sleep(60*30)  # sleep 30 minutes between ingests
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting cleanly.")
    except Exception:
        traceback.print_exc()

if __name__ == "__main__":
    main_loop()
