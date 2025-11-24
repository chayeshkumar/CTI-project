# db.py
"""
MongoDB helpers for CTI project.
Exports:
 - mongo_client: the raw MongoClient
 - db: the selected database object
 - ioc_feed, enrichment_cache, alerts: Collection objects
 - ensure_indexes(): create recommended indexes (idempotent)
"""

import os
import json
from pymongo import MongoClient, errors

_cfg_path = os.path.join(os.path.dirname(__file__), "config.json")
if not os.path.exists(_cfg_path):
    raise SystemExit("db.py: Missing config.json in project root. Create config.json before running.")
with open(_cfg_path, "r", encoding="utf-8") as fh:
    cfg = json.load(fh)

MONGO_URI = os.environ.get("MONGO_URI") or cfg.get("MONGO_URI") or "mongodb://127.0.0.1:27017"
DB_NAME = cfg.get("DB_NAME", "cti_dashboard")

mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)


try:
    mongo_client.admin.command("ping")
except errors.ServerSelectionTimeoutError as e:
    
    print("Warning: cannot connect to MongoDB at", MONGO_URI, " —", str(e))


db = mongo_client[DB_NAME]
ioc_feed = db.get_collection("ioc_feed")
enrichment_cache = db.get_collection("enrichment_cache")
alerts = db.get_collection("alerts")
playbooks = db.get_collection("playbooks")
automation_logs = db.get_collection("automation_logs")
relations = db.get_collection("relations")

def ensure_indexes():
    """
    Create recommended indexes. Safe to call on every startup.
    """
    try:
        ioc_feed.create_index([("indicator", 1)])
        ioc_feed.create_index([("updated_at", -1)])
        ioc_feed.create_index([("country", 1)])
        ioc_feed.create_index([("score", -1)])
        ioc_feed.create_index([("type", 1)])
    except Exception:
        pass

    # enrichment cache
    try:
        enrichment_cache.create_index([("indicator", 1)], unique=True)
    except Exception:
        pass

    # alerts
    try:
        alerts.create_index([("created_at", -1)])
        alerts.create_index([("handled_by_soar", 1)])
    except Exception:
        pass

    # playbooks & automation logs
    try:
        playbooks.create_index([("name", 1)], unique=True)
        automation_logs.create_index([("timestamp", -1)])
    except Exception:
        pass

    # relations
    try:
        relations.create_index([("source", 1)])
        relations.create_index([("target", 1)])
    except Exception:
        pass

# run ensure_indexes on import for convenience (you can remove if you prefer manual)
try:
    ensure_indexes()
except Exception:
    # don't crash import if Mongo is offline; allow scripts to handle the exception later
    pass
