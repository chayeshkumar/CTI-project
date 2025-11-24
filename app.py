#!/usr/bin/env python3
"""
CTI Dashboard — Full Flask Application (updated with Playbook manager + Block endpoint)

- Dashboard endpoints
- Playbook CRUD + respond
- /api/block for manual blocking (playbook/cloudflare/iptables)
- Automation logs endpoint
- Admin-token protected endpoints (X-ADMIN-TOKEN)
"""

import os
import json
import traceback
from datetime import datetime, timezone
from functools import wraps

import requests
from flask import Flask, render_template, request, jsonify
import soar

# ---------- Mongo imports ----------
try:
    from bson.objectid import ObjectId
except Exception:
    class ObjectId:
        pass

try:
    from db import ioc_feed, alerts, ensure_indexes
except Exception as e:
    print("❌ Could not import db.py (ioc_feed, alerts, ensure_indexes):", e)
    raise

# ---------- Config ----------
_cfg_path = os.path.join(os.path.dirname(__file__), "config.json")
if not os.path.exists(_cfg_path):
    raise SystemExit("Missing config.json — create it from config.example.json.")
with open(_cfg_path, "r", encoding="utf-8") as fh:
    cfg = json.load(fh)

app = Flask(__name__)
ensure_indexes()

# ---------- Admin token auth ----------
ADMIN_TOKEN = cfg.get("ADMIN_TOKEN") or os.environ.get("CTI_ADMIN_TOKEN")

def require_admin(fn):
    """Decorator to protect sensitive endpoints with X-ADMIN-TOKEN header or admin_token query param."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-ADMIN-TOKEN") or request.args.get("admin_token")
        if not ADMIN_TOKEN:
            return jsonify({"error": "admin token not configured on server"}), 403
        if not token or token != ADMIN_TOKEN:
            return jsonify({"error": "unauthorized - missing or invalid admin token"}), 401
        return fn(*args, **kwargs)
    return wrapper

# ---------- Utils ----------
def now_iso(dt):
    if not dt:
        return None
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc).isoformat()
        return dt.isoformat()
    return str(dt)

def sanitize(obj):
    """Recursively convert Mongo objects to JSON-safe primitives."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    try:
        if isinstance(obj, ObjectId):
            return str(obj)
    except Exception:
        pass
    if isinstance(obj, datetime):
        return now_iso(obj)
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize(x) for x in obj]
    return str(obj)

# ---------- Load Country Centroids ----------
COUNTRY_CENTROIDS = {
    "US": [39.8, -98.6], "IN": [22.0, 79.0], "RU": [61.5, 105.3], "CN": [35.9, 104.2],
    "DE": [51.2, 10.4], "BR": [-10.0, -55.0], "GB": [54.0, -2.0], "FR": [46.2, 2.2],
    "NL": [52.1, 5.3], "CA": [56.1, -106.3], "JP": [36.2, 138.2]
}
_centroids_path = os.path.join(os.path.dirname(__file__), "geoip", "country_centroids.json")
if os.path.exists(_centroids_path):
    try:
        with open(_centroids_path, "r", encoding="utf-8") as fh:
            COUNTRY_CENTROIDS = json.load(fh)
        app.logger.info(f"✅ Loaded country_centroids.json ({len(COUNTRY_CENTROIDS)} entries)")
    except Exception as e:
        app.logger.warning(f"⚠️ Failed to load country_centroids.json: {e}")

def centroid_for_country(iso2):
    return COUNTRY_CENTROIDS.get(str(iso2).upper(), [0.0, 0.0])

# ---------- Routes ----------
@app.route("/")
def index():
    try:
        raw_data = list(ioc_feed.find().sort("updated_at", -1).limit(50))
        data = [sanitize(d) for d in raw_data]

        # Aggregates
        by_type = list(ioc_feed.aggregate([
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]))
        by_country = list(ioc_feed.aggregate([
            {"$match": {"country": {"$nin": [None, "", "Unknown"]}}},
            {"$group": {"_id": "$country", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))

        unknown_count = ioc_feed.count_documents({"country": {"$in": [None, "", "Unknown"]}})
        total_count = ioc_feed.count_documents({})
        known_count = total_count - unknown_count
        threshold = int(cfg.get("ALERT_THRESHOLD", 80))
        malicious_count = ioc_feed.count_documents({"score": {"$gte": threshold}})

        return render_template(
            "index.html",
            data=data,
            by_type=by_type,
            by_country=by_country,
            total_count=total_count,
            known_count=known_count,
            unknown_count=unknown_count,
            malicious_count=malicious_count,
            last_updated=data[0]["updated_at"] if data else "now",
            cfg=cfg
        )
    except Exception as e:
        traceback.print_exc()
        return f"Dashboard error: {e}", 500

# ---------- Basic API ----------
@app.route("/api/search")
def api_search():
    q = request.args.get("q", "")
    if not q:
        return jsonify([])
    results = list(ioc_feed.find({"indicator": {"$regex": q, "$options": "i"}}).limit(100))
    return jsonify([sanitize(r) for r in results])

@app.route("/api/indicator/<indicator>")
def api_indicator(indicator):
    doc = ioc_feed.find_one({"indicator": indicator})
    if not doc:
        return jsonify({"error": "not found"}), 404
    return jsonify(sanitize(doc))

@app.route("/api/aggregate/type")
def aggregate_type():
    pipeline = [{"$group": {"_id": "$type", "count": {"$sum": 1}}}]
    return jsonify([sanitize(x) for x in list(ioc_feed.aggregate(pipeline))])

# ---------- Geo Data ----------
@app.route("/api/geo_data")
def api_geo_data():
    try:
        pipeline = [
            {"$match": {"country": {"$nin": [None, "", "Unknown"]}}},
            {"$group": {
                "_id": "$country",
                "count": {"$sum": 1},
                "avg_score": {"$avg": {"$ifNull": ["$score", 0]}},
                "malicious": {"$sum": {"$cond": [{"$gte": ["$score", int(cfg.get("ALERT_THRESHOLD", 80))]}, 1, 0]}}
            }},
            {"$sort": {"count": -1}}
        ]
        arr = list(ioc_feed.aggregate(pipeline))
        out = []
        for x in arr:
            s = sanitize(x)
            lat, lon = centroid_for_country(s["_id"])
            out.append({
                "country": s["_id"],
                "count": s["count"],
                "avg_score": s["avg_score"],
                "malicious": s["malicious"],
                "lat": lat,
                "lon": lon
            })
        return jsonify(out)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ---------- AI Summarizer ----------
def call_llm_system(prompt_text, max_tokens=400):
    lm_url = cfg.get("LLM_API_URL", "").strip()
    if lm_url:
        resp = requests.post(lm_url, json={"prompt": prompt_text}, timeout=60)
        return resp.json().get("summary", resp.text)

    key = cfg.get("OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("No LLM configured")

    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    model = cfg.get("LLM_MODEL", "gpt-4o-mini")
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a cyber threat analyst."},
            {"role": "user", "content": prompt_text}
        ],
        "max_tokens": max_tokens,
        "temperature": 0.2
    }
    r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=body, timeout=60)
    j = r.json()
    return j["choices"][0]["message"]["content"].strip()

@app.route("/api/summarize", methods=["POST", "GET"])
def api_summarize():
    try:
        limit = int(request.args.get("limit", 100))
        docs = list(ioc_feed.find().sort("updated_at", -1).limit(limit))
        lines = [f"{d.get('indicator')} {d.get('type')} {d.get('country')} {d.get('score')} {d.get('level')}"
                 for d in docs]
        prompt = "Recent threat indicators:\n" + "\n".join(lines)
        summary = call_llm_system(prompt)
        return jsonify({"summary": summary})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ---------- SOAR: Playbooks CRUD & Respond ----------
@app.route("/api/playbooks", methods=["GET"])
@require_admin
def api_playbooks():
    try:
        soar.ensure_collections()
        arr = list(soar.playbooks_col.find())
        for p in arr:
            p["_id"] = str(p.get("_id"))
        return jsonify(arr)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/playbooks/<name>", methods=["GET"])
@require_admin
def api_get_playbook(name):
    try:
        soar.ensure_collections()
        p = soar.playbooks_col.find_one({"name": name})
        if not p:
            return jsonify({"error": "not found"}), 404
        p["_id"] = str(p.get("_id"))
        return jsonify(sanitize(p))
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/api/playbooks", methods=["POST"])
@require_admin
def api_create_playbook():
    try:
        body = request.get_json()
        if not body or "name" not in body:
            return jsonify({"error": "invalid payload"}), 400
        soar.ensure_collections()
        if soar.playbooks_col.find_one({"name": body["name"]}):
            return jsonify({"error": "playbook already exists"}), 409
        soar.playbooks_col.insert_one(body)

        admin_user = request.headers.get("X-ADMIN-USER") or request.args.get("admin_user") or "unknown"
        try:
            if hasattr(soar, "automation_logs"):
                soar.automation_logs.insert_one({
                    "action": "create_playbook",
                    "playbook": body.get("name"),
                    "admin_user": admin_user,
                    "payload": body,
                    "timestamp": datetime.now(timezone.utc),
                    "dry_run": False
                })
        except Exception:
            traceback.print_exc()

        return jsonify({"ok": True, "name": body["name"]}), 201
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/api/playbooks/<name>", methods=["PUT"])
@require_admin
def api_update_playbook(name):
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "invalid payload"}), 400
        soar.ensure_collections()
        existing = soar.playbooks_col.find_one({"name": name})
        if not existing:
            return jsonify({"error": "playbook not found"}), 404

        new_name = body.get("name", name)
        if new_name != name and soar.playbooks_col.find_one({"name": new_name}):
            return jsonify({"error": "new name conflicts with existing playbook"}), 409

        soar.playbooks_col.update_one({"name": name}, {"$set": body})
        admin_user = request.headers.get("X-ADMIN-USER") or request.args.get("admin_user") or "unknown"
        try:
            if hasattr(soar, "automation_logs"):
                soar.automation_logs.insert_one({
                    "action": "update_playbook",
                    "playbook": name,
                    "admin_user": admin_user,
                    "payload": body,
                    "timestamp": datetime.now(timezone.utc),
                    "dry_run": False
                })
        except Exception:
            traceback.print_exc()
        return jsonify({"ok": True, "updated": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/api/playbooks/<name>", methods=["DELETE"])
@require_admin
def api_delete_playbook(name):
    try:
        soar.ensure_collections()
        res = soar.playbooks_col.delete_one({"name": name})
        if res.deleted_count == 0:
            return jsonify({"error": "not found"}), 404
        admin_user = request.headers.get("X-ADMIN-USER") or request.args.get("admin_user") or "unknown"
        try:
            if hasattr(soar, "automation_logs"):
                soar.automation_logs.insert_one({
                    "action": "delete_playbook",
                    "playbook": name,
                    "admin_user": admin_user,
                    "timestamp": datetime.now(timezone.utc),
                    "dry_run": False
                })
        except Exception:
            traceback.print_exc()
        return jsonify({"ok": True, "deleted": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/api/respond", methods=["POST"])
@require_admin
def api_respond():
    try:
        body = request.get_json(silent=True) or {}
        playbook_name = body.get("playbook")
        indicator = body.get("indicator")
        confirm = bool(body.get("confirm", False))
        if not playbook_name or not indicator:
            return jsonify({"error": "playbook and indicator required"}), 400
        soar.ensure_collections()
        playbook = soar.playbooks_col.find_one({"name": playbook_name})
        if not playbook:
            return jsonify({"error": "playbook not found"}), 404

        res = soar.execute_playbook(playbook, indicator, dry_run=not confirm)

        admin_user = request.headers.get("X-ADMIN-USER") or request.args.get("admin_user") or "unknown"
        try:
            if hasattr(soar, "automation_logs"):
                soar.automation_logs.insert_one({
                    "action": "manual_respond",
                    "playbook": playbook_name,
                    "indicator": indicator,
                    "admin_user": admin_user,
                    "confirm": confirm,
                    "dry_run": not confirm,
                    "result": res,
                    "timestamp": datetime.now(timezone.utc)
                })
        except Exception:
            traceback.print_exc()

        return jsonify(res)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ---------- Block endpoint (admin-protected) ----------
@app.route("/api/block", methods=["POST"])
@require_admin
def api_block():
    """
    Block an indicator immediately.
    JSON body:
      { "indicator": "1.2.3.4", "method": "playbook"|"cloudflare"|"iptables", "playbook": "optional-playbook-name", "confirm": true/false }
    If confirm==false => dry-run (no real action)
    """
    try:
        body = request.get_json(silent=True) or {}
        indicator = body.get("indicator")
        if not indicator:
            return jsonify({"error": "indicator required"}), 400

        method = (body.get("method") or "playbook").lower()
        confirm = bool(body.get("confirm", False))

        # choose playbook (from payload or config)
        playbook_name = body.get("playbook") or cfg.get("DEFAULT_AUTOBLOCK_PLAYBOOK", "block_cloudflare_and_create_case")

        result = {"method": method, "indicator": indicator, "dry_run": not confirm}
        try:
            if method == "playbook":
                soar.ensure_collections()
                pb = soar.playbooks_col.find_one({"name": playbook_name})
                if not pb:
                    return jsonify({"error": f"playbook '{playbook_name}' not found"}), 404
                res = soar.execute_playbook(pb, indicator, dry_run=not confirm)
                result["result"] = res

            elif method == "cloudflare":
                res = soar.cloudflare_block_ip(indicator, dry_run=not confirm)
                result["result"] = res

            elif method == "iptables":
                res = soar.iptables_block_ip_local(indicator, dry_run=not confirm)
                result["result"] = res

            else:
                return jsonify({"error": f"unknown method '{method}'"}), 400

        except Exception as e:
            result["error"] = str(e)
            traceback.print_exc()

        # audit log
        admin_user = request.headers.get("X-ADMIN-USER") or request.args.get("admin_user") or "unknown"
        try:
            if hasattr(soar, "automation_logs"):
                soar.automation_logs.insert_one({
                    "action": "manual_block",
                    "method": method,
                    "playbook": playbook_name,
                    "indicator": indicator,
                    "admin_user": admin_user,
                    "confirm": confirm,
                    "dry_run": not confirm,
                    "result": result.get("result") or result.get("error"),
                    "timestamp": datetime.now(timezone.utc)
                })
        except Exception:
            traceback.print_exc()

        return jsonify(result)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# -------------------------------------------------------
#  AUTOMATION LOGS ENDPOINT (for SOAR actions)
# -------------------------------------------------------
@app.route("/api/automation_logs")
@require_admin
def api_automation_logs():
    try:
        if hasattr(soar, "ensure_collections"):
            soar.ensure_collections()

        rows = list(soar.automation_logs.find().sort("timestamp", -1).limit(200))

        out = []
        for r in rows:
            clean = {}
            for k, v in r.items():
                if k == "_id":
                    clean["_id"] = str(v)
                elif isinstance(v, datetime):
                    clean[k] = v.isoformat()
                else:
                    clean[k] = v
            out.append(clean)

        return jsonify(out)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ---------- Run ----------
if __name__ == "__main__":
    host = cfg.get("FLASK_HOST", "127.0.0.1")
    port = int(cfg.get("FLASK_PORT", 5000))
    print(f"🚀 Starting Flask at http://{host}:{port} — DB:{cfg.get('DB_NAME')} — SOAR Ready ✅")
    app.run(host=host, port=port, debug=True)
