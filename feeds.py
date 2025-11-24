# feeds.py
# Robust feed ingestion for CTI Dashboard
# Drop this into your project as /home/ck/Downloads/CTI/feeds.py

import time
import requests
import traceback
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

# Default network timeout
_DEFAULT_TIMEOUT = 15

# Small set of example feeds (URLs). You can extend this list.
_FEEDS = {
    "feodo_ipblocklist": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "feodo_domainblocklist": "https://feodotracker.abuse.ch/downloads/domainblocklist.txt",
    "ransomware_ips": "https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt",
    "blocklist_de": "https://lists.blocklist.de/lists/all.txt",
    # add other feeds here...
}

# helpers --------------------------------------------------------------------
def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _safe_get(url: str, headers: Optional[Dict[str,str]] = None, timeout: int = _DEFAULT_TIMEOUT) -> str:
    """
    Perform a safe GET request and return text. Raises requests.HTTPError on bad HTTP status.
    """
    try:
        r = requests.get(url, headers=headers or {}, timeout=timeout, allow_redirects=True)
        r.raise_for_status()
        return r.text
    except Exception:
        # raise to caller so caller can decide how to handle
        raise

def fetch_blocklist(url: str) -> List[str]:
    """
    Fetch a simple blocklist text file and return indicator lines (stripped).
    Ignores blank lines and comments (#).
    """
    try:
        txt = _safe_get(url)
    except Exception as e:
        raise RuntimeError(f"HTTP error on {url}: {e}") from e

    lines = []
    for ln in txt.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        # many blocklists include comments after fields - take first token
        parts = ln.split()
        if parts:
            lines.append(parts[0].strip())
    return lines

# feed state helpers (rel_col tracks feed state) ----------------------------
def _feed_state_doc_name(feed_name: str) -> str:
    return f"feed:{feed_name}"

def _get_feed_state(rel_col, feed_name: str) -> Optional[Dict[str,Any]]:
    """
    Return a state document for the feed or None if not present.
    rel_col may be None (in which case this returns None safely).
    IMPORTANT: do NOT call bool(rel_col) — compare with None explicitly.
    """
    if rel_col is None:
        return None
    # Relational collection stores docs keyed by name
    doc = rel_col.find_one({"_id": _feed_state_doc_name(feed_name)})
    return doc

def _set_feed_failure(rel_col, feed_name: str, reason: str):
    """Mark feed as failed with timestamp and reason. Safe if rel_col is None."""
    if rel_col is None:
        return
    try:
        rel_col.update_one(
            {"_id": _feed_state_doc_name(feed_name)},
            {"$set": {"last_failed_at": datetime.now(timezone.utc), "last_error": reason}},
            upsert=True,
        )
    except Exception:
        traceback.print_exc()

def _set_feed_success(rel_col, feed_name: str, added_count: int):
    """Record feed success and number of items added."""
    if rel_col is None:
        return
    try:
        rel_col.update_one(
            {"_id": _feed_state_doc_name(feed_name)},
            {"$set": {"last_success_at": datetime.now(timezone.utc), "last_added": int(added_count)}},
            upsert=True,
        )
    except Exception:
        traceback.print_exc()

def _should_skip_feed(rel_col, feed_name: str) -> bool:
    """
    Decide whether to skip a feed based on recent failures (if rel_col is provided).
    Simple heuristic: if feed failed less than 1 minute ago, skip.
    """
    state = _get_feed_state(rel_col, feed_name)
    if not state:
        return False
    last_failed = state.get("last_failed_at")
    if last_failed and isinstance(last_failed, datetime):
        delta = datetime.now(timezone.utc) - last_failed
        if delta.total_seconds() < 60:
            return True
    return False

# ingestion logic ------------------------------------------------------------
def _upsert_indicator(ioc_feed, indicator: str, feed_name: str, src_url: str) -> bool:
    """
    Insert minimal indicator doc into ioc_feed if not exists.
    Returns True if inserted, False if already present or on error.
    Important: keep documents small and idempotent.
    """
    try:
        # canonicalize indicator string
        indicator = indicator.strip()
        if not indicator:
            return False
        # We'll insert if there's no document with same indicator
        exists = ioc_feed.find_one({"indicator": indicator})
        if exists:
            return False
        doc = {
            "indicator": indicator,
            "source": feed_name,
            "source_url": src_url,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            # fields below can be enriched elsewhere
            "type": "ip" if _looks_like_ip(indicator) else "domain",
            "score": 0,
            "country": "Unknown",
            "tags": ["feed:" + feed_name]
        }
        ioc_feed.insert_one(doc)
        return True
    except Exception:
        traceback.print_exc()
        return False

def _looks_like_ip(s: str) -> bool:
    # simple detection
    try:
        parts = s.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return True
    except Exception:
        pass
    return False

def ingest_all(ioc_feed,
               rel_col,
               limit: int = 200,
               api_key: Optional[str] = None,
               enable_blocklists: bool = True) -> Dict[str,Any]:
    """
    Ingest multiple feeds into ioc_feed. rel_col is optional collection used to record feed state.
    Returns summary dict.
    """
    summary = {"start": _now_iso(), "feeds": {}, "added_total": 0}
    try:
        feed_items_max = limit or 200
        # iterate configured feeds
        for fname, url in _FEEDS.items():
            feed_summary = {"checked": False, "added": 0, "error": None, "count": 0}
            summary["feeds"][fname] = feed_summary

            # optionally skip if feed flapping (using rel_col state)
            try:
                if _should_skip_feed(rel_col, fname):
                    feed_summary["error"] = "skipped: recent failure"
                    continue
            except Exception:
                # ensure feed doesn't crash overall ingestion
                traceback.print_exc()

            if not enable_blocklists:
                feed_summary["error"] = "disabled"
                continue

            # fetch
            try:
                items = fetch_blocklist(url)
                feed_summary["checked"] = True
                feed_summary["count"] = len(items)
            except Exception as e:
                # mark feed failure but continue
                err = str(e)
                feed_summary["error"] = err
                _set_feed_failure(rel_col, fname, err)
                continue

            # ingest items, up to feed_items_max across all feeds
            added = 0
            for it in items:
                if summary["added_total"] >= feed_items_max:
                    break
                try:
                    ok = _upsert_indicator(ioc_feed, it, fname, url)
                    if ok:
                        added += 1
                        summary["added_total"] += 1
                except Exception:
                    traceback.print_exc()
                    # continue with next item
            feed_summary["added"] = added
            try:
                _set_feed_success(rel_col, fname, added)
            except Exception:
                traceback.print_exc()

        summary["end"] = _now_iso()
        return summary

    except Exception as e:
        traceback.print_exc()
        return {"error": str(e), "partial": summary}

# If used as script for debug
if __name__ == "__main__":
    import os
    try:
        # quick debug run requires MONGO env or manual wiring; skip here
        print("feeds.py debug run - no Mongo configured in standalone mode.")
    except Exception:
        traceback.print_exc()
