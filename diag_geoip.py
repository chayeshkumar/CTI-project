#!/usr/bin/env python3
"""
Diagnostic GeoIP script.

- Tests geoip2 on a known IP (8.8.8.8)
- Scans Mongo ioc_feed for IP-type docs and checks/updates country using GeoLite2 DB
- Prints enrichment_cache entries for geoip when present
"""
import os, sys, json
from datetime import datetime
import ipaddress
try:
    import geoip2.database
except Exception as e:
    geoip2 = None
    print("geoip2 not installed:", e)

# import db (uses your config.json)
try:
    from db import ioc_feed, enrichment_cache
except Exception as e:
    print("Error importing db.py - fix it first:", e)
    sys.exit(1)

# GeoIP DB path - must match your project
GEOIP_DB = os.path.join(os.path.dirname(__file__), "geoip", "GeoLite2-Country.mmdb")
if not os.path.exists(GEOIP_DB):
    print("GeoIP DB not found at:", GEOIP_DB)
    print("Place GeoLite2-Country.mmdb at that path.")
    sys.exit(1)

# Load reader
try:
    reader = geoip2.database.Reader(GEOIP_DB)
    print("GeoIP Reader loaded:", GEOIP_DB)
except Exception as e:
    print("Failed to open GeoIP DB:", e)
    sys.exit(1)

def geoip_lookup(ip):
    try:
        r = reader.country(ip)
        return r.country.iso_code or "Unknown"
    except Exception:
        return "Unknown"

# Quick sanity test
print("\n=== Quick sanity check with 8.8.8.8 ===")
test_ip = "8.8.8.8"
print("Lookup for 8.8.8.8 ->", geoip_lookup(test_ip))
print("---\n")

# Query: only IP-type docs
query = {"type": {"$in": ["IP", "ipv4", "IPv4", "ip", "IPv6", "ipv6", "IPv4 address"]}}
# We'll normalize by checking if indicator is valid IP
cursor = ioc_feed.find(query).limit(200)  # limit to 200 for safety

count = ioc_feed.count_documents(query)
print(f"Found {count} candidate IP-type documents (query). Scanning up to 200.\n")

processed = 0
updated = 0
mismatches = 0

for doc in cursor:
    processed += 1
    indicator = doc.get("indicator")
    stored_country = doc.get("country", None)
    resolved_ip = doc.get("resolved_ip", None)
    _id = doc.get("_id")
    print(f"[{processed}] _id={_id} indicator={indicator} stored_country={stored_country} resolved_ip={resolved_ip}")

    # Normalize indicator (strip port), check validity
    ip_candidate = None
    if indicator:
        # remove common schemes/ports (e.g., "1.2.3.4:80")
        cand = indicator.split("://")[-1].split("/")[0].split(":")[0]
        try:
            # Validate IP (v4 or v6)
            ip_obj = ipaddress.ip_address(cand)
            ip_candidate = str(ip_obj)
        except Exception:
            ip_candidate = None

    if not ip_candidate:
        print("  → indicator is NOT a valid IP string. (Maybe it's actually a domain.) Skipping.")
        print("")
        continue

    # Check enrichment_cache for geoip
    cache = enrichment_cache.find_one({"indicator": ip_candidate, "type": "geoip"})
    cached_country = cache.get("data", {}).get("country") if cache else None
    print(f"  → ip_candidate = {ip_candidate} ; enrichment_cache country = {cached_country}")

    # Do a direct lookup now
    looked_up = geoip_lookup(ip_candidate)
    print(f"  → GeoIP lookup result = {looked_up}")

    # If enrichment_cache missing but lookup ok, store cache
    if not cache or cached_country != looked_up:
        enrichment_cache.update_one(
            {"indicator": ip_candidate, "type": "geoip"},
            {"$set": {"data": {"country": looked_up, "ts": datetime.utcnow()}}},
            upsert=True
        )
        print("  → enrichment_cache updated.")

    # If document country is missing or Unknown and lookup gives a country, update doc
    if (not stored_country or stored_country in [None, "", "Unknown"]) and looked_up and looked_up != "Unknown":
        ioc_feed.update_one({"_id": _id}, {"$set": {"country": looked_up, "enriched_at": datetime.utcnow()}})
        updated += 1
        print(f"  → Document updated with country={looked_up}")
    else:
        # if doc has a different country, show mismatch
        if stored_country and looked_up and looked_up != "Unknown" and stored_country != looked_up:
            mismatches += 1
            print(f"  → NOTE: stored_country ({stored_country}) != looked_up ({looked_up})")
        else:
            print("  → No update needed.")

    print("")

print("=== Summary ===")
print(f"Processed: {processed}")
print(f"Updated docs: {updated}")
print(f"Mismatches found: {mismatches}")
print("If you updated docs, refresh dashboard to see country values.")
print("If many IP-type docs were skipped, they were not valid IP strings — they may be domains and need domain->IP enrichment script.")
