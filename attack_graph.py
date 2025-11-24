# attack_graph.py
"""
Attack Graph generator + helpers.

Relations collection schema:
{
  "source": "<indicator>",
  "target": "<indicator or entity>",
  "relation": "same_pulse" | "has_tag" | "same_asn" | "same_country" | ...,
  "weight": 1,
  "ctx": "<pulse_id or feed_id>",
  "created_at": datetime
}

Functions:
 - ensure_relations_index(relations_col)
 - create_relation(relations_col, source, target, relation, ctx=None, weight=1)
 - build_relations_from_pulse(relations_col, pulse_id, indicators, pulse_tags=None, asn_map=None, country_map=None)
 - graph_for_indicator(relations_col, indicator, depth=1, max_nodes=200)
"""
from datetime import datetime, timezone
import traceback

def now_utc():
    return datetime.now(timezone.utc)

def ensure_relations_index(relations_col):
    try:
        relations_col.create_index([("source",1)])
        relations_col.create_index([("target",1)])
        relations_col.create_index([("relation",1)])
        relations_col.create_index([("ctx",1)])
    except Exception:
        traceback.print_exc()

def create_relation(relations_col, source, target, relation, ctx=None, weight=1):
    if not source or not target:
        return None
    if source == target:
        return None
    qry = {"source": source, "target": target, "relation": relation, "ctx": ctx}
    doc = {
        "source": source,
        "target": target,
        "relation": relation,
        "weight": int(weight or 1),
        "ctx": ctx,
        "created_at": now_utc()
    }
    try:
        relations_col.update_one(qry, {"$set": doc}, upsert=True)
        return doc
    except Exception:
        traceback.print_exc()
        return None

def build_relations_from_pulse(relations_col, pulse_id, indicators, pulse_tags=None, asn_map=None, country_map=None):
    pulse_tags = pulse_tags or []
    n = len(indicators or [])
    # pairwise same_pulse relations
    for i in range(n):
        for j in range(i+1, n):
            a = indicators[i]
            b = indicators[j]
            create_relation(relations_col, a, b, "same_pulse", ctx=pulse_id, weight=3)
            create_relation(relations_col, b, a, "same_pulse", ctx=pulse_id, weight=3)
    # tag relations
    for ind in indicators or []:
        for t in pulse_tags:
            if t:
                create_relation(relations_col, ind, f"tag::{t}", "has_tag", ctx=pulse_id, weight=1)
    # asn relations
    if asn_map:
        for ind in indicators or []:
            asn = asn_map.get(ind)
            if asn:
                create_relation(relations_col, ind, f"asn::{asn}", "same_asn", ctx=pulse_id, weight=2)
    # country relations
    if country_map:
        for ind in indicators or []:
            c = country_map.get(ind)
            if c:
                create_relation(relations_col, ind, f"country::{c}", "same_country", ctx=pulse_id, weight=2)

def graph_for_indicator(relations_col, indicator, depth=1, max_nodes=200):
    nodes = {}
    edges = []
    queue = [indicator]
    visited = set()
    level = 0
    while queue and len(nodes) < max_nodes and level < depth:
        next_q = []
        for src in queue:
            if src in visited:
                continue
            visited.add(src)
            try:
                for r in relations_col.find({"source": src}).limit(1000):
                    tgt = r.get("target")
                    if not tgt:
                        continue
                    nodes[src] = True
                    nodes[tgt] = True
                    edges.append({
                        "from": src,
                        "to": tgt,
                        "relation": r.get("relation"),
                        "weight": r.get("weight", 1)
                    })
                    if tgt not in visited:
                        next_q.append(tgt)
            except Exception:
                traceback.print_exc()
                continue
        queue = next_q
        level += 1
    # format nodes
    node_list = []
    for n in list(nodes.keys())[:max_nodes]:
        ntype = "entity"
        if isinstance(n, str):
            if n.startswith("tag::"):
                ntype = "tag"
            elif n.startswith("asn::"):
                ntype = "asn"
            elif n.startswith("country::"):
                ntype = "country"
            else:
                # heuristics: IP or domain => ioc
                if n.count(".") >= 1 or ":" in n or "/" in n:
                    ntype = "ioc"
        node_list.append({"id": n, "label": n, "type": ntype})
    return {"nodes": node_list, "edges": edges}
