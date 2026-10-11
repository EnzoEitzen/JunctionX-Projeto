"""
mongo_sync.py - push classified findings to MongoDB.

classifier.py calls this after it has written results.json. Every finding becomes one document.
Running it again updates the existing documents instead of creating duplicates.

Configuration (environment variables, or a .env file if python-dotenv is installed):
    MONGODB_URI          connection string. Syncing is skipped when this is not set.
    MONGODB_DB           database name    (default: quantumtrace)
    MONGODB_COLLECTION   collection name  (default: findings)

Each document has the nine Finding fields plus:
    _id          stable id built from source, asset, location, algorithm and key_length
    first_seen   when the finding was first stored (never changes)
    last_seen    when the finding was last reported by the scanners
    run_id       id of the classifier run that last reported it

The id deliberately ignores risk_tier, replacement, notes and library: those are re-derived on every
run, so a re-classified finding updates its document instead of creating a second one.
"""
import hashlib
import json
import os
import uuid
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone

DEFAULT_DB = "quantumtrace"
DEFAULT_COLLECTION = "findings"
BATCH_SIZE = 500
INDEXED_FIELDS = ("risk_tier", "source", "algorithm")   # fields a dashboard is likely to filter on


def finding_id(f, occurrence=0):
    """Stable id of a finding. `occurrence` separates findings that share the same identity."""
    identity = [f.source, f.asset.replace("\\", "/"), f.location, f.algorithm, f.key_length]
    if occurrence:
        identity.append(occurrence)
    return hashlib.sha256(json.dumps(identity).encode("utf-8")).hexdigest()[:32]


def assign_ids(findings):
    """One id per finding, in order. Two findings with the same identity get different ids."""
    seen, ids = Counter(), []
    for f in findings:
        base = finding_id(f)
        n = seen[base]
        seen[base] += 1
        ids.append(base if n == 0 else finding_id(f, n))
    return ids


def sync_findings(findings, collection, run_id=None, prune=False, replace=False, now=None):
    """Upsert every finding into `collection`. Returns a dict with the counts.

    prune=True also deletes documents that an earlier run stored but this run no longer reports. Only
    the sources present in this run are pruned, so a missing scanner output never wipes its findings.

    replace=True makes the collection hold exactly the findings of this run: everything else in it is
    deleted, whatever its source. The new findings are written first and the old ones removed afterwards,
    so a failure half way never leaves the collection empty. Use a collection that only holds findings."""
    from pymongo import UpdateOne          # imported here so the classifier works without pymongo installed

    run_id = run_id or uuid.uuid4().hex
    now = now or datetime.now(timezone.utc)
    ids = assign_ids(findings)

    operations = [
        UpdateOne(
            {"_id": fid},
            {"$set": {**asdict(f), "run_id": run_id, "last_seen": now},
             "$setOnInsert": {"first_seen": now}},
            upsert=True,
        )
        for fid, f in zip(ids, findings)
    ]

    inserted = updated = 0
    for start in range(0, len(operations), BATCH_SIZE):
        result = collection.bulk_write(operations[start:start + BATCH_SIZE], ordered=False)
        inserted += result.upserted_count
        updated += result.matched_count

    deleted = 0
    if replace:
        deleted = collection.delete_many({"run_id": {"$ne": run_id}}).deleted_count
    elif prune:
        sources = sorted({f.source for f in findings})
        deleted = collection.delete_many({"run_id": {"$ne": run_id}, "source": {"$in": sources}}).deleted_count

    for field in INDEXED_FIELDS:
        collection.create_index(field)

    return {"total": len(findings), "inserted": inserted, "updated": updated, "deleted": deleted, "run_id": run_id}


def _load_dotenv():
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv()


def push_findings(findings, db=None, collection=None, prune=False, replace=False, log=print):
    """Connect to MongoDB and sync the findings.

    Returns True on success, False if something went wrong, and None if MongoDB is not configured."""
    _load_dotenv()
    uri = os.environ.get("MONGODB_URI")
    if not uri:
        return None
    try:
        from pymongo import MongoClient
        from pymongo.errors import PyMongoError
    except ImportError:
        log("[ERROR] MONGODB_URI is set but pymongo is not installed. Run: pip install pymongo")
        return False

    db_name = db or os.environ.get("MONGODB_DB", DEFAULT_DB)
    coll_name = collection or os.environ.get("MONGODB_COLLECTION", DEFAULT_COLLECTION)
    client = None
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000, tz_aware=True)
        client.admin.command("ping")                       # fail fast with a clear message if unreachable
        stats = sync_findings(findings, client[db_name][coll_name], prune=prune, replace=replace)
    except PyMongoError as exc:
        log(f"[ERROR] MongoDB sync failed ({exc.__class__.__name__}): {exc}")
        return False
    finally:
        if client is not None:
            client.close()

    extra = f", {stats['deleted']} removed" if (prune or replace) else ""
    log(f"[OK] MongoDB {db_name}.{coll_name}: {stats['inserted']} new, {stats['updated']} updated{extra} "
        f"({stats['total']} findings)")
    return True