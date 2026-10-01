
"""Standalone classroom ledger. Not integrated with the application API."""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone


def simulate_once(db_path, *, incident_id, entity_id, action, approval):
    if action not in {"isolate_endpoint", "disable_identity"}:
        raise ValueError("Unsupported action")
    if not incident_id or not entity_id:
        raise ValueError("Missing incident or entity")

    # Saved classroom decisions are inputs, not authenticated credentials.
    if (
        approval.get("incident_id") != incident_id
        or approval.get("action") != action
        or approval.get("dry_run") is not True
        or not str(approval.get("analyst", "")).strip()
    ):
        raise ValueError("Invalid classroom decision")

    if approval.get("decision") == "deny":
        return {"status": "denied", "dry_run": True}

    if (
        approval.get("decision") != "approve"
        or approval.get("status") != "simulated"
    ):
        raise ValueError("Approval required")

    fields = {
        "playbook_id": "PB-SAVANNAPAY-001",
        "playbook_version": "1.0",
        "incident_id": incident_id,
        "entity_id": entity_id,
        "action": action,
    }
    key = hashlib.sha256(
        json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    db = sqlite3.connect(str(db_path), timeout=30)
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("""
            CREATE TABLE IF NOT EXISTS simulations (
                idempotency_key TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                completed_at TEXT NOT NULL
            )
        """)
        existing = db.execute(
            "SELECT 1 FROM simulations WHERE idempotency_key = ?", (key,)
        ).fetchone()

        if existing:
            status = "already_completed"
        else:
            # Inserting this record is the entire simulated effect.
            payload = {
                **fields,
                "analyst": approval["analyst"],
                "status": "simulated",
                "dry_run": True,
            }
            db.execute(
                "INSERT INTO simulations VALUES (?, ?, ?)",
                (
                    key,
                    json.dumps(payload, sort_keys=True),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            status = "simulated"
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    return {
        "status": status,
        "idempotency_key": key,
        "dry_run": True,
    }
