"""
SEC-04: Clean up memory rows in wrong namespaces.

Run once after deploying the SEC-01 namespace injection fix.
Idempotent: safe to run multiple times.

Strategy:
  1. Rows where namespace == "default" -> reassign to "agent:{agent_id}"
  2. Rows where namespace starts with "agent:" but encodes a DIFFERENT
     agent_id than the row's agent_id column -> DELETE (BOLA exploitation)
  3. Rows where agent_id not in agents table -> DELETE (orphaned by deleted agents)
  4. "notes" namespace rows (tiered memory) -> LEAVE ALONE
  5. Apply same cleanup to memory_history table (if namespace column exists)

Usage:
    python -m migrations.fix_orphaned_namespaces
    python migrations/fix_orphaned_namespaces.py
"""
import sqlite3
import os
import sys

DB_PATH = os.environ.get("MOLTGRID_DB", "agentforge.db")


def run(db_path: str = None) -> dict:
    """Run the migration. Returns dict with counts for verification.

    Args:
        db_path: Path to the SQLite database. Defaults to MOLTGRID_DB env var or agentforge.db.

    Returns:
        dict with keys: orphaned_before, default_before, deleted_agents_before,
        default_reassigned, orphaned_after, default_after, notes_preserved, total_changes
    """
    path = db_path or DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")

    counts = {}

    # Step 1: Count orphaned rows BEFORE cleanup
    counts["orphaned_before"] = conn.execute(
        "SELECT COUNT(*) FROM memory WHERE namespace LIKE 'agent:%' AND namespace != 'agent:' || agent_id"
    ).fetchone()[0]

    counts["default_before"] = conn.execute(
        "SELECT COUNT(*) FROM memory WHERE namespace = 'default'"
    ).fetchone()[0]

    counts["deleted_agents_before"] = conn.execute(
        "SELECT COUNT(*) FROM memory WHERE agent_id NOT IN (SELECT agent_id FROM agents)"
    ).fetchone()[0]

    # Reset total_changes counter via a no-op
    conn.execute("SELECT 1")

    # Step 2: Reassign "default" namespace rows to correct agent namespace
    conn.execute("""
        UPDATE memory SET namespace = 'agent:' || agent_id
        WHERE namespace = 'default'
    """)
    counts["default_reassigned"] = conn.execute("SELECT changes()").fetchone()[0]

    # Step 3: Delete rows where namespace encodes a different agent_id (BOLA exploitation)
    # Note: "notes" namespace does not match 'agent:%' so it is not affected
    conn.execute("""
        DELETE FROM memory
        WHERE namespace LIKE 'agent:%'
        AND namespace != 'agent:' || agent_id
    """)

    # Step 4: Delete rows whose agent_id no longer exists in agents table
    conn.execute("""
        DELETE FROM memory
        WHERE agent_id NOT IN (SELECT agent_id FROM agents)
    """)

    # Step 5: Apply same cleanup to memory_history table if namespace column exists
    # Check schema first to be safe with older DB versions
    history_cols = [
        row[1] for row in conn.execute("PRAGMA table_info(memory_history)").fetchall()
    ]
    if "namespace" in history_cols:
        conn.execute("""
            UPDATE memory_history SET namespace = 'agent:' || agent_id
            WHERE namespace = 'default'
        """)
        conn.execute("""
            DELETE FROM memory_history
            WHERE namespace LIKE 'agent:%'
            AND namespace != 'agent:' || agent_id
        """)
        conn.execute("""
            DELETE FROM memory_history
            WHERE agent_id NOT IN (SELECT agent_id FROM agents)
        """)

    conn.commit()

    # Step 6: Verify zero orphaned rows remain
    counts["orphaned_after"] = conn.execute(
        "SELECT COUNT(*) FROM memory WHERE namespace LIKE 'agent:%' AND namespace != 'agent:' || agent_id"
    ).fetchone()[0]

    counts["default_after"] = conn.execute(
        "SELECT COUNT(*) FROM memory WHERE namespace = 'default'"
    ).fetchone()[0]

    counts["notes_preserved"] = conn.execute(
        "SELECT COUNT(*) FROM memory WHERE namespace = 'notes'"
    ).fetchone()[0]

    counts["total_remaining"] = conn.execute(
        "SELECT COUNT(*) FROM memory"
    ).fetchone()[0]

    conn.close()

    print("Migration complete:")
    print(f"  Orphaned rows (agent:X where X != agent_id): {counts['orphaned_before']} -> {counts['orphaned_after']}")
    print(f"  Default namespace rows: {counts['default_before']} -> {counts['default_after']}")
    print(f"  Rows for deleted agents: {counts['deleted_agents_before']}")
    print(f"  Notes namespace preserved: {counts['notes_preserved']}")
    print(f"  Default rows reassigned: {counts['default_reassigned']}")

    return counts


if __name__ == "__main__":
    db = sys.argv[1] if len(sys.argv) > 1 else None
    result = run(db_path=db)
    if result["orphaned_after"] != 0:
        print(f"WARNING: {result['orphaned_after']} orphaned rows still remain!", file=sys.stderr)
        sys.exit(1)
    if result["default_after"] != 0:
        print(f"WARNING: {result['default_after']} default-namespace rows still remain!", file=sys.stderr)
        sys.exit(1)
    print("Verification passed: zero orphaned rows, zero default-namespace rows.")
