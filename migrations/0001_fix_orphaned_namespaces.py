"""
SEC-04: Clean up memory rows in wrong namespaces.

This file follows the numbered migration convention.
Delegates to fix_orphaned_namespaces.py for the actual logic.

Run once after deploying the SEC-01 namespace injection fix.
Idempotent: safe to run multiple times.

Usage:
    python -m migrations.0001_fix_orphaned_namespaces [db_path]
"""
from migrations.fix_orphaned_namespaces import run  # noqa: F401

if __name__ == "__main__":
    import sys
    db = sys.argv[1] if len(sys.argv) > 1 else None
    run(db_path=db)
