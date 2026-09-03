"""Audit logging with SHA-256 hash-chained entries.

Each audit entry is linked to the previous one via a SHA-256 hash,
creating a tamper-evident chain.  Any modification to a historical
entry breaks the chain and is detectable via verify_audit_chain().
"""

import time
from typing import Optional

from storage.db import Storage


class AuditLogger:
    """Hash-chained audit logger backed by the storage layer."""

    def __init__(self, storage: Storage):
        self.storage = storage

    def log(self, session_id: int, role: str, operation: str,
            object_label: str = None, object_handle: int = None,
            success: bool = True, detail: str = ""):
        """Record an audit entry."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.storage.insert_audit(
            timestamp=timestamp,
            session_id=session_id or 0,
            role=role or "anonymous",
            operation=operation,
            object_label=object_label or "",
            object_handle=object_handle or 0,
            success=success,
            detail=detail,
        )

    def show(self, limit: int = 100) -> str:
        """Return a formatted table of audit entries."""
        logs = self.storage.get_audit_logs(limit)
        if not logs:
            return "  (no audit entries)"

        header = (
            f"  {'ID':<5} {'Timestamp':<21} {'Sess':<5} {'Role':<12} "
            f"{'Operation':<30} {'Object':<20} {'Result':<8} {'Hash':<16}"
        )
        sep = "  " + "-" * 120
        lines = [header, sep]
        for e in logs:
            result = "SUCCESS" if e["success"] else "FAILED"
            short_hash = e["entry_hash"][:12] + "..."
            lines.append(
                f"  {e['id']:<5} {e['timestamp']:<21} {e['session_id']:<5} "
                f"{e['role']:<12} {e['operation']:<30} {e['object_label']:<20} "
                f"{result:<8} {short_hash:<16}"
            )
        if e:
            lines.append("")
            lines.append(f"  Chain integrity: {'VERIFIED' if self.verify_chain() else 'BROKEN'}")
        return "\n".join(lines)

    def clear(self):
        """Clear all audit entries."""
        self.storage.clear_audit_logs()

    def verify_chain(self) -> bool:
        """Verify the hash chain integrity."""
        return self.storage.verify_audit_chain()
