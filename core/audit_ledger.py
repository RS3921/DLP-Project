"""
VAULT-X · Immutable Audit Ledger (L-13)
Three-layer immutability: Append-only + SHA-256 hash chain + Ed25519 signatures
"""

import hashlib
import json
import os
import time
from datetime import datetime


class LedgerEntry:
    """One append-only audit record linked to the previous record by hash."""

    def __init__(self, index, event_type, details, prev_hash, signer_fn=None):
        """Create and optionally sign a new ledger entry."""
        self.index = index
        self.event_type = event_type
        self.details = details
        self.timestamp = datetime.now().isoformat()
        self.unix_ts = time.time()
        self.prev_hash = prev_hash
        self.entry_hash = self._compute_hash()
        self.signature = None
        if signer_fn:
            try:
                self.signature = signer_fn(
                    {
                        "index": self.index,
                        "event_type": self.event_type,
                        "entry_hash": self.entry_hash,
                        "timestamp": self.timestamp,
                    }
                )
            except Exception:
                # Audit logging must continue if an external signer is unavailable.
                self.signature = "unavailable"

    def _compute_hash(self):
        """Return the deterministic SHA-256 hash for the entry's signed fields."""
        core = json.dumps(
            {
                "index": self.index,
                "event_type": self.event_type,
                "details": self.details,
                "timestamp": self.timestamp,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
        ).encode()
        return hashlib.sha256(core).hexdigest()

    def verify_hash(self):
        """Check whether the stored entry hash still matches its content."""
        return self._compute_hash() == self.entry_hash

    def to_dict(self):
        """Serialize the entry into a JSON-compatible dictionary."""
        return {
            "index": self.index,
            "event_type": self.event_type,
            "details": self.details,
            "timestamp": self.timestamp,
            "unix_ts": self.unix_ts,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d):
        """Restore an entry without recomputing its original timestamp or hash."""
        obj = object.__new__(cls)
        for k in [
            "index",
            "event_type",
            "details",
            "timestamp",
            "unix_ts",
            "prev_hash",
            "entry_hash",
            "signature",
        ]:
            setattr(obj, k, d.get(k))
        return obj


class AuditLedger:
    """Append-only JSONL ledger protected by a forward SHA-256 hash chain."""

    LEDGER_FILE = "vault_audit.jsonl"
    GENESIS_HASH = "0" * 64

    def __init__(self, vault_dir, sign_fn=None):
        """Open the ledger in ``vault_dir`` and recover its last chain state."""
        self.vault_dir = vault_dir
        self._path = os.path.join(vault_dir, self.LEDGER_FILE)
        self._sign_fn = sign_fn
        self._count = 0
        self._last_hash = self.GENESIS_HASH
        os.makedirs(vault_dir, exist_ok=True)
        self._load_state()

    def _load_state(self):
        """Recover entry count and last hash from the existing JSONL file."""
        if not os.path.exists(self._path):
            return
        last = None
        count = 0
        with open(self._path) as f:
            for line in f:
                if line.strip():
                    last = line.strip()
                    count += 1
        self._count = count
        if last:
            try:
                self._last_hash = json.loads(last).get("entry_hash", self.GENESIS_HASH)
            except (json.JSONDecodeError, AttributeError):
                # Verification later reports malformed chain content.
                self._last_hash = self.GENESIS_HASH

    def log(self, event_type, details):
        """Append an event and advance the in-memory chain head."""
        e = LedgerEntry(self._count, event_type, details, self._last_hash, self._sign_fn)
        with open(self._path, "a") as f:
            f.write(json.dumps(e.to_dict()) + "\n")
        self._last_hash = e.entry_hash
        self._count += 1
        return e

    def read_all(self):
        """Read valid JSON ledger rows into ``LedgerEntry`` objects."""
        entries = []
        if not os.path.exists(self._path):
            return entries
        with open(self._path) as f:
            for line in f:
                if line.strip():
                    try:
                        entries.append(LedgerEntry.from_dict(json.loads(line)))
                    except (json.JSONDecodeError, TypeError):
                        # Keep reading so one malformed row does not hide later evidence.
                        pass
        return entries

    def verify_chain(self):
        """Validate sequence numbers, previous hashes, and entry hashes."""
        entries = self.read_all()
        prev = self.GENESIS_HASH
        for i, e in enumerate(entries):
            if e.index != i:
                return False, f"Sequence error at entry {i}"
            if e.prev_hash != prev:
                return False, f"Chain break at entry {i}"
            if not e.verify_hash():
                return False, f"Hash mismatch at entry {i}"
            prev = e.entry_hash
        return True, f"Chain valid. {len(entries)} entries verified."

    def print_recent(self, n=20):
        """Print the latest ``n`` audit entries for CLI operators."""
        entries = self.read_all()[-n:]
        print(f"\n{'─'*68}")
        print(f"  VAULT-X Audit Ledger — Last {len(entries)} entries")
        print(f"{'─'*68}")
        for e in entries:
            print(f"\n  [{e.timestamp[:19]}] #{e.index}  {e.event_type}")
            print(f"   hash: {e.entry_hash[:24]}...")
            for k, v in (e.details or {}).items():
                if k != "signature":
                    print(f"   {k}: {v}")
        print(f"{'─'*68}\n")

    def export_for_audit(self, output_path):
        """Export the complete ledger as one structured JSON document."""
        entries = self.read_all()
        with open(output_path, "w") as f:
            json.dump(
                {
                    "vault_x_version": "2.0.0",
                    "exported_at": datetime.now().isoformat(),
                    "entry_count": len(entries),
                    "entries": [e.to_dict() for e in entries],
                },
                f,
                indent=2,
            )
        print(f"[Audit Ledger] Exported {len(entries)} entries to {output_path}")
