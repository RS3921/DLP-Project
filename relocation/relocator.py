"""
VAULT-X · Zero-Correlation Relocation Protocol (L-10/L-11)
4-step protocol: Decrypt → Fresh Key-B → Re-encrypt → DoD 3-pass wipe
"""
import os, json, time, hashlib, secrets, dataclasses
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, Callable
from core.vault_engine import VaultEngine, VaultBlob, SessionToken

@dataclass
class RelocationRecord:
    old_blob_id: str; new_blob_id: str; old_path_hash: str; new_path_hash: str
    wipe_passes: int; wipe_verified: bool; relocated_at: float; session_id: str
    def to_dict(self): return {**asdict(self), "relocated_at_str": datetime.fromtimestamp(self.relocated_at).isoformat()}

class LocationRegistry:
    def __init__(self, registry_dict):
        self._reg = registry_dict
    def register(self, blob_id, path):
        self._reg[blob_id] = hashlib.sha256(os.path.abspath(path).encode()).hexdigest()
    def remove(self, blob_id): self._reg.pop(blob_id, None)
    def verify_location(self, blob_id, path):
        stored = self._reg.get(blob_id)
        if not stored: return True
        return hashlib.sha256(os.path.abspath(path).encode()).hexdigest() == stored

def secure_wipe(path, passes=3):
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            for p in range(passes):
                f.seek(0)
                if p==0: f.write(b"\x00"*size)
                elif p==1: f.write(b"\xFF"*size)
                else: f.write(secrets.token_bytes(size))
                f.flush(); os.fsync(f.fileno())
        os.remove(path)
        return not os.path.exists(path)
    except: return False

class Relocator:
    def __init__(self, vault_engine, registry, audit_callback=None):
        self._engine = vault_engine; self._registry = registry; self._audit = audit_callback

    def relocate(self, old_path, new_path, token, wipe_passes=3):
        if not os.path.exists(old_path): raise FileNotFoundError(f"Not found: {old_path}")
        print(f"\n[Relocator] {old_path} → {new_path}  ({wipe_passes}-pass wipe)")
        with open(old_path) as f: old_blob = VaultBlob(**json.load(f))
        plaintext = self._engine.decrypt(old_blob, token)
        print(f"  ✓ Step 1: Decrypted {len(plaintext)} bytes")
        new_token = self._engine.create_session_token(token.owner_hash, scope=["write"])
        print(f"  ✓ Step 2: Fresh Key-B derived (zero correlation to Key-A)")
        new_blob = self._engine.encrypt(plaintext, new_token)
        del plaintext
        os.makedirs(os.path.dirname(new_path) if os.path.dirname(new_path) else ".", exist_ok=True)
        with open(new_path, "w") as f: json.dump(dataclasses.asdict(new_blob), f, indent=2)
        self._registry.register(new_blob.blob_id, new_path)
        self._engine.revoke_session(new_token.session_id)
        print(f"  ✓ Step 3: Re-encrypted → {new_path}")
        old_hash = hashlib.sha256(os.path.abspath(old_path).encode()).hexdigest()
        new_hash = hashlib.sha256(os.path.abspath(new_path).encode()).hexdigest()
        wipe_ok = secure_wipe(old_path, passes=wipe_passes)
        self._registry.remove(old_blob.blob_id)
        print(f"  ✓ Step 4: Old location wiped ({'success' if wipe_ok else 'failed'})")
        record = RelocationRecord(old_blob_id=old_blob.blob_id, new_blob_id=new_blob.blob_id,
            old_path_hash=old_hash[:16]+"...", new_path_hash=new_hash[:16]+"...",
            wipe_passes=wipe_passes, wipe_verified=wipe_ok, relocated_at=time.time(), session_id=token.session_id)
        print(f"\n  ✅ Relocation complete  Old ID: {old_blob.blob_id[:16]}...  New ID: {new_blob.blob_id[:16]}...")
        if self._audit: self._audit("RELOCATION_COMPLETE", record.to_dict())
        return record
