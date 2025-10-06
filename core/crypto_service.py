"""
Cryptographic Integrity Service
Handles hashing, signing, Merkle tree construction, and tamper detection
"""

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import uuid

class MerkleTree:
    """Merkle Tree implementation for tamper-evident snapshots"""
    
    def __init__(self):
        self.leaves = []
        self.tree = []
    
    def add_leaf(self, data: str) -> str:
        """Add a leaf to the tree and return its hash"""
        leaf_hash = hashlib.sha256(data.encode()).hexdigest()
        self.leaves.append(leaf_hash)
        return leaf_hash
    
    def build_tree(self) -> str:
        """Build the Merkle tree and return root hash"""
        if not self.leaves:
            return ""
        
        level = self.leaves[:]
        self.tree = [level]
        
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else level[i]
                combined = left + right
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                next_level.append(parent_hash)
            level = next_level
            self.tree.append(level)
        
        return level[0] if level else ""
    
    def get_proof(self, leaf_index: int) -> List[str]:
        """Generate Merkle proof for a specific leaf"""
        if leaf_index >= len(self.leaves):
            return []
        
        proof = []
        current_index = leaf_index
        
        for level in self.tree[:-1]:
            if current_index % 2 == 0:
                # Current node is left child
                if current_index + 1 < len(level):
                    proof.append(level[current_index + 1])
            else:
                # Current node is right child
                proof.append(level[current_index - 1])
            current_index //= 2
        
        return proof

class CryptoService:
    """Core cryptographic service for DefenderAI"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.generate_keys()
        self.merkle_tree = MerkleTree()
        self.snapshots = []
        
    def generate_keys(self):
        """Generate RSA key pair for signing"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def compute_file_hash(self, content: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Compute SHA-256 hash of file content with metadata"""
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        record = {
            "id": str(uuid.uuid4()),
            "content_hash": content_hash,
            "size": len(content),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {}
        }
        
        return record
    
    def create_snapshot(self, records: List[Dict[str, Any]], dept: str) -> Dict[str, Any]:
        """Create a signed snapshot of records"""
        snapshot = {
            "snapshot_id": str(uuid.uuid4()),
            "department": dept,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "record_count": len(records),
            "records": records
        }
        
        # Create Merkle tree from records
        merkle_tree = MerkleTree()
        for record in records:
            merkle_tree.add_leaf(json.dumps(record, sort_keys=True))
        
        merkle_root = merkle_tree.build_tree()
        snapshot["merkle_root"] = merkle_root
        
        # Sign the snapshot
        snapshot_data = json.dumps(snapshot, sort_keys=True)
        signature = self.sign_data(snapshot_data)
        
        signed_snapshot = {
            "snapshot": snapshot,
            "signature": signature,
            "signed_by": "DefenderAI_System",
            "signature_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        self.snapshots.append(signed_snapshot)
        return signed_snapshot
    
    def sign_data(self, data: str) -> str:
        """Sign data with private key"""
        signature = self.private_key.sign(
            data.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def verify_signature(self, data: str, signature: str) -> bool:
        """Verify signature with public key"""
        try:
            signature_bytes = base64.b64decode(signature)
            self.public_key.verify(
                signature_bytes,
                data.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def verify_integrity(self, record: Dict[str, Any], original_content: str) -> bool:
        """Verify integrity of a record against original content"""
        computed_hash = hashlib.sha256(original_content.encode()).hexdigest()
        return computed_hash == record.get("content_hash")
    
    def create_daily_merkle_root(self) -> str:
        """Create daily Merkle root from all snapshots"""
        if not self.snapshots:
            return ""
        
        daily_tree = MerkleTree()
        for snapshot in self.snapshots:
            snapshot_data = json.dumps(snapshot["snapshot"], sort_keys=True)
            daily_tree.add_leaf(snapshot_data)
        
        return daily_tree.build_tree()
    
    def get_tamper_evidence(self, record_id: str) -> Dict[str, Any]:
        """Get tamper evidence for a specific record"""
        evidence = {
            "record_id": record_id,
            "check_timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "unknown",
            "details": {}
        }
        
        # Find record in snapshots
        for snapshot in self.snapshots:
            for record in snapshot["snapshot"]["records"]:
                if record.get("id") == record_id:
                    # Verify snapshot signature
                    snapshot_data = json.dumps(snapshot["snapshot"], sort_keys=True)
                    signature_valid = self.verify_signature(snapshot_data, snapshot["signature"])
                    
                    evidence.update({
                        "status": "verified" if signature_valid else "tampered",
                        "details": {
                            "snapshot_id": snapshot["snapshot"]["snapshot_id"],
                            "original_timestamp": record["timestamp"],
                            "signature_valid": signature_valid,
                            "merkle_root": snapshot["snapshot"]["merkle_root"]
                        }
                    })
                    break
        
        return evidence

# Sample usage and test functions
def test_crypto_service():
    """Test the crypto service functionality"""
    crypto = CryptoService()
    
    # Sample records
    sample_records = [
        crypto.compute_file_hash("Top Secret Police Report #001", {"dept": "POLICE", "classification": "SECRET"}),
        crypto.compute_file_hash("Army Strategic Plan 2024", {"dept": "ARMY", "classification": "CONFIDENTIAL"}),
        crypto.compute_file_hash("Public Health Data Q4", {"dept": "HEALTH", "classification": "RESTRICTED"})
    ]
    
    # Create snapshots for different departments
    police_snapshot = crypto.create_snapshot([sample_records[0]], "POLICE")
    army_snapshot = crypto.create_snapshot([sample_records[1]], "ARMY")
    health_snapshot = crypto.create_snapshot([sample_records[2]], "HEALTH")
    
    # Create daily Merkle root
    daily_root = crypto.create_daily_merkle_root()
    
    print("=== DefenderAI Crypto Service Test ===")
    print(f"Daily Merkle Root: {daily_root}")
    print(f"Total Snapshots: {len(crypto.snapshots)}")
    
    # Test integrity verification
    for record in sample_records:
        evidence = crypto.get_tamper_evidence(record["id"])
        print(f"Record {record['id'][:8]}... - Status: {evidence['status']}")
    
    return crypto

if __name__ == "__main__":
    test_crypto_service()
