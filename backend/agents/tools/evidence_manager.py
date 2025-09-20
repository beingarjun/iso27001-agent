"""
Evidence Management System
Immutable evidence storage with chain of custody and integrity verification
"""

import hashlib
import json
import shutil
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging

# Import models and deps from backend when running in full application
from ...models import Evidence, Finding, User  
from ...deps import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

class EvidenceManager:
    """Immutable evidence storage with chain of custody tracking"""
    
    def __init__(self):
        self.evidence_root = Path("evidence")
        self.evidence_vault = self.evidence_root / "vault"
        self.staging_area = self.evidence_root / "staging"
        self.metadata_store = self.evidence_root / "metadata"
        
        # Create directory structure
        self.evidence_vault.mkdir(parents=True, exist_ok=True)
        self.staging_area.mkdir(parents=True, exist_ok=True)
        self.metadata_store.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories by evidence type
        for evidence_type in ["scans", "screenshots", "logs", "documents", "certificates", "bias_tests"]:
            (self.evidence_vault / evidence_type).mkdir(exist_ok=True)
            (self.staging_area / evidence_type).mkdir(exist_ok=True)
    
    def store_evidence(
        self,
        title: str,
        description: str,
        evidence_type: str,
        file_content: bytes,
        file_name: str,
        mime_type: str,
        org_id: int,
        collected_by: str,
        finding_id: Optional[int] = None,
        control_id: Optional[str] = None,
        audit_period: Optional[str] = None,
        is_sensitive: bool = False,
        authorized_roles: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Store evidence with immutable storage and integrity verification
        
        Args:
            title: Evidence title
            description: Evidence description  
            evidence_type: Type of evidence (SCREENSHOT, LOG_FILE, DOCUMENT, etc.)
            file_content: Raw file content as bytes
            file_name: Original file name
            mime_type: MIME type of the file
            org_id: Organization ID
            collected_by: User who collected the evidence
            finding_id: Optional related finding ID
            control_id: Optional related control ID
            audit_period: Optional audit period
            is_sensitive: Whether evidence contains sensitive data
            authorized_roles: List of roles authorized to access (if sensitive)
        
        Returns:
            Dict containing evidence metadata and storage details
        """
        
        try:
            # Generate unique evidence ID
            evidence_id = f"EVD-{datetime.utcnow().year}-{uuid.uuid4().hex[:8].upper()}"
            
            # Calculate content hash for integrity
            content_hash = hashlib.sha256(file_content).hexdigest()
            
            # Create metadata
            metadata = {
                "evidence_id": evidence_id,
                "title": title,
                "description": description,
                "evidence_type": evidence_type,
                "file_name": file_name,
                "file_size": len(file_content),
                "mime_type": mime_type,
                "content_hash": content_hash,
                "org_id": org_id,
                "collected_by": collected_by,
                "collection_date": datetime.utcnow().isoformat(),
                "collection_method": "API_UPLOAD",
                "finding_id": finding_id,
                "control_id": control_id,
                "audit_period": audit_period,
                "is_sensitive": is_sensitive,
                "authorized_roles": authorized_roles or [],
                "immutable": True,
                "custody_log": [
                    {
                        "action": "COLLECTED",
                        "timestamp": datetime.utcnow().isoformat(),
                        "user": collected_by,
                        "details": "Evidence collected and stored in vault"
                    }
                ]
            }
            
            # Calculate metadata hash for tampering detection
            metadata_hash = self._calculate_metadata_hash(metadata)
            metadata["metadata_hash"] = metadata_hash
            
            # Store file in vault with hash-based path
            vault_path = self._get_vault_path(evidence_type, content_hash, file_name)
            
            with open(vault_path, 'wb') as f:
                f.write(file_content)
            
            # Store metadata
            metadata_path = self.metadata_store / f"{evidence_id}.json"
            with open(metadata_path, 'w') as f:
                f.write(json.dumps(metadata, indent=2))
            
            # Verify storage integrity
            self._verify_storage_integrity(vault_path, content_hash)
            
            logger.info(f"Evidence {evidence_id} stored successfully in vault")
            
            return {
                "evidence_id": evidence_id,
                "content_hash": content_hash,
                "vault_path": str(vault_path),
                "metadata_path": str(metadata_path),
                "file_size": len(file_content),
                "stored_at": datetime.utcnow().isoformat(),
                "immutable": True
            }
            
        except Exception as e:
            logger.error(f"Failed to store evidence: {str(e)}")
            raise Exception(f"Evidence storage failed: {str(e)}")
    
    def retrieve_evidence(
        self,
        evidence_id: str,
        requesting_user: str,
        user_roles: List[str]
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Retrieve evidence with access control and audit logging
        
        Args:
            evidence_id: Evidence identifier
            requesting_user: User requesting access
            user_roles: Roles of requesting user
        
        Returns:
            Tuple of (file_content, metadata)
        """
        
        try:
            # Load metadata
            metadata_path = self.metadata_store / f"{evidence_id}.json"
            if not metadata_path.exists():
                raise Exception(f"Evidence {evidence_id} not found")
            
            with open(metadata_path, 'r') as f:
                metadata_content = f.read()
                metadata = json.loads(metadata_content)
            
            # Verify metadata integrity
            stored_hash = metadata.pop("metadata_hash")
            calculated_hash = self._calculate_metadata_hash(metadata)
            metadata["metadata_hash"] = stored_hash
            
            if stored_hash != calculated_hash:
                logger.error(f"Metadata integrity check failed for evidence {evidence_id}")
                raise Exception("Evidence metadata has been tampered with")
            
            # Check access permissions
            if metadata["is_sensitive"]:
                authorized_roles = metadata.get("authorized_roles", [])
                if not any(role in user_roles for role in authorized_roles) and "ADMIN" not in user_roles:
                    raise Exception("Access denied: insufficient permissions for sensitive evidence")
            
            # Get file path
            vault_path = Path(metadata.get("vault_path") or self._get_vault_path(
                metadata["evidence_type"], 
                metadata["content_hash"], 
                metadata["file_name"]
            ))
            
            if not vault_path.exists():
                raise Exception(f"Evidence file not found: {vault_path}")
            
            # Read file content
            with open(vault_path, 'rb') as f:
                file_content = f.read()
            
            # Verify content integrity
            content_hash = hashlib.sha256(file_content).hexdigest()
            if content_hash != metadata["content_hash"]:
                logger.error(f"Content integrity check failed for evidence {evidence_id}")
                raise Exception("Evidence file has been tampered with")
            
            # Log access in custody chain
            self._log_custody_action(
                evidence_id=evidence_id,
                action="ACCESSED",
                user=requesting_user,
                details=f"Evidence accessed by {requesting_user}"
            )
            
            logger.info(f"Evidence {evidence_id} retrieved by {requesting_user}")
            
            return file_content, metadata
            
        except Exception as e:
            logger.error(f"Failed to retrieve evidence {evidence_id}: {str(e)}")
            raise
    
    def verify_evidence_integrity(
        self,
        evidence_id: str
    ) -> Dict[str, Any]:
        """
        Verify integrity of stored evidence
        
        Args:
            evidence_id: Evidence identifier
        
        Returns:
            Dict containing integrity verification results
        """
        
        try:
            # Load metadata
            metadata_path = self.metadata_store / f"{evidence_id}.json"
            if not metadata_path.exists():
                return {
                    "evidence_id": evidence_id,
                    "status": "NOT_FOUND",
                    "metadata_integrity": False,
                    "content_integrity": False,
                    "verified_at": datetime.utcnow().isoformat()
                }
            
            with open(metadata_path, 'r') as f:
                metadata_content = f.read()
                metadata = json.loads(metadata_content)
            
            # Verify metadata integrity
            stored_metadata_hash = metadata.get("metadata_hash")
            metadata_copy = metadata.copy()
            metadata_copy.pop("metadata_hash", None)
            calculated_metadata_hash = self._calculate_metadata_hash(metadata_copy)
            
            metadata_integrity = stored_metadata_hash == calculated_metadata_hash
            
            # Verify content integrity
            vault_path = Path(metadata.get("vault_path") or self._get_vault_path(
                metadata["evidence_type"], 
                metadata["content_hash"], 
                metadata["file_name"]
            ))
            
            content_integrity = False
            content_hash = None
            if vault_path.exists():
                with open(vault_path, 'rb') as f:
                    file_content = f.read()
                
                content_hash = hashlib.sha256(file_content).hexdigest()
                content_integrity = content_hash == metadata["content_hash"]
            
            status = "INTACT" if metadata_integrity and content_integrity else "COMPROMISED"
            
            return {
                "evidence_id": evidence_id,
                "status": status,
                "metadata_integrity": metadata_integrity,
                "content_integrity": content_integrity,
                "file_exists": vault_path.exists() if vault_path else False,
                "verified_at": datetime.utcnow().isoformat(),
                "original_hash": metadata.get("content_hash"),
                "current_hash": content_hash
            }
            
        except Exception as e:
            logger.error(f"Integrity verification failed for evidence {evidence_id}: {str(e)}")
            return {
                "evidence_id": evidence_id,
                "status": "ERROR",
                "error": str(e),
                "verified_at": datetime.utcnow().isoformat()
            }
    
    def _get_vault_path(self, evidence_type: str, content_hash: str, file_name: str) -> Path:
        """Get vault storage path for evidence file"""
        # Use content hash for deduplication and file extension from original name
        file_extension = Path(file_name).suffix
        vault_filename = f"{content_hash}{file_extension}"
        return self.evidence_vault / evidence_type / vault_filename
    
    def _calculate_metadata_hash(self, metadata: Dict) -> str:
        """Calculate hash of metadata for integrity verification"""
        # Remove dynamic fields that shouldn't affect integrity
        metadata_copy = metadata.copy()
        metadata_copy.pop("metadata_hash", None)
        metadata_copy.pop("custody_log", None)  # Custody log can change
        
        metadata_str = json.dumps(metadata_copy, sort_keys=True)
        return hashlib.sha256(metadata_str.encode()).hexdigest()
    
    def _verify_storage_integrity(self, file_path: Path, expected_hash: str):
        """Verify file was stored correctly"""
        with open(file_path, 'rb') as f:
            content = f.read()
        
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != expected_hash:
            raise Exception(f"Storage integrity check failed: {actual_hash} != {expected_hash}")
    
    def _log_custody_action(
        self,
        evidence_id: str,
        action: str,
        user: str,
        details: str
    ):
        """Log custody action for evidence"""
        try:
            metadata_path = self.metadata_store / f"{evidence_id}.json"
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.loads(f.read())
                
                custody_entry = {
                    "action": action,
                    "timestamp": datetime.utcnow().isoformat(),
                    "user": user,
                    "details": details
                }
                
                metadata["custody_log"].append(custody_entry)
                
                # Recalculate metadata hash (excluding custody log)
                metadata_for_hash = metadata.copy()
                metadata_for_hash.pop("metadata_hash", None)
                metadata_for_hash.pop("custody_log", None)
                metadata["metadata_hash"] = self._calculate_metadata_hash(metadata_for_hash)
                
                with open(metadata_path, 'w') as f:
                    f.write(json.dumps(metadata, indent=2))
        
        except Exception as e:
            logger.error(f"Failed to log custody action for {evidence_id}: {str(e)}")

# Factory function
def create_evidence_manager() -> EvidenceManager:
    """Create and configure evidence manager"""
    return EvidenceManager()