"""
CAPA (Corrective Action Preventive Action) Workflow Management
Automated CAPA tracking with escalation and effectiveness verification
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum
import uuid
import json

from ..models import CAPA, Finding, User, CAPAStatus
from ..deps import get_db
from .tools.evidence_manager import EvidenceManager

class CAPAWorkflowEngine:
    """CAPA workflow automation with escalation"""
    
    def __init__(self, evidence_manager: EvidenceManager):
        self.evidence_manager = evidence_manager
    
    def create_capa(
        self,
        finding_id: int,
        corrective_action: str,
        preventive_action: str,
        responsible_party: str,
        target_date: datetime,
        org_id: int,
        created_by: str,
        priority: str = "MEDIUM"
    ) -> Dict[str, Any]:
        """Create new CAPA with automated workflow"""
        
        capa_id = f"CAPA-{datetime.utcnow().year}-{uuid.uuid4().hex[:8].upper()}"
        
        # Calculate escalation dates
        escalation_dates = self._calculate_escalation_schedule(target_date, priority)
        
        capa_data = {
            "capa_id": capa_id,
            "finding_id": finding_id,
            "corrective_action": corrective_action,
            "preventive_action": preventive_action,
            "responsible_party": responsible_party,
            "target_date": target_date.isoformat(),
            "priority": priority,
            "status": CAPAStatus.OPEN.value,
            "org_id": org_id,
            "created_by": created_by,
            "created_at": datetime.utcnow().isoformat(),
            "escalation_schedule": escalation_dates,
            "workflow_state": "ASSIGNED",
            "effectiveness_verification": {
                "required": True,
                "completed": False,
                "verification_date": None,
                "verification_method": None
            }
        }
        
        return {
            "capa_id": capa_id,
            "workflow_initiated": True,
            "next_milestone": escalation_dates[0] if escalation_dates else None,
            "capa_data": capa_data
        }
    
    def _calculate_escalation_schedule(self, target_date: datetime, priority: str) -> List[Dict]:
        """Calculate escalation schedule based on priority"""
        
        escalations = []
        
        if priority == "HIGH":
            # Daily escalations for high priority
            current_date = datetime.utcnow()
            while current_date < target_date:
                current_date += timedelta(days=1)
                escalations.append({
                    "date": current_date.isoformat(),
                    "type": "REMINDER",
                    "recipients": ["responsible_party", "manager"]
                })
        
        elif priority == "MEDIUM":
            # Weekly escalations
            current_date = datetime.utcnow()
            while current_date < target_date:
                current_date += timedelta(weeks=1)
                escalations.append({
                    "date": current_date.isoformat(),
                    "type": "REMINDER",
                    "recipients": ["responsible_party"]
                })
        
        # Final escalation at due date
        escalations.append({
            "date": target_date.isoformat(),
            "type": "DUE_DATE",
            "recipients": ["responsible_party", "manager", "compliance_team"]
        })
        
        return escalations

def create_capa_workflow_engine(evidence_manager: EvidenceManager) -> CAPAWorkflowEngine:
    return CAPAWorkflowEngine(evidence_manager)