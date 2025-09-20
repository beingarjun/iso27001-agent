"""
SQLModel database models for ISO 27001 Agent
"""
from sqlmodel import SQLModel, Field
from typing import Optional, Literal
from datetime import datetime

# Type definitions
ApprovalStatus = Literal["PENDING", "APPROVED", "REJECTED"]
ScanStatus = Literal["RUNNING", "WAITING_APPROVAL", "DONE", "FAILED"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Finding(SQLModel, table=True):
    """Security finding with approval workflow"""
    id: Optional[int] = Field(default=None, primary_key=True)
    control: str = Field(description="ISO 27001 control reference (e.g., A.12.6)")
    severity: Severity = Field(description="Finding severity level")
    title: str = Field(description="Brief finding title")
    detail: str = Field(description="Detailed finding description")
    host: str = Field(description="Target host/system")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Approval workflow fields
    approval_status: ApprovalStatus = Field(default="PENDING")
    approval_reason: Optional[str] = Field(default=None, description="Approval/rejection reason")
    approved_by: Optional[str] = Field(default=None, description="Approver email/identifier")
    approved_at: Optional[datetime] = Field(default=None, description="Approval timestamp")
    
    # Additional metadata
    scan_run_id: Optional[int] = Field(default=None, foreign_key="scanrun.id")
    evidence: Optional[str] = Field(default=None, description="Supporting evidence/logs")
    remediation: Optional[str] = Field(default=None, description="Suggested remediation")
    
    # ISO 27001 specific
    control_family: Optional[str] = Field(default=None, description="Control family (e.g., Access Control)")
    risk_score: Optional[float] = Field(default=None, description="Calculated risk score")


class ScanRun(SQLModel, table=True):
    """Scan execution record"""
    id: Optional[int] = Field(default=None, primary_key=True)
    host: str = Field(description="Target host/system")
    status: ScanStatus = Field(default="RUNNING")
    
    # Timing
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = Field(default=None)
    
    # Results
    findings_count: int = Field(default=0, description="Total findings discovered")
    high_severity_count: int = Field(default=0, description="Count of high/critical findings")
    report_path: Optional[str] = Field(default=None, description="Generated report file path")
    
    # Execution metadata
    initiated_by: Optional[str] = Field(default=None, description="User who started the scan")
    scan_config: Optional[str] = Field(default=None, description="JSON scan configuration")
    
    # AI/LangGraph state
    graph_state: Optional[str] = Field(default=None, description="Serialized LangGraph state")
    error_message: Optional[str] = Field(default=None, description="Error details if failed")


class ControlMapping(SQLModel, table=True):
    """ISO 27001 control definitions and mappings"""
    id: Optional[int] = Field(default=None, primary_key=True)
    control_id: str = Field(unique=True, description="ISO control ID (e.g., A.12.6.1)")
    control_name: str = Field(description="Control name")
    control_description: str = Field(description="Full control description")
    control_family: str = Field(description="Control family/category")
    
    # Implementation guidance
    implementation_guidance: Optional[str] = Field(default=None)
    testing_procedures: Optional[str] = Field(default=None)
    
    # Automation mapping
    scanner_types: Optional[str] = Field(default=None, description="JSON list of applicable scanners")
    severity_mapping: Optional[str] = Field(default=None, description="JSON severity rules")


class UserRole(SQLModel, table=True):
    """User roles and permissions"""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_email: str = Field(unique=True, description="User email identifier")
    role: Literal["VIEWER", "APPROVER", "ADMIN"] = Field(description="User role")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = Field(default=None)
    is_active: bool = Field(default=True)


class AuditLog(SQLModel, table=True):
    """Audit trail for compliance"""
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_email: str = Field(description="User performing action")
    action: str = Field(description="Action performed")
    resource_type: str = Field(description="Type of resource (finding, scan, etc.)")
    resource_id: Optional[str] = Field(default=None, description="Resource identifier")
    details: Optional[str] = Field(default=None, description="JSON action details")
    ip_address: Optional[str] = Field(default=None, description="User IP address")
    user_agent: Optional[str] = Field(default=None, description="User agent string")


# Pydantic models for API requests/responses
class FindingCreate(SQLModel):
    """Request model for creating findings"""
    control: str
    severity: Severity
    title: str
    detail: str
    host: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None


class FindingUpdate(SQLModel):
    """Request model for updating findings"""
    approval_status: ApprovalStatus
    approval_reason: str
    approved_by: str


class ScanRequest(SQLModel):
    """Request model for starting scans"""
    host: str = Field(description="Target host to scan")
    scan_types: Optional[list[str]] = Field(default=None, description="Specific scan types to run")
    initiated_by: Optional[str] = Field(default=None, description="User initiating scan")


class ScanResponse(SQLModel):
    """Response model for scan operations"""
    run_id: int
    status: ScanStatus
    requires_approval: bool = False
    findings_count: int = 0
    message: Optional[str] = None