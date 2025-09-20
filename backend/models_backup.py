from sqlmodel import SQLModel, Field, Relationshipfrom sqlmodel import SQLModel, Field, Relationshipfrom sqlmodel import SQLModel, Field, Relationshipfrom sqlmodel import SQLModel, Field, Relationship

from typing import Optional, Literal, List

from datetime import datetime, timedeltafrom typing import Optional, Literal, List

from enum import Enum

import hashlibfrom datetime import datetimefrom typing import Optional, Literal, Listfrom typing import Optional, Literal, List

import json

import uuidimport hashlib



# Enterprise-grade enums following Vanta/Drata patternsimport jsonfrom datetime import datetimefrom datetime import datetime

class ApprovalStatus(str, Enum):

    PENDING = "PENDING"

    APPROVED = "APPROVED" 

    REJECTED = "REJECTED"# Enums for enterprise compliance (based on Vanta/Drata/Scrut patterns)import hashlibimport hashlib



class RiskStatus(str, Enum):ApprovalStatus = Literal["PENDING", "APPROVED", "REJECTED"]

    OPEN = "OPEN"

    MITIGATED = "MITIGATED"RiskStatus = Literal["OPEN", "MITIGATED", "ACCEPTED", "TRANSFERRED", "CLOSED"]import jsonimport json

    ACCEPTED = "ACCEPTED"

    TRANSFERRED = "TRANSFERRED"ControlStatus = Literal["INCLUDED", "EXCLUDED", "NOT_APPLICABLE"]

    CLOSED = "CLOSED"

CAPAStatus = Literal["OPEN", "IN_PROGRESS", "CLOSED", "OVERDUE"]

class ControlStatus(str, Enum):

    INCLUDED = "INCLUDED"DataClassification = Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]

    EXCLUDED = "EXCLUDED"

    NOT_APPLICABLE = "NOT_APPLICABLE"LawfulBasis = Literal["CONSENT", "CONTRACT", "LEGAL_OBLIGATION", "VITAL_INTERESTS", "PUBLIC_TASK", "LEGITIMATE_INTERESTS"]# Enums for compliance frameworks (inspired by Vanta/Drata/Scrut)# Enums



class ImplementationStatus(str, Enum):ComplianceFramework = Literal["ISO27001", "SOC2", "GDPR", "DPDP_INDIA", "PCI_DSS", "HIPAA"]

    NOT_STARTED = "NOT_STARTED"

    IN_PROGRESS = "IN_PROGRESS"ApprovalStatus = Literal["PENDING", "APPROVED", "REJECTED"]ApprovalStatus = Literal["PENDING", "APPROVED", "REJECTED"]

    IMPLEMENTED = "IMPLEMENTED"

    NEEDS_REVIEW = "NEEDS_REVIEW"# Organization & Multi-tenancy



class CAPAStatus(str, Enum):class Organization(SQLModel, table=True):RiskStatus = Literal["OPEN", "MITIGATED", "ACCEPTED", "TRANSFERRED", "CLOSED"]RiskStatus = Literal["OPEN", "MITIGATED", "ACCEPTED", "TRANSFERRED", "CLOSED"]

    OPEN = "OPEN"

    IN_PROGRESS = "IN_PROGRESS"    id: Optional[int] = Field(default=None, primary_key=True)

    CLOSED = "CLOSED"

    OVERDUE = "OVERDUE"    name: str = Field(unique=True)ControlStatus = Literal["INCLUDED", "EXCLUDED", "NOT_APPLICABLE"]ControlStatus = Literal["INCLUDED", "EXCLUDED", "NOT_APPLICABLE"]



class UserRole(str, Enum):    domain: str = Field(unique=True)

    ADMIN = "ADMIN"

    COMPLIANCE_MANAGER = "COMPLIANCE_MANAGER"    industry: Optional[str] = NoneCAPAStatus = Literal["OPEN", "IN_PROGRESS", "CLOSED", "OVERDUE"]CAPAStatus = Literal["OPEN", "IN_PROGRESS", "CLOSED", "OVERDUE"]

    AUDITOR = "AUDITOR"

    VIEWER = "VIEWER"    compliance_frameworks: str = Field(default='["ISO27001"]')  # JSON array



class ComplianceFramework(str, Enum):    created_at: datetime = Field(default_factory=datetime.utcnow)DataClassification = Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]DataClassification = Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]

    ISO27001 = "ISO27001"

    SOC2 = "SOC2"    subscription_tier: Literal["STARTER", "PROFESSIONAL", "ENTERPRISE"] = "STARTER"

    GDPR = "GDPR"

    DPDP_INDIA = "DPDP_INDIA"    is_active: bool = Field(default=True)LawfulBasis = Literal["CONSENT", "CONTRACT", "LEGAL_OBLIGATION", "VITAL_INTERESTS", "PUBLIC_TASK", "LEGITIMATE_INTERESTS"]LawfulBasis = Literal["CONSENT", "CONTRACT", "LEGAL_OBLIGATION", "VITAL_INTERESTS", "PUBLIC_TASK", "LEGITIMATE_INTERESTS"]

    PCI_DSS = "PCI_DSS"

    HIPAA = "HIPAA"



# Multi-tenant organization model (Drata-style)class User(SQLModel, table=True):ComplianceFramework = Literal["ISO27001", "SOC2", "GDPR", "DPDP_INDIA", "PCI_DSS", "HIPAA"]ComplianceFramework = Literal["ISO27001", "SOC2", "GDPR", "DPDP_INDIA", "PCI_DSS", "HIPAA"]

class Organization(SQLModel, table=True):

    """Multi-tenant organization entity"""    id: Optional[int] = Field(default=None, primary_key=True)

    id: Optional[int] = Field(default=None, primary_key=True)

    name: str = Field(min_length=1, max_length=100)    email: str = Field(unique=True)

    slug: str = Field(unique=True, min_length=3, max_length=50)

    domain: str = Field(unique=True)    name: str

    industry: Optional[str] = None

        role: Literal["ADMIN", "COMPLIANCE_MANAGER", "AUDITOR", "VIEWER"] = "VIEWER"# Organization & Multi-tenancy (Drata-style org management)# Core entities (similar to Vanta/Drata approach)

    # Compliance configuration

    compliance_frameworks: str = Field(default='["ISO27001"]')  # JSON array    org_id: int = Field(foreign_key="organization.id")

    risk_appetite_score: int = Field(default=15, ge=1, le=25)

        is_active: bool = Field(default=True)class Organization(SQLModel, table=True):class Finding(SQLModel, table=True):

    # Subscription and limits

    subscription_tier: Literal["STARTER", "PROFESSIONAL", "ENTERPRISE"] = "STARTER"    mfa_enabled: bool = Field(default=False)

    max_users: int = Field(default=10)

    max_controls: int = Field(default=100)    last_login: Optional[datetime] = None    id: Optional[int] = Field(default=None, primary_key=True)    id: Optional[int] = Field(default=None, primary_key=True)

    

    # Metadata    created_at: datetime = Field(default_factory=datetime.utcnow)

    created_at: datetime = Field(default_factory=datetime.utcnow)

    is_active: bool = Field(default=True)    sso_provider: Optional[str] = None    name: str = Field(unique=True)    control: str

    settings: Optional[str] = None  # JSON object for org-specific settings

    sso_id: Optional[str] = None

class User(SQLModel, table=True):

    """User with RBAC and SSO support"""    domain: str = Field(unique=True)    severity: str

    id: Optional[int] = Field(default=None, primary_key=True)

    email: str = Field(unique=True, index=True)# Core Finding entity with audit trail

    name: str = Field(min_length=1, max_length=100)

    role: UserRole = UserRole.VIEWERclass Finding(SQLModel, table=True):    industry: Optional[str] = None    title: str

    

    # Organization relationship    id: Optional[int] = Field(default=None, primary_key=True)

    org_id: int = Field(foreign_key="organization.id")

        org_id: int = Field(foreign_key="organization.id")    compliance_frameworks: str = Field(default='["ISO27001"]')  # JSON array    detail: str

    # Authentication

    hashed_password: Optional[str] = None    control: str

    is_active: bool = Field(default=True)

    email_verified: bool = Field(default=False)    severity: str    created_at: datetime = Field(default_factory=datetime.utcnow)    host: str

    

    # MFA and security    title: str

    mfa_enabled: bool = Field(default=False)

    mfa_secret: Optional[str] = None    detail: str    subscription_tier: Literal["STARTER", "PROFESSIONAL", "ENTERPRISE"] = "STARTER"

    last_login: Optional[datetime] = None

    failed_login_attempts: int = Field(default=0)    host: str

    

    # SSO integration    created_at: datetime = Field(default_factory=datetime.utcnow)    is_active: bool = Field(default=True)    created_at: datetime = Field(default_factory=datetime.utcnow)

    sso_provider: Optional[str] = None  # "google", "azure", "okta"

    sso_id: Optional[str] = None    approval_status: ApprovalStatus = "PENDING"

    

    # Metadata    approval_reason: Optional[str] = None

    created_at: datetime = Field(default_factory=datetime.utcnow)

    last_activity: Optional[datetime] = None    approved_by: Optional[str] = None



# Core compliance entities    class User(SQLModel, table=True):    approval_status: ApprovalStatus = "PENDING"# Type definitions

class ControlLibrary(SQLModel, table=True):

    """Master control library supporting multiple frameworks"""    # Evidence & audit trail

    id: Optional[int] = Field(default=None, primary_key=True)

    control_id: str = Field(unique=True)  # e.g., "A.5.1.1", "CC6.1"    raw_evidence_hash: Optional[str] = None    id: Optional[int] = Field(default=None, primary_key=True)

    framework: ComplianceFramework

    title: str    raw_evidence_path: Optional[str] = None

    objective: str

    description: str    scanner_output: Optional[str] = None    email: str = Field(unique=True)    approval_reason: Optional[str] = None

    category: str  # e.g., "Access Control", "System Operations"

        evidence_screenshot: Optional[str] = None

    # Implementation guidance

    implementation_guidance: Optional[str] = None    risk_id: Optional[int] = Field(default=None, foreign_key="riskregister.id")    name: str

    testing_procedures: Optional[str] = None

    common_evidence: Optional[str] = None  # JSON array    capa_id: Optional[int] = Field(default=None, foreign_key="capa.id")

    

    # Automation potential        role: Literal["ADMIN", "COMPLIANCE_MANAGER", "AUDITOR", "VIEWER"] = "VIEWER"    approved_by: Optional[str] = NoneApprovalStatus = Literal["PENDING", "APPROVED", "REJECTED"]ApprovalStatus = Literal["PENDING", "APPROVED", "REJECTED"]

    automatable: bool = Field(default=False)

    automation_tools: Optional[str] = None  # JSON array    # Multi-framework compliance mapping

    

    # Metadata    frameworks: Optional[str] = None  # JSON array    org_id: int = Field(foreign_key="organization.id")

    version: str = Field(default="1.0")

    last_updated: datetime = Field(default_factory=datetime.utcnow)    control_mappings: Optional[str] = None  # JSON object



class StatementOfApplicability(SQLModel, table=True):    is_active: bool = Field(default=True)

    """Organization-specific control implementation (SoA)"""

    id: Optional[int] = Field(default=None, primary_key=True)class ScanRun(SQLModel, table=True):

    org_id: int = Field(foreign_key="organization.id")

    control_id: str = Field(foreign_key="controllibrary.control_id")    id: Optional[int] = Field(default=None, primary_key=True)    mfa_enabled: bool = Field(default=False)

    

    # Implementation decision    org_id: int = Field(foreign_key="organization.id")

    status: ControlStatus

    rationale: str = Field(min_length=10)  # Why included/excluded    host: str    last_login: Optional[datetime] = Noneclass ScanRun(SQLModel, table=True):ScanStatus = Literal["RUNNING", "WAITING_APPROVAL", "DONE", "FAILED"]

    implementation_description: Optional[str] = None

    implementation_status: ImplementationStatus = ImplementationStatus.NOT_STARTED    status: str

    

    # Ownership and responsibility    started_at: datetime = Field(default_factory=datetime.utcnow)    created_at: datetime = Field(default_factory=datetime.utcnow)

    owner_id: Optional[int] = Field(default=None, foreign_key="user.id")

    responsible_party: Optional[str] = None    finished_at: Optional[datetime] = None

    

    # Review cycle    report_path: Optional[str] = None        id: Optional[int] = Field(default=None, primary_key=True)

    last_reviewed: datetime = Field(default_factory=datetime.utcnow)

    next_review: datetime    report_hash: Optional[str] = None

    review_frequency_months: int = Field(default=12)

        evidence_package_path: Optional[str] = None    # SSO integration

    # Evidence management

    evidence_required: bool = Field(default=True)    scan_type: Optional[str] = "AUTOMATED"

    evidence_frequency_days: int = Field(default=90)

    last_evidence_date: Optional[datetime] = None    sso_provider: Optional[str] = None  # "google", "azure", "okta"    host: strclass Finding(SQLModel, table=True):Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    evidence_status: Literal["CURRENT", "STALE", "MISSING"] = "MISSING"

    # Statement of Applicability with control ownership

    # Automation

    automated_monitoring: bool = Field(default=False)class StatementOfApplicability(SQLModel, table=True):    sso_id: Optional[str] = None

    automation_tool: Optional[str] = None

    last_automated_check: Optional[datetime] = None    id: Optional[int] = Field(default=None, primary_key=True)

    

    # Version control    org_id: int = Field(foreign_key="organization.id")    status: str  # RUNNING / DONE / FAILED / WAITING_APPROVAL

    version: int = Field(default=1)

    change_log: Optional[str] = None  # JSON array of changes    control_id: str



class Finding(SQLModel, table=True):    control_title: str# Core Finding entity with enterprise features

    """Security and compliance findings with audit trail"""

    id: Optional[int] = Field(default=None, primary_key=True)    control_objective: str

    org_id: int = Field(foreign_key="organization.id")

        framework: ComplianceFramework = "ISO27001"class Finding(SQLModel, table=True):    started_at: datetime = Field(default_factory=datetime.utcnow)    id: Optional[int] = Field(default=None, primary_key=True)

    # Finding identification

    finding_id: str = Field(unique=True, default_factory=lambda: f"FIND-{uuid.uuid4().hex[:8].upper()}")    status: ControlStatus

    title: str = Field(min_length=5, max_length=200)

    description: str = Field(min_length=10)    rationale: str    id: Optional[int] = Field(default=None, primary_key=True)

    

    # Categorization    implementation_description: Optional[str] = None

    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    category: str  # "Security", "Privacy", "Operational"    implementation_status: Literal["NOT_STARTED", "IN_PROGRESS", "IMPLEMENTED", "NEEDS_REVIEW"] = "NOT_STARTED"    org_id: int = Field(foreign_key="organization.id")    finished_at: Optional[datetime] = None

    source: Literal["AUTOMATED_SCAN", "MANUAL_REVIEW", "PENETRATION_TEST", "AUDIT", "INCIDENT"]

        owner_id: Optional[int] = Field(default=None, foreign_key="controlowner.id")

    # Control mapping

    affected_controls: str  # JSON array of control IDs    last_reviewed: datetime = Field(default_factory=datetime.utcnow)    control: str

    control_gaps: Optional[str] = None  # JSON array describing gaps

        next_review: datetime

    # Technical details

    host: Optional[str] = None    version: int = Field(default=1)    severity: str    report_path: Optional[str] = None    control: str

    asset_id: Optional[str] = None

    vulnerability_id: Optional[str] = None  # CVE, etc.    evidence_required: bool = Field(default=True)

    

    # Evidence and proof    evidence_frequency: Literal["CONTINUOUS", "QUARTERLY", "ANNUALLY"] = "ANNUALLY"    title: str

    raw_evidence_hash: Optional[str] = None

    raw_evidence_path: Optional[str] = None    last_evidence_date: Optional[datetime] = None

    scanner_output: Optional[str] = None  # JSON of raw scanner data

    screenshot_path: Optional[str] = None    automated_monitoring: bool = Field(default=False)    detail: str    severity: strclass Finding(SQLModel, table=True):

    log_entries: Optional[str] = None  # JSON array

        automation_tool: Optional[str] = None

    # Approval workflow

    approval_status: ApprovalStatus = ApprovalStatus.PENDING    host: str

    approval_reason: Optional[str] = None

    approved_by: Optional[str] = Noneclass ControlOwner(SQLModel, table=True):

    approval_date: Optional[datetime] = None

        id: Optional[int] = Field(default=None, primary_key=True)    created_at: datetime = Field(default_factory=datetime.utcnow)    title: str    """Security finding with approval workflow"""

    # Risk and remediation

    risk_id: Optional[int] = Field(default=None, foreign_key="riskregister.id")    org_id: int = Field(foreign_key="organization.id")

    capa_id: Optional[int] = Field(default=None, foreign_key="capa.id")

        name: str    approval_status: ApprovalStatus = "PENDING"

    # Compliance framework mapping

    frameworks: str = Field(default='["ISO27001"]')  # JSON array    email: str

    framework_mappings: Optional[str] = None  # JSON object

        role: str    approval_reason: Optional[str] = None    detail: str    id: Optional[int] = Field(default=None, primary_key=True)

    # Lifecycle

    identified_date: datetime = Field(default_factory=datetime.utcnow)    department: str

    target_resolution_date: Optional[datetime] = None

    actual_resolution_date: Optional[datetime] = None    is_active: bool = Field(default=True)    approved_by: Optional[str] = None

    status: Literal["OPEN", "IN_REMEDIATION", "RESOLVED", "ACCEPTED", "FALSE_POSITIVE"] = "OPEN"

        notification_preferences: Optional[str] = None

    # Metadata

    created_by: str        host: str    control: str = Field(description="ISO 27001 control reference (e.g., A.12.6)")

    last_updated: datetime = Field(default_factory=datetime.utcnow)

    tags: Optional[str] = None  # JSON array# Risk Register with time-boxed acceptance



class RiskRegister(SQLModel, table=True):class RiskRegister(SQLModel, table=True):    # Evidence & audit trail (Vanta-style immutable evidence)

    """Enterprise risk register with time-boxed acceptance"""

    id: Optional[int] = Field(default=None, primary_key=True)    id: Optional[int] = Field(default=None, primary_key=True)

    org_id: int = Field(foreign_key="organization.id")

        org_id: int = Field(foreign_key="organization.id")    raw_evidence_hash: Optional[str] = None    created_at: datetime = Field(default_factory=datetime.utcnow)    severity: Severity = Field(description="Finding severity level")

    # Risk identification

    risk_id: str = Field(unique=True, default_factory=lambda: f"RISK-{datetime.now().year}-{uuid.uuid4().hex[:6].upper()}")    risk_id: str

    title: str = Field(min_length=5, max_length=200)

    description: str = Field(min_length=10)    title: str    raw_evidence_path: Optional[str] = None

    category: str  # "Cybersecurity", "Operational", "Strategic", "Financial", "Compliance"

    subcategory: Optional[str] = None    description: str

    

    # Business context    category: str    scanner_output: Optional[str] = None  # JSON string of raw scanner output    approval_status: ApprovalStatus = "PENDING"    title: str = Field(description="Brief finding title")

    business_process: Optional[str] = None

    asset_impacted: Optional[str] = None    business_process: Optional[str] = None

    stakeholder: Optional[str] = None

        inherent_likelihood: int = Field(ge=1, le=5)    evidence_screenshot: Optional[str] = None

    # Risk assessment (5x5 matrix)

    inherent_likelihood: int = Field(ge=1, le=5)    inherent_impact: int = Field(ge=1, le=5)

    inherent_impact: int = Field(ge=1, le=5)

    inherent_risk_score: int  # calculated: likelihood * impact    inherent_risk_score: int    risk_id: Optional[int] = Field(default=None, foreign_key="riskregister.id")    approval_reason: Optional[str] = None    detail: str = Field(description="Detailed finding description")

    

    residual_likelihood: int = Field(ge=1, le=5)    residual_likelihood: int = Field(ge=1, le=5)

    residual_impact: int = Field(ge=1, le=5) 

    residual_risk_score: int  # calculated: likelihood * impact    residual_impact: int = Field(ge=1, le=5)    capa_id: Optional[int] = Field(default=None, foreign_key="capa.id")

    

    # Risk appetite and tolerance    residual_risk_score: int

    risk_appetite_threshold: int = Field(default=15)

    exceeds_appetite: bool = Field(default=False)    risk_appetite_threshold: int = Field(default=15)        approved_by: Optional[str] = None    host: str = Field(description="Target host/system")

    

    # Status and ownership    status: RiskStatus = "OPEN"

    status: RiskStatus = RiskStatus.OPEN

    owner_id: int = Field(foreign_key="user.id")    owner_id: Optional[int] = Field(default=None, foreign_key="controlowner.id")    # Compliance mapping (multi-framework like Scrut.io)

    responsible_party: Optional[str] = None

        identified_date: datetime = Field(default_factory=datetime.utcnow)

    # Timeline management

    identified_date: datetime = Field(default_factory=datetime.utcnow)    target_closure_date: Optional[datetime] = None    frameworks: Optional[str] = None  # JSON array of applicable frameworks    

    target_closure_date: Optional[datetime] = None

    actual_closure_date: Optional[datetime] = None    actual_closure_date: Optional[datetime] = None

    

    # Risk acceptance (time-boxed)    risk_acceptance_expiry: Optional[datetime] = None    control_mappings: Optional[str] = None  # JSON object mapping to different frameworks

    risk_acceptance_expiry: Optional[datetime] = None

    risk_acceptance_approver: Optional[str] = None    risk_acceptance_approver: Optional[str] = None

    risk_acceptance_reason: Optional[str] = None

    risk_acceptance_conditions: Optional[str] = None  # JSON array    risk_acceptance_reason: Optional[str] = None    class ScanRun(SQLModel, table=True):    # Organization context

    acceptance_review_date: Optional[datetime] = None

        risk_acceptance_conditions: Optional[str] = None

    # Review schedule

    last_reviewed: datetime = Field(default_factory=datetime.utcnow)    last_reviewed: datetime = Field(default_factory=datetime.utcnow)    # Relationships

    review_frequency_days: int = Field(default=90)

    next_review_date: Optional[datetime] = None    review_frequency_days: int = Field(default=90)

    

    # Control relationships    next_review_date: Optional[datetime] = None    risk: Optional["RiskRegister"] = Relationship(back_populates="findings")    id: Optional[int] = Field(default=None, primary_key=True)    company_id: int = Field(foreign_key="company.id")

    affected_controls: Optional[str] = None  # JSON array of control IDs

    existing_controls: Optional[str] = None  # JSON array of controls already in place    affected_controls: Optional[str] = None

    planned_controls: Optional[str] = None  # JSON array of planned mitigations

        mitigating_controls: Optional[str] = None    capa: Optional["CAPA"] = Relationship(back_populates="finding")

    # External factors

    regulatory_requirement: bool = Field(default=False)

    customer_requirement: bool = Field(default=False)

    contractual_requirement: bool = Field(default=False)# CAPA with verification workflow    host: str    project_id: Optional[int] = Field(foreign_key="project.id")

    

    # Metadataclass CAPA(SQLModel, table=True):

    created_by: str

    last_updated: datetime = Field(default_factory=datetime.utcnow)    id: Optional[int] = Field(default=None, primary_key=True)class ScanRun(SQLModel, table=True):

    change_log: Optional[str] = None  # JSON array

    org_id: int = Field(foreign_key="organization.id")

class CAPA(SQLModel, table=True):

    """Corrective and Preventive Actions with verification workflow"""    capa_id: str = Field(unique=True)    id: Optional[int] = Field(default=None, primary_key=True)    status: str  # RUNNING / DONE / FAILED / WAITING_APPROVAL    

    id: Optional[int] = Field(default=None, primary_key=True)

    org_id: int = Field(foreign_key="organization.id")    title: str

    

    # CAPA identification    description: str    org_id: int = Field(foreign_key="organization.id")

    capa_id: str = Field(unique=True, default_factory=lambda: f"CAPA-{datetime.now().year}-{uuid.uuid4().hex[:6].upper()}")

    title: str = Field(min_length=5, max_length=200)    action_type: Literal["CORRECTIVE", "PREVENTIVE", "BOTH"]

    description: str = Field(min_length=10)

        priority: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]    host: str    started_at: datetime = Field(default_factory=datetime.utcnow)    created_at: datetime = Field(default_factory=datetime.utcnow)

    # Type and priority

    action_type: Literal["CORRECTIVE", "PREVENTIVE", "BOTH"]    status: CAPAStatus = "OPEN"

    priority: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    status: CAPAStatus = CAPAStatus.OPEN    assigned_to: str    status: str  # RUNNING / DONE / FAILED / WAITING_APPROVAL

    

    # Root cause analysis    created_by: str

    root_cause: Optional[str] = None

    contributing_factors: Optional[str] = None  # JSON array    due_date: datetime    started_at: datetime = Field(default_factory=datetime.utcnow)    finished_at: Optional[datetime] = None    

    

    # Assignment and accountability    completion_date: Optional[datetime] = None

    assigned_to: str  # User email

    backup_assignee: Optional[str] = None    estimated_effort_hours: Optional[int] = None    finished_at: Optional[datetime] = None

    created_by: str

    approver: Optional[str] = None    actual_effort_hours: Optional[int] = None

    

    # Timeline and effort    verification_required: bool = Field(default=True)    report_path: Optional[str] = None    report_path: Optional[str] = None    # Approval workflow fields

    due_date: datetime

    estimated_effort_hours: Optional[int] = None    verified_by: Optional[str] = None

    actual_effort_hours: Optional[int] = None

    completion_date: Optional[datetime] = None    verification_date: Optional[datetime] = None    report_hash: Optional[str] = None    approval_status: ApprovalStatus = Field(default="PENDING")

    

    # Implementation tracking    verification_evidence: Optional[str] = None

    action_plan: Optional[str] = None  # JSON array of steps

    progress_percentage: int = Field(default=0, ge=0, le=100)    verification_comments: Optional[str] = None    evidence_package_path: Optional[str] = None    approval_reason: Optional[str] = Field(default=None, description="Approval/rejection reason")

    milestones: Optional[str] = None  # JSON array

    dependencies: Optional[str] = None  # JSON array    progress_percentage: int = Field(default=0, ge=0, le=100)

    

    # Verification workflow    last_update: datetime = Field(default_factory=datetime.utcnow)    scan_type: Optional[str] = "AUTOMATED"  # AUTOMATED, MANUAL, CONTINUOUS    approved_by: Optional[str] = Field(default=None, description="Approver email/identifier")

    verification_required: bool = Field(default=True)

    verification_criteria: Optional[str] = None    update_comments: Optional[str] = None

    verified_by: Optional[str] = None

    verification_date: Optional[datetime] = None    finding_id: Optional[int] = Field(default=None, foreign_key="finding.id")    approved_at: Optional[datetime] = Field(default=None, description="Approval timestamp")

    verification_evidence: Optional[str] = None

    verification_comments: Optional[str] = None    risk_id: Optional[int] = Field(default=None, foreign_key="riskregister.id")

    

    # Effectiveness validation    control_id: Optional[str] = None# ISO 27001 Statement of Applicability (Vanta-style control management)    

    effectiveness_review_due: Optional[datetime] = None

    effectiveness_validated: bool = Field(default=False)

    effectiveness_comments: Optional[str] = None

    # BC/DR Drill tracking with RTO/RPO metricsclass StatementOfApplicability(SQLModel, table=True):    # Additional metadata

    # Linkages

    finding_id: Optional[int] = Field(default=None, foreign_key="finding.id")class BCDRDrill(SQLModel, table=True):

    risk_id: Optional[int] = Field(default=None, foreign_key="riskregister.id")

    related_controls: Optional[str] = None  # JSON array of control IDs    id: Optional[int] = Field(default=None, primary_key=True)    id: Optional[int] = Field(default=None, primary_key=True)    scan_run_id: Optional[int] = Field(default=None, foreign_key="scanrun.id")

    

    # Communication and updates    org_id: int = Field(foreign_key="organization.id")

    stakeholder_notification: bool = Field(default=False)

    last_update: datetime = Field(default_factory=datetime.utcnow)    drill_id: str = Field(unique=True)    org_id: int = Field(foreign_key="organization.id")    evidence: Optional[str] = Field(default=None, description="Supporting evidence/logs")

    update_comments: Optional[str] = None

    escalation_triggered: bool = Field(default=False)    drill_type: Literal["BACKUP_RESTORE", "FAILOVER", "TABLETOP", "FULL_SCALE", "COMMUNICATION"]



# Helper functions for enterprise operations    scenario: str    control_id: str  # e.g., "A.5.1.1"    remediation: Optional[str] = Field(default=None, description="Suggested remediation")

def generate_evidence_hash(data: bytes) -> str:

    """Generate SHA-256 hash for evidence integrity"""    scope: str

    return hashlib.sha256(data).hexdigest()

    planned_date: datetime    control_title: str    

def create_audit_trail_entry(

    user_id: str,    planned_duration_minutes: int

    action: str,

    resource_type: str,    participants: str  # JSON array    control_objective: str    # ISO 27001 specific

    resource_id: str,

    details: Optional[dict] = None,    actual_date: Optional[datetime] = None

    timestamp: Optional[datetime] = None,

    source_ip: Optional[str] = None    actual_duration_minutes: Optional[int] = None    framework: ComplianceFramework = "ISO27001"    control_family: Optional[str] = Field(default=None, description="Control family (e.g., Access Control)")

) -> dict:

    """Create standardized audit trail entry"""    rto_target_minutes: int

    return {

        "user_id": user_id,    rpo_target_minutes: int    status: ControlStatus    risk_score: Optional[float] = Field(default=None, description="Calculated risk score")

        "action": action,

        "resource_type": resource_type,    rto_actual_minutes: Optional[int] = None

        "resource_id": resource_id,

        "details": details or {},    rpo_actual_minutes: Optional[int] = None    rationale: str  # Why included/excluded

        "timestamp": (timestamp or datetime.utcnow()).isoformat(),

        "source_ip": source_ip    success: Optional[bool] = None

    }

    success_criteria_met: Optional[str] = None    implementation_description: Optional[str] = None

def calculate_risk_score(likelihood: int, impact: int) -> int:

    """Calculate risk score using 5x5 matrix"""    issues_identified: Optional[str] = None

    return likelihood * impact

    lessons_learned: Optional[str] = None    implementation_status: Literal["NOT_STARTED", "IN_PROGRESS", "IMPLEMENTED", "NEEDS_REVIEW"] = "NOT_STARTED"class ScanRun(SQLModel, table=True):

def determine_risk_level(score: int) -> str:

    """Determine risk level based on score (1-25 scale)"""    recommendations: Optional[str] = None

    if score >= 20:

        return "CRITICAL"    conducted_by: str    owner_id: Optional[int] = Field(default=None, foreign_key="controlowner.id")    """Scan execution record"""

    elif score >= 15:

        return "HIGH"    verified_by: Optional[str] = None

    elif score >= 10:

        return "MEDIUM"    approval_date: Optional[datetime] = None    last_reviewed: datetime = Field(default_factory=datetime.utcnow)    id: Optional[int] = Field(default=None, primary_key=True)

    elif score >= 5:

        return "LOW"    evidence_files: Optional[str] = None

    else:

        return "VERY_LOW"    drill_report_path: Optional[str] = None    next_review: datetime    host: str = Field(description="Target host/system")



def get_next_review_date(current_date: datetime, frequency_months: int) -> datetime:

    """Calculate next review date based on frequency"""

    return current_date + timedelta(days=frequency_months * 30)# Data Inventory for GDPR/DPDP compliance    version: int = Field(default=1)    status: ScanStatus = Field(default="RUNNING")



def is_capa_overdue(due_date: datetime, completion_date: Optional[datetime] = None) -> bool:class DataInventory(SQLModel, table=True):

    """Check if CAPA is overdue"""

    if completion_date:    id: Optional[int] = Field(default=None, primary_key=True)        

        return False

    return datetime.utcnow() > due_date    org_id: int = Field(foreign_key="organization.id")

    system_name: str    # Evidence linkage    # Organization context

    system_owner: str

    data_category: str    evidence_required: bool = Field(default=True)    company_id: int = Field(foreign_key="company.id")

    data_types: str  # JSON array

    classification: DataClassification    evidence_frequency: Literal["CONTINUOUS", "QUARTERLY", "ANNUALLY"] = "ANNUALLY"    project_id: Optional[int] = Field(foreign_key="project.id")

    lawful_basis: LawfulBasis

    lawful_basis_details: Optional[str] = None    last_evidence_date: Optional[datetime] = None    

    purpose: str

    legitimate_interests_assessment: Optional[str] = None        # Timing

    retention_period_months: int

    retention_justification: str    # Automation status (Secureframe-style)    started_at: datetime = Field(default_factory=datetime.utcnow)

    disposal_method: Optional[str] = None

    data_subjects: str    automated_monitoring: bool = Field(default=False)    finished_at: Optional[datetime] = Field(default=None)

    data_location: str

    cross_border_transfers: bool = Field(default=False)    automation_tool: Optional[str] = None    

    transfer_mechanism: Optional[str] = None

    adequacy_decision: Optional[str] = None        # Results

    data_processor: Optional[str] = None

    third_party_sharing: bool = Field(default=False)    # Relationships    findings_count: int = Field(default=0, description="Total findings discovered")

    sharing_details: Optional[str] = None

    encryption_at_rest: bool = Field(default=False)    owner: Optional["ControlOwner"] = Relationship(back_populates="controls")    high_severity_count: int = Field(default=0, description="Count of high/critical findings")

    encryption_in_transit: bool = Field(default=False)

    access_controls: Optional[str] = None    report_path: Optional[str] = Field(default=None, description="Generated report file path")

    backup_locations: Optional[str] = None

    supports_access_requests: bool = Field(default=False)class ControlOwner(SQLModel, table=True):    

    supports_portability: bool = Field(default=False)

    supports_deletion: bool = Field(default=False)    id: Optional[int] = Field(default=None, primary_key=True)    # Execution metadata

    supports_rectification: bool = Field(default=False)

    last_reviewed: datetime = Field(default_factory=datetime.utcnow)    org_id: int = Field(foreign_key="organization.id")    initiated_by: Optional[str] = Field(default=None, description="User who started the scan")

    next_review: datetime

    dpo_approved: bool = Field(default=False)    name: str    scan_config: Optional[str] = Field(default=None, description="JSON scan configuration")

    dpo_approval_date: Optional[datetime] = None

    privacy_impact_assessment: Optional[str] = None    email: str    



# Access Exceptions with time-boxing    role: str    # AI/LangGraph state

class AccessException(SQLModel, table=True):

    id: Optional[int] = Field(default=None, primary_key=True)    department: str    graph_state: Optional[str] = Field(default=None, description="Serialized LangGraph state")

    org_id: int = Field(foreign_key="organization.id")

    user_email: str    is_active: bool = Field(default=True)    error_message: Optional[str] = Field(default=None, description="Error details if failed")

    exception_type: Literal["MFA_BYPASS", "PRIVILEGED_ACCESS", "EMERGENCY_ACCESS", "TEMPORARY_ELEVATION"]

    system_name: str    notification_preferences: Optional[str] = None  # JSON object

    justification: str

    business_justification: Optional[str] = None    

    requested_by: str

    approved_by: str    # Relationshipsclass ControlMapping(SQLModel, table=True):

    approval_date: datetime

    start_date: datetime    controls: List["StatementOfApplicability"] = Relationship(back_populates="owner")    """ISO 27001 control definitions and mappings"""

    end_date: datetime

    actual_end_date: Optional[datetime] = None    id: Optional[int] = Field(default=None, primary_key=True)

    extension_requested: bool = Field(default=False)

    extension_approved: bool = Field(default=False)# Risk Management (Sprinto-style risk register)    control_id: str = Field(unique=True, description="ISO control ID (e.g., A.12.6.1)")

    access_reviewed: bool = Field(default=False)

    review_date: Optional[datetime] = Noneclass RiskRegister(SQLModel, table=True):    control_name: str = Field(description="Control name")

    reviewer: Optional[str] = None

    review_comments: Optional[str] = None    id: Optional[int] = Field(default=None, primary_key=True)    control_description: str = Field(description="Full control description")

    risk_level: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"

    compensating_controls: Optional[str] = None    org_id: int = Field(foreign_key="organization.id")    control_family: str = Field(description="Control family/category")

    monitoring_requirements: Optional[str] = None

    risk_id: str  # e.g., "RISK-2024-001"    

# Immutable Audit Evidence

class AuditEvidence(SQLModel, table=True):    title: str    # Implementation guidance

    id: Optional[int] = Field(default=None, primary_key=True)

    org_id: int = Field(foreign_key="organization.id")    description: str    implementation_guidance: Optional[str] = Field(default=None)

    evidence_id: str = Field(unique=True)

    control_id: str    category: str  # e.g., "Cybersecurity", "Operational", "Compliance"    testing_procedures: Optional[str] = Field(default=None)

    framework: ComplianceFramework = "ISO27001"

    evidence_type: Literal["DOCUMENT", "SCREENSHOT", "LOG_FILE", "CONFIGURATION", "INTERVIEW", "OBSERVATION", "AUTOMATED_CHECK"]    business_process: Optional[str] = None    

    title: str

    description: str    inherent_likelihood: int = Field(ge=1, le=5)    # Automation mapping

    file_path: Optional[str] = None

    file_hash: Optional[str] = None    inherent_impact: int = Field(ge=1, le=5)    scanner_types: Optional[str] = Field(default=None, description="JSON list of applicable scanners")

    file_size_bytes: Optional[int] = None

    mime_type: Optional[str] = None    inherent_risk_score: int  # likelihood * impact    severity_mapping: Optional[str] = Field(default=None, description="JSON severity rules")

    collected_by: str

    collection_method: Literal["MANUAL", "AUTOMATED", "IMPORTED"] = "MANUAL"    residual_likelihood: int = Field(ge=1, le=5)

    collected_date: datetime = Field(default_factory=datetime.utcnow)

    evidence_date: datetime    residual_impact: int = Field(ge=1, le=5)

    retention_until: datetime

    immutable_storage: bool = Field(default=True)    residual_risk_score: intclass Company(SQLModel, table=True):

    storage_location: Optional[str] = None

    audit_trail: Optional[str] = None    risk_appetite_threshold: int = Field(default=15)  # Organization's risk appetite    """Company/Organization model"""

    access_count: int = Field(default=0)

    last_accessed: Optional[datetime] = None    status: RiskStatus = "OPEN"    id: Optional[int] = Field(default=None, primary_key=True)

    tags: Optional[str] = None

    related_finding_id: Optional[int] = None    owner_id: Optional[int] = Field(default=None, foreign_key="controlowner.id")    name: str = Field(description="Company name")

    related_risk_id: Optional[int] = None

        domain: str = Field(unique=True, description="Company email domain (e.g., company.com)")

# Management Review records

class ManagementReview(SQLModel, table=True):    # Timeline    industry: Optional[str] = Field(default=None, description="Industry type")

    id: Optional[int] = Field(default=None, primary_key=True)

    org_id: int = Field(foreign_key="organization.id")    identified_date: datetime = Field(default_factory=datetime.utcnow)    size: Optional[Literal["STARTUP", "SME", "ENTERPRISE"]] = Field(default=None)

    review_period: str

    review_date: datetime    target_closure_date: Optional[datetime] = None    country: Optional[str] = Field(default=None)

    meeting_type: Literal["QUARTERLY", "ANNUAL", "AD_HOC"] = "QUARTERLY"

    attendees: str  # JSON array    actual_closure_date: Optional[datetime] = None    

    chairman: str

    kpis_reviewed: str  # JSON object        # Subscription/billing

    risks_reviewed: int

    new_risks_identified: int = Field(default=0)    # Risk acceptance (time-boxed like Drata)    subscription_plan: Literal["FREE", "BASIC", "PREMIUM", "ENTERPRISE"] = Field(default="FREE")

    capas_reviewed: int

    capas_closed: int = Field(default=0)    risk_acceptance_expiry: Optional[datetime] = None    subscription_status: Literal["ACTIVE", "SUSPENDED", "CANCELLED"] = Field(default="ACTIVE")

    security_incidents: int = Field(default=0)

    compliance_score: Optional[float] = None    risk_acceptance_approver: Optional[str] = None    

    audit_findings: int = Field(default=0)

    policy_changes: Optional[str] = None    risk_acceptance_reason: Optional[str] = None    # Settings

    budget_allocated: Optional[float] = None

    resource_changes: Optional[str] = None    risk_acceptance_conditions: Optional[str] = None  # JSON array    is_active: bool = Field(default=True)

    objectives_next_period: Optional[str] = None

    strategic_decisions: Optional[str] = None        created_at: datetime = Field(default_factory=datetime.utcnow)

    minutes_location: Optional[str] = None

    presentation_path: Optional[str] = None    # Review schedule    updated_at: Optional[datetime] = Field(default=None)

    action_items: Optional[str] = None

    approved_by: str    last_reviewed: datetime = Field(default_factory=datetime.utcnow)

    approval_date: datetime

    next_review_date: datetime    review_frequency_days: int = Field(default=90)



# Helper functions    next_review_date: Optional[datetime] = Noneclass Project(SQLModel, table=True):

def generate_evidence_hash(data: str) -> str:

    """Generate SHA-256 hash for evidence integrity"""        """Project/Application model within a company"""

    return hashlib.sha256(data.encode()).hexdigest()

    # Controls mapping    id: Optional[int] = Field(default=None, primary_key=True)

def create_audit_trail_entry(user: str, action: str, timestamp: datetime = None, source_ip: str = None) -> dict:

    """Create standardized audit trail entry"""    affected_controls: Optional[str] = None  # JSON array of control IDs    name: str = Field(description="Project name")

    return {

        "user": user,    mitigating_controls: Optional[str] = None  # JSON array of control IDs    description: Optional[str] = Field(default=None)

        "action": action,

        "timestamp": (timestamp or datetime.utcnow()).isoformat(),        company_id: int = Field(foreign_key="company.id")

        "source_ip": source_ip

    }    # Relationships    

    findings: List["Finding"] = Relationship(back_populates="risk")    # Project settings

    capas: List["CAPA"] = Relationship(back_populates="risk")    environment: Literal["DEVELOPMENT", "STAGING", "PRODUCTION"] = Field(default="PRODUCTION")

    criticality: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(default="MEDIUM")

# CAPA Management (Corrective and Preventive Actions - Scytale.ai style)    compliance_frameworks: Optional[str] = Field(default=None, description="JSON list of frameworks")

class CAPA(SQLModel, table=True):    

    id: Optional[int] = Field(default=None, primary_key=True)    # URLs and endpoints

    org_id: int = Field(foreign_key="organization.id")    primary_url: Optional[str] = Field(default=None, description="Main application URL")

    capa_id: str = Field(unique=True)  # e.g., "CAPA-2024-001"    api_endpoints: Optional[str] = Field(default=None, description="JSON list of API endpoints")

    title: str    

    description: str    # Repository info

    action_type: Literal["CORRECTIVE", "PREVENTIVE", "BOTH"]    repository_url: Optional[str] = Field(default=None)

    priority: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]    deployment_info: Optional[str] = Field(default=None, description="JSON deployment details")

    status: CAPAStatus = "OPEN"    

        is_active: bool = Field(default=True)

    # Assignment and timeline    created_at: datetime = Field(default_factory=datetime.utcnow)

    assigned_to: str  # email    created_by: Optional[str] = Field(default=None)

    created_by: str

    due_date: datetime

    completion_date: Optional[datetime] = Noneclass User(SQLModel, table=True):

    estimated_effort_hours: Optional[int] = None    """User model with company and role association"""

    actual_effort_hours: Optional[int] = None    id: Optional[int] = Field(default=None, primary_key=True)

        email: str = Field(unique=True, description="User email")

    # Verification workflow    name: str = Field(description="Full name")

    verification_required: bool = Field(default=True)    company_id: Optional[int] = Field(foreign_key="company.id")

    verified_by: Optional[str] = None    

    verification_date: Optional[datetime] = None    # Authentication

    verification_evidence: Optional[str] = None    hashed_password: Optional[str] = Field(default=None, description="Hashed password for email signup")

    verification_comments: Optional[str] = None    google_id: Optional[str] = Field(default=None, description="Google OAuth ID")

        auth_provider: Literal["EMAIL", "GOOGLE", "SSO"] = Field(default="EMAIL")

    # Progress tracking    

    progress_percentage: int = Field(default=0, ge=0, le=100)    # Profile

    last_update: datetime = Field(default_factory=datetime.utcnow)    job_title: Optional[str] = Field(default=None)

    update_comments: Optional[str] = None    phone: Optional[str] = Field(default=None)

        timezone: Optional[str] = Field(default="UTC")

    # Linkages    

    finding_id: Optional[int] = Field(default=None, foreign_key="finding.id")    # Permissions

    risk_id: Optional[int] = Field(default=None, foreign_key="riskregister.id")    role: Literal["OWNER", "ADMIN", "SECURITY_OFFICER", "ANALYST", "VIEWER"] = Field(default="VIEWER")

    control_id: Optional[str] = None  # ISO control reference    permissions: Optional[str] = Field(default=None, description="JSON permissions object")

        

    # Relationships    # Status

    finding: Optional["Finding"] = Relationship(back_populates="capa")    is_active: bool = Field(default=True)

    risk: Optional["RiskRegister"] = Relationship(back_populates="capas")    is_verified: bool = Field(default=False)

    last_login: Optional[datetime] = Field(default=None)

# Business Continuity & Disaster Recovery (Delve.co style)    created_at: datetime = Field(default_factory=datetime.utcnow)

class BCDRDrill(SQLModel, table=True):    

    id: Optional[int] = Field(default=None, primary_key=True)    # Project access

    org_id: int = Field(foreign_key="organization.id")    accessible_projects: Optional[str] = Field(default=None, description="JSON list of project IDs")

    drill_id: str = Field(unique=True)

    drill_type: Literal["BACKUP_RESTORE", "FAILOVER", "TABLETOP", "FULL_SCALE", "COMMUNICATION"]

    scenario: strclass UserRole(SQLModel, table=True):

    scope: str  # What systems/processes are included    """User roles and permissions (legacy - keeping for compatibility)"""

        id: Optional[int] = Field(default=None, primary_key=True)

    # Planning    user_email: str = Field(unique=True, description="User email identifier")

    planned_date: datetime    role: Literal["VIEWER", "APPROVER", "ADMIN"] = Field(description="User role")

    planned_duration_minutes: int    created_at: datetime = Field(default_factory=datetime.utcnow)

    participants: str  # JSON array of participants    created_by: Optional[str] = Field(default=None)

        is_active: bool = Field(default=True)

    # Execution

    actual_date: Optional[datetime] = None

    actual_duration_minutes: Optional[int] = Noneclass AuditLog(SQLModel, table=True):

        """Audit trail for compliance"""

    # Objectives and metrics    id: Optional[int] = Field(default=None, primary_key=True)

    rto_target_minutes: int  # Recovery Time Objective    timestamp: datetime = Field(default_factory=datetime.utcnow)

    rpo_target_minutes: int  # Recovery Point Objective    user_email: str = Field(description="User performing action")

    rto_actual_minutes: Optional[int] = None    action: str = Field(description="Action performed")

    rpo_actual_minutes: Optional[int] = None    resource_type: str = Field(description="Type of resource (finding, scan, etc.)")

        resource_id: Optional[str] = Field(default=None, description="Resource identifier")

    # Results    details: Optional[str] = Field(default=None, description="JSON action details")

    success: Optional[bool] = None    ip_address: Optional[str] = Field(default=None, description="User IP address")

    success_criteria_met: Optional[str] = None  # JSON array of criteria    user_agent: Optional[str] = Field(default=None, description="User agent string")

    issues_identified: Optional[str] = None  # JSON array

    lessons_learned: Optional[str] = None

    recommendations: Optional[str] = None  # JSON array# Pydantic models for API requests/responses

    class CompanyCreate(SQLModel):

    # Approval    """Request model for creating companies"""

    conducted_by: str    name: str

    verified_by: Optional[str] = None    domain: str

    approval_date: Optional[datetime] = None    industry: Optional[str] = None

        size: Optional[Literal["STARTUP", "SME", "ENTERPRISE"]] = None

    # Evidence    country: Optional[str] = None

    evidence_files: Optional[str] = None  # JSON array of file paths

    drill_report_path: Optional[str] = None

class UserSignup(SQLModel):

# Data Protection & Privacy (TryComp.ai style privacy compliance)    """Request model for user signup"""

class DataInventory(SQLModel, table=True):    email: str

    id: Optional[int] = Field(default=None, primary_key=True)    name: str

    org_id: int = Field(foreign_key="organization.id")    password: Optional[str] = None  # For email signup

    system_name: str    company_name: Optional[str] = None  # For new company creation

    system_owner: str    company_domain: Optional[str] = None

    data_category: str  # e.g., "Customer PII", "Employee Data", "Financial"    job_title: Optional[str] = None

    data_types: str  # JSON array e.g., ["name", "email", "phone"]    auth_provider: Literal["EMAIL", "GOOGLE"] = "EMAIL"

    classification: DataClassification    google_token: Optional[str] = None  # For Google signup

    

    # Legal basis and compliance

    lawful_basis: LawfulBasisclass UserLogin(SQLModel):

    lawful_basis_details: Optional[str] = None    """Request model for user login"""

    purpose: str    email: str

    legitimate_interests_assessment: Optional[str] = None  # If applicable    password: Optional[str] = None

        google_token: Optional[str] = None

    # Retention and disposal    auth_provider: Literal["EMAIL", "GOOGLE"] = "EMAIL"

    retention_period_months: int

    retention_justification: str

    disposal_method: Optional[str] = Noneclass ProjectCreate(SQLModel):

        """Request model for creating projects"""

    # Data subjects and location    name: str

    data_subjects: str  # e.g., "Customers", "Employees"    description: Optional[str] = None

    data_location: str  # e.g., "EU", "India", "Global"    environment: Literal["DEVELOPMENT", "STAGING", "PRODUCTION"] = "PRODUCTION"

    cross_border_transfers: bool = Field(default=False)    criticality: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"

    transfer_mechanism: Optional[str] = None  # e.g., "Standard Contractual Clauses"    primary_url: Optional[str] = None

    adequacy_decision: Optional[str] = None    repository_url: Optional[str] = None

    

    # Processing and sharing

    data_processor: Optional[str] = Noneclass UserResponse(SQLModel):

    third_party_sharing: bool = Field(default=False)    """Response model for user data"""

    sharing_details: Optional[str] = None  # JSON array    id: int

        email: str

    # Security measures    name: str

    encryption_at_rest: bool = Field(default=False)    company_id: Optional[int]

    encryption_in_transit: bool = Field(default=False)    role: str

    access_controls: Optional[str] = None  # JSON description    job_title: Optional[str]

    backup_locations: Optional[str] = None  # JSON array    is_verified: bool

        created_at: datetime

    # Privacy rights support

    supports_access_requests: bool = Field(default=False)

    supports_portability: bool = Field(default=False)class AuthResponse(SQLModel):

    supports_deletion: bool = Field(default=False)    """Response model for authentication"""

    supports_rectification: bool = Field(default=False)    access_token: str

        token_type: str = "bearer"

    # Review and approval    user: UserResponse

    last_reviewed: datetime = Field(default_factory=datetime.utcnow)    company: Optional[dict] = None

    next_review: datetime

    dpo_approved: bool = Field(default=False)

    dpo_approval_date: Optional[datetime] = Noneclass FindingCreate(SQLModel):

    privacy_impact_assessment: Optional[str] = None  # Path to PIA    """Request model for creating findings"""

    control: str

# Access Management and Exceptions (MFA bypass tracking)    severity: Severity

class AccessException(SQLModel, table=True):    title: str

    id: Optional[int] = Field(default=None, primary_key=True)    detail: str

    org_id: int = Field(foreign_key="organization.id")    host: str

    user_email: str    company_id: int

    exception_type: Literal["MFA_BYPASS", "PRIVILEGED_ACCESS", "EMERGENCY_ACCESS", "TEMPORARY_ELEVATION"]    project_id: Optional[int] = None

    system_name: str    evidence: Optional[str] = None

    justification: str    remediation: Optional[str] = None

    business_justification: Optional[str] = None

    

    # Approval workflowclass FindingUpdate(SQLModel):

    requested_by: str    """Request model for updating findings"""

    approved_by: str    approval_status: ApprovalStatus

    approval_date: datetime    approval_reason: str

        approved_by: str

    # Timeline

    start_date: datetime

    end_date: datetimeclass ScanRequest(SQLModel):

    actual_end_date: Optional[datetime] = None    """Request model for starting scans"""

    extension_requested: bool = Field(default=False)    host: str = Field(description="Target host to scan")

    extension_approved: bool = Field(default=False)    company_id: int

        project_id: Optional[int] = None

    # Monitoring and review    scan_types: Optional[list[str]] = Field(default=None, description="Specific scan types to run")

    access_reviewed: bool = Field(default=False)    initiated_by: Optional[str] = Field(default=None, description="User initiating scan")

    review_date: Optional[datetime] = None

    reviewer: Optional[str] = None

    review_comments: Optional[str] = Noneclass ScanResponse(SQLModel):

        """Response model for scan operations"""

    # Risk assessment    run_id: int

    risk_level: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"    status: ScanStatus

    compensating_controls: Optional[str] = None  # JSON array    requires_approval: bool = False

    monitoring_requirements: Optional[str] = None    findings_count: int = 0

    message: Optional[str] = None
# Audit Evidence (Immutable evidence storage like Vanta)
class AuditEvidence(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id")
    evidence_id: str = Field(unique=True)
    control_id: str  # ISO control reference
    framework: ComplianceFramework = "ISO27001"
    evidence_type: Literal["DOCUMENT", "SCREENSHOT", "LOG_FILE", "CONFIGURATION", "INTERVIEW", "OBSERVATION", "AUTOMATED_CHECK"]
    title: str
    description: str
    
    # File and integrity
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    file_size_bytes: Optional[int] = None
    mime_type: Optional[str] = None
    
    # Collection metadata
    collected_by: str
    collection_method: Literal["MANUAL", "AUTOMATED", "IMPORTED"] = "MANUAL"
    collected_date: datetime = Field(default_factory=datetime.utcnow)
    evidence_date: datetime  # When the evidence was created/valid
    
    # Retention and storage
    retention_until: datetime
    immutable_storage: bool = Field(default=True)
    storage_location: Optional[str] = None  # S3 bucket, etc.
    
    # Audit trail and access
    audit_trail: Optional[str] = None  # JSON of access/modification log
    access_count: int = Field(default=0)
    last_accessed: Optional[datetime] = None
    
    # Relationships and tags
    tags: Optional[str] = None  # JSON array for categorization
    related_finding_id: Optional[int] = None
    related_risk_id: Optional[int] = None

# Management Review (Quarterly business reviews)
class ManagementReview(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id")
    review_period: str  # e.g., "Q4-2024"
    review_date: datetime
    meeting_type: Literal["QUARTERLY", "ANNUAL", "AD_HOC"] = "QUARTERLY"
    
    # Participants
    attendees: str  # JSON array of attendees with roles
    chairman: str  # Usually CEO or equivalent
    
    # Review content
    kpis_reviewed: str  # JSON object of KPIs and their values
    risks_reviewed: int  # Number of risks reviewed
    new_risks_identified: int = Field(default=0)
    capas_reviewed: int  # Number of CAPAs reviewed
    capas_closed: int = Field(default=0)
    
    # Performance metrics
    security_incidents: int = Field(default=0)
    compliance_score: Optional[float] = None  # Percentage
    audit_findings: int = Field(default=0)
    
    # Decisions and actions
    policy_changes: Optional[str] = None  # JSON array of policy updates
    budget_allocated: Optional[float] = None
    resource_changes: Optional[str] = None  # JSON object
    objectives_next_period: Optional[str] = None  # JSON array
    strategic_decisions: Optional[str] = None  # JSON array
    
    # Documentation
    minutes_location: Optional[str] = None  # Path to meeting minutes
    presentation_path: Optional[str] = None
    action_items: Optional[str] = None  # JSON array with owners and due dates
    
    # Approval
    approved_by: str  # CEO/equivalent
    approval_date: datetime
    next_review_date: datetime

# Helper functions for evidence integrity and audit trails
def generate_evidence_hash(data: str) -> str:
    """Generate SHA-256 hash for evidence integrity"""
    return hashlib.sha256(data.encode()).hexdigest()

def create_audit_trail_entry(user: str, action: str, timestamp: datetime = None, source_ip: str = None) -> dict:
    """Create standardized audit trail entry"""
    return {
        "user": user,
        "action": action,
        "timestamp": (timestamp or datetime.utcnow()).isoformat(),
        "source_ip": source_ip
    }