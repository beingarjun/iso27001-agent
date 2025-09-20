from sqlmodel import SQLModel, Field, Relationship
from typing import Optional, Literal, List
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import json
import uuid

# Enterprise-grade enums following Vanta/Drata patterns + AI governance
class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED" 
    REJECTED = "REJECTED"

class RiskStatus(str, Enum):
    OPEN = "OPEN"
    MITIGATED = "MITIGATED"
    ACCEPTED = "ACCEPTED"
    TRANSFERRED = "TRANSFERRED"
    CLOSED = "CLOSED"

class ControlStatus(str, Enum):
    INCLUDED = "INCLUDED"
    EXCLUDED = "EXCLUDED"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class ImplementationStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    IMPLEMENTED = "IMPLEMENTED"
    NEEDS_REVIEW = "NEEDS_REVIEW"

class CAPAStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    CLOSED = "CLOSED"
    OVERDUE = "OVERDUE"

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    COMPLIANCE_MANAGER = "COMPLIANCE_MANAGER"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"
    AI_GOVERNANCE_LEAD = "AI_GOVERNANCE_LEAD"  # AI-specific role

class ComplianceFramework(str, Enum):
    ISO27001 = "ISO27001"
    ISO42001 = "ISO42001"  # AI Management System
    SOC2 = "SOC2"
    GDPR = "GDPR"
    DPDP_INDIA = "DPDP_INDIA"
    PCI_DSS = "PCI_DSS"
    HIPAA = "HIPAA"
    NIST_AI_RMF = "NIST_AI_RMF"

class AssetType(str, Enum):
    CODE = "CODE"
    MODEL = "MODEL"
    DATASET = "DATASET"
    SECRET = "SECRET"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    INFRASTRUCTURE = "INFRASTRUCTURE"

class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SENSITIVE = "SENSITIVE"  # For AI/ML data

class AIRiskCategory(str, Enum):
    BIAS_FAIRNESS = "BIAS_FAIRNESS"
    SAFETY_SECURITY = "SAFETY_SECURITY"
    PRIVACY = "PRIVACY"
    TRANSPARENCY = "TRANSPARENCY"
    RELIABILITY = "RELIABILITY"
    HUMAN_OVERSIGHT = "HUMAN_OVERSIGHT"

# Multi-tenant organization model (Drata-style) with AI governance
class Organization(SQLModel, table=True):
    """Multi-tenant organization entity with AI governance"""
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(min_length=1, max_length=100)
    slug: str = Field(unique=True, min_length=3, max_length=50)
    domain: str = Field(unique=True)
    industry: Optional[str] = None
    
    # Compliance configuration
    compliance_frameworks: str = Field(default='["ISO27001", "ISO42001"]')  # JSON array
    risk_appetite_score: int = Field(default=15, ge=1, le=25)
    ai_risk_appetite: int = Field(default=10, ge=1, le=25)  # AI-specific risk appetite
    
    # AI governance settings
    ai_policy_version: Optional[str] = None
    ai_oversight_committee: Optional[str] = None  # JSON array of members
    ai_use_cases_approved: str = Field(default='[]')  # JSON array
    
    # Subscription and limits
    subscription_tier: Literal["STARTER", "PROFESSIONAL", "ENTERPRISE"] = "STARTER"
    max_users: int = Field(default=10)
    max_controls: int = Field(default=100)
    max_ai_models: int = Field(default=5)
    
    # Scope definition (acceptance criteria A)
    scope_definition: Optional[str] = None  # JSON object defining AI systems + website/infra scope
    accountable_roles: Optional[str] = None  # JSON object mapping roles to owners
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=True)
    settings: Optional[str] = None  # JSON object for org-specific settings

class User(SQLModel, table=True):
    """User with RBAC and SSO support including AI governance roles"""
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    name: str = Field(min_length=1, max_length=100)
    role: UserRole = UserRole.VIEWER
    
    # Organization relationship
    org_id: int = Field(foreign_key="organization.id")
    
    # Authentication
    hashed_password: Optional[str] = None
    is_active: bool = Field(default=True)
    email_verified: bool = Field(default=False)
    
    # MFA and security (acceptance criteria D)
    mfa_enabled: bool = Field(default=False)
    mfa_secret: Optional[str] = None
    last_login: Optional[datetime] = None
    failed_login_attempts: int = Field(default=0)
    password_last_changed: Optional[datetime] = None
    
    # SSO integration
    sso_provider: Optional[str] = None  # "google", "azure", "okta"
    sso_id: Optional[str] = None
    
    # Training and competence (acceptance criteria M)
    security_training_completed: Optional[datetime] = None
    ai_training_completed: Optional[datetime] = None
    training_completion_rate: float = Field(default=0.0)
    competence_matrix: Optional[str] = None  # JSON object
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: Optional[datetime] = None

# Asset and Data Management (acceptance criteria C)
class AssetInventory(SQLModel, table=True):
    """Comprehensive asset inventory including AI assets"""
    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id")
    
    # Asset identification
    asset_id: str = Field(unique=True)
    name: str
    asset_type: AssetType
    classification: DataClassification
    
    # Asset details
    description: Optional[str] = None
    location: Optional[str] = None  # Physical or logical location
    owner_id: int = Field(foreign_key="user.id")
    custodian_email: Optional[str] = None
    
    # For AI assets
    model_version: Optional[str] = None
    training_data_lineage: Optional[str] = None  # JSON object
    model_card_path: Optional[str] = None
    
    # For data assets
    data_sources: Optional[str] = None  # JSON array
    retention_period_months: int = Field(default=36)
    retention_schedule_enforced: bool = Field(default=False)
    deletion_tested: bool = Field(default=False)
    last_deletion_test: Optional[datetime] = None
    
    # Security attributes
    encryption_at_rest: bool = Field(default=False)
    encryption_in_transit: bool = Field(default=False)
    access_controls_applied: bool = Field(default=False)
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=True)

# AI Model Management (ISO 42001 compliance)
class AIModel(SQLModel, table=True):
    """AI/ML model registry with governance"""
    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id")
    
    # Model identification
    model_id: str = Field(unique=True)
    name: str
    version: str
    model_type: str  # "llm", "classification", "regression", etc.
    
    # Model details
    description: str
    intended_use: str
    limitations: Optional[str] = None
    data_sources: str  # JSON array
    training_data_lineage: str  # JSON object
    
    # Evaluation metrics
    evaluation_metrics: str  # JSON object
    bias_metrics: str  # JSON object
    safety_metrics: str  # JSON object
    quality_thresholds: str  # JSON object
    
    # Governance
    model_card_published: bool = Field(default=False)
    model_card_path: Optional[str] = None
    bias_assessment_completed: bool = Field(default=False)
    safety_assessment_completed: bool = Field(default=False)
    
    # Risk assessment
    risk_rating: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    risk_mitigations: Optional[str] = None  # JSON array
    
    # Approval and deployment
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: Optional[str] = None
    approval_date: Optional[datetime] = None
    deployment_approved: bool = Field(default=False)
    
    # Monitoring
    monitoring_enabled: bool = Field(default=False)
    drift_detection_enabled: bool = Field(default=False)
    last_drift_check: Optional[datetime] = None
    
    # Metadata
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=True)

# Enhanced Finding model with AI governance
class Finding(SQLModel, table=True):
    """Security and compliance findings with AI governance support"""
    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id")
    
    # Finding identification
    finding_id: str = Field(unique=True, default_factory=lambda: f"FIND-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(min_length=5, max_length=200)
    description: str = Field(min_length=10)
    
    # Categorization
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    category: str  # "Security", "Privacy", "AI_Safety", "AI_Bias", "AI_Transparency"
    source: Literal["AUTOMATED_SCAN", "MANUAL_REVIEW", "PENETRATION_TEST", "AUDIT", "INCIDENT", "AI_EVALUATION"]
    
    # AI-specific fields
    ai_risk_category: Optional[AIRiskCategory] = None
    model_affected: Optional[str] = None  # Model ID if AI-related
    bias_metric_exceeded: Optional[str] = None
    safety_threshold_violated: Optional[str] = None
    
    # Control mapping
    affected_controls: str  # JSON array of control IDs
    control_gaps: Optional[str] = None  # JSON array describing gaps
    
    # Technical details
    host: Optional[str] = None
    asset_id: Optional[str] = None
    vulnerability_id: Optional[str] = None  # CVE, etc.
    
    # Evidence and proof (acceptance criteria O)
    raw_evidence_hash: Optional[str] = None
    raw_evidence_path: Optional[str] = None
    scanner_output: Optional[str] = None  # JSON of raw scanner data
    screenshot_path: Optional[str] = None
    log_entries: Optional[str] = None  # JSON array
    evidence_immutable: bool = Field(default=True)
    evidence_content_hash: Optional[str] = None
    
    # Approval workflow (human-in-the-loop gates)
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approval_reason: Optional[str] = None
    approved_by: Optional[str] = None
    approval_date: Optional[datetime] = None
    approval_expiry: Optional[datetime] = None  # Time-boxed approvals
    
    # Risk and remediation
    risk_id: Optional[int] = Field(default=None, foreign_key="riskregister.id")
    capa_id: Optional[int] = Field(default=None, foreign_key="capa.id")
    
    # Compliance framework mapping
    frameworks: str = Field(default='["ISO27001"]')  # JSON array
    framework_mappings: Optional[str] = None  # JSON object
    
    # Pipeline blocking (acceptance criteria)
    blocks_release: bool = Field(default=False)  # HIGH findings block pipeline
    release_approved: bool = Field(default=False)
    
    # Lifecycle
    identified_date: datetime = Field(default_factory=datetime.utcnow)
    target_resolution_date: Optional[datetime] = None
    actual_resolution_date: Optional[datetime] = None
    status: Literal["OPEN", "IN_REMEDIATION", "RESOLVED", "ACCEPTED", "FALSE_POSITIVE"] = "OPEN"
    
    # Metadata
    created_by: str
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    tags: Optional[str] = None  # JSON array

# Enhanced Risk Register with AI risks
class RiskRegister(SQLModel, table=True):
    """Enterprise risk register with AI governance (ISO 42001 + ISO 27001)"""
    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id")
    
    # Risk identification
    risk_id: str = Field(unique=True, default_factory=lambda: f"RISK-{datetime.now().year}-{uuid.uuid4().hex[:6].upper()}")
    title: str = Field(min_length=5, max_length=200)
    description: str = Field(min_length=10)
    category: str  # "Cybersecurity", "AI_Safety", "Operational", "Strategic", "Compliance"
    subcategory: Optional[str] = None
    
    # AI-specific risk fields
    ai_risk_category: Optional[AIRiskCategory] = None
    affected_models: Optional[str] = None  # JSON array of model IDs
    model_lifecycle_stage: Optional[str] = None  # "development", "testing", "production"
    
    # Business context
    business_process: Optional[str] = None
    asset_impacted: Optional[str] = None
    stakeholder: Optional[str] = None
    
    # Risk assessment (5x5 matrix)
    inherent_likelihood: int = Field(ge=1, le=5)
    inherent_impact: int = Field(ge=1, le=5)
    inherent_risk_score: int  # calculated: likelihood * impact
    
    residual_likelihood: int = Field(ge=1, le=5)
    residual_impact: int = Field(ge=1, le=5) 
    residual_risk_score: int  # calculated: likelihood * impact
    
    # Risk appetite and tolerance
    risk_appetite_threshold: int = Field(default=15)
    exceeds_appetite: bool = Field(default=False)
    
    # Re-assessment triggers (acceptance criteria B)
    reassessment_triggers: str = Field(default='["model_drift", "new_cves", "major_incidents"]')  # JSON array
    last_reassessment: Optional[datetime] = None
    automatic_ticket_created: bool = Field(default=False)
    
    # Status and ownership
    status: RiskStatus = RiskStatus.OPEN
    owner_id: int = Field(foreign_key="user.id")
    responsible_party: Optional[str] = None
    
    # Timeline management
    identified_date: datetime = Field(default_factory=datetime.utcnow)
    target_closure_date: Optional[datetime] = None
    actual_closure_date: Optional[datetime] = None
    
    # Risk acceptance (time-boxed with signatures)
    risk_acceptance_expiry: Optional[datetime] = None
    risk_acceptance_approver: Optional[str] = None
    risk_acceptance_reason: Optional[str] = None
    risk_acceptance_conditions: Optional[str] = None  # JSON array
    acceptance_review_date: Optional[datetime] = None
    acceptance_signed: bool = Field(default=False)
    acceptance_signature_hash: Optional[str] = None
    
    # Review schedule
    last_reviewed: datetime = Field(default_factory=datetime.utcnow)
    review_frequency_days: int = Field(default=90)
    next_review_date: Optional[datetime] = None
    
    # Control relationships
    affected_controls: Optional[str] = None  # JSON array of control IDs
    existing_controls: Optional[str] = None  # JSON array of controls already in place
    planned_controls: Optional[str] = None  # JSON array of planned mitigations
    
    # External factors
    regulatory_requirement: bool = Field(default=False)
    customer_requirement: bool = Field(default=False)
    contractual_requirement: bool = Field(default=False)
    
    # Metadata
    created_by: str
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    change_log: Optional[str] = None  # JSON array

# ISO 27001 Control Implementation
class ControlImplementation(SQLModel, table=True):
    """ISO 27001:2022 control implementation with mapping"""
    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id")
    
    # Control identification
    control_id: str = Field(index=True)  # "A.5.1", "A.8.23", etc.
    control_title: str
    control_description: str
    framework: ComplianceFramework = ComplianceFramework.ISO27001
    
    # AI-specific controls (ISO 42001)
    ai_control_category: Optional[str] = None  # "AI_Risk_Assessment", "AI_Testing", etc.
    applies_to_ai_systems: bool = Field(default=False)
    
    # Implementation status
    status: ControlStatus = ControlStatus.INCLUDED
    implementation_status: ImplementationStatus = ImplementationStatus.NOT_STARTED
    implementation_approach: Optional[str] = None
    
    # Statement of Applicability
    soa_justification: Optional[str] = None
    exclusion_reason: Optional[str] = None
    not_applicable_reason: Optional[str] = None
    
    # Control details
    owner_id: int = Field(foreign_key="user.id")
    responsible_party: Optional[str] = None
    implementation_date: Optional[datetime] = None
    
    # Evidence and testing
    evidence_location: Optional[str] = None
    testing_frequency: Optional[str] = None  # "QUARTERLY", "ANNUALLY", etc.
    last_test_date: Optional[datetime] = None
    next_test_date: Optional[datetime] = None
    test_results: Optional[str] = None  # JSON object
    
    # Monitoring and effectiveness
    monitoring_approach: Optional[str] = None
    effectiveness_rating: Optional[int] = Field(default=None, ge=1, le=5)
    improvement_notes: Optional[str] = None
    
    # Risk and compliance
    risk_ids: Optional[str] = None  # JSON array of related risk IDs
    threats_addressed: Optional[str] = None  # JSON array
    
    # Cross-framework mapping
    other_framework_mappings: Optional[str] = None  # JSON object
    
    # Metadata
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    review_notes: Optional[str] = None

# Corrective Action Preventive Action (CAPA) 
class CAPA(SQLModel, table=True):
    """CAPA management with audit trails"""
    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id")
    
    # CAPA identification
    capa_id: str = Field(unique=True, default_factory=lambda: f"CAPA-{datetime.now().year}-{uuid.uuid4().hex[:6].upper()}")
    title: str = Field(min_length=5, max_length=200)
    description: str = Field(min_length=10)
    capa_type: Literal["CORRECTIVE", "PREVENTIVE"] = "CORRECTIVE"
    
    # Root cause analysis
    root_cause: Optional[str] = None
    root_cause_analysis_method: Optional[str] = None  # "5_WHY", "FISHBONE", "FMEA"
    contributing_factors: Optional[str] = None  # JSON array
    
    # Relationships
    finding_id: Optional[int] = Field(default=None, foreign_key="finding.id")
    risk_id: Optional[int] = Field(default=None, foreign_key="riskregister.id")
    incident_id: Optional[str] = None
    
    # Action plan
    action_plan: str = Field(min_length=10)  # Detailed action steps
    success_criteria: str = Field(min_length=5)
    
    # Ownership and timeline
    owner_id: int = Field(foreign_key="user.id")
    assigned_to: Optional[str] = None
    due_date: datetime
    target_completion_date: Optional[datetime] = None
    actual_completion_date: Optional[datetime] = None
    
    # Status tracking
    status: CAPAStatus = CAPAStatus.OPEN
    progress_percentage: int = Field(default=0, ge=0, le=100)
    status_notes: Optional[str] = None
    
    # Effectiveness verification
    verification_method: Optional[str] = None
    verification_criteria: Optional[str] = None
    verification_date: Optional[datetime] = None
    verification_results: Optional[str] = None  # JSON object
    effectiveness_confirmed: bool = Field(default=False)
    
    # Priority and escalation
    priority: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    escalated: bool = Field(default=False)
    escalation_date: Optional[datetime] = None
    escalation_reason: Optional[str] = None
    
    # Resources and budget
    estimated_effort_hours: Optional[int] = None
    actual_effort_hours: Optional[int] = None
    budget_required: Optional[float] = None
    budget_approved: bool = Field(default=False)
    
    # Approval workflow
    approval_required: bool = Field(default=False)
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: Optional[str] = None
    approval_date: Optional[datetime] = None
    
    # Metadata and audit trail
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    change_log: Optional[str] = None  # JSON array of status changes
    attachments: Optional[str] = None  # JSON array of file paths

# Evidence Management (immutable storage)
class Evidence(SQLModel, table=True):
    """Evidence management with immutable storage and chain of custody"""
    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id")
    
    # Evidence identification
    evidence_id: str = Field(unique=True, default_factory=lambda: f"EVD-{datetime.now().year}-{uuid.uuid4().hex[:8].upper()}")
    title: str = Field(min_length=3, max_length=200)
    description: Optional[str] = None
    
    # Evidence metadata
    evidence_type: str  # "SCREENSHOT", "LOG_FILE", "DOCUMENT", "CERTIFICATE", "SCAN_RESULT"
    file_path: str  # Path to stored evidence file
    file_name: str
    file_size: int
    mime_type: str
    
    # Immutability and integrity
    content_hash: str  # SHA-256 hash of the file content
    metadata_hash: str  # Hash of metadata for tampering detection
    timestamp_hash: Optional[str] = None  # RFC 3161 timestamp if available
    immutable: bool = Field(default=True)
    
    # Chain of custody
    collected_by: str  # User who collected the evidence
    collection_date: datetime = Field(default_factory=datetime.utcnow)
    collection_method: Optional[str] = None  # "AUTOMATED_SCAN", "MANUAL_CAPTURE", etc.
    custody_log: Optional[str] = None  # JSON array of custody changes
    
    # Relationships and context
    finding_id: Optional[int] = Field(default=None, foreign_key="finding.id")
    control_id: Optional[str] = None  # Related control
    audit_period: Optional[str] = None  # "2024-Q1", "2024-ANNUAL"
    
    # Evidence attributes
    is_sensitive: bool = Field(default=False)
    retention_period_years: int = Field(default=7)
    auto_delete_date: Optional[datetime] = None
    legal_hold: bool = Field(default=False)
    
    # Access control
    access_restricted: bool = Field(default=False)
    authorized_roles: Optional[str] = None  # JSON array of roles who can access
    
    # Verification and approval
    verified: bool = Field(default=False)
    verified_by: Optional[str] = None
    verification_date: Optional[datetime] = None
    verification_notes: Optional[str] = None
    
    # Quality and relevance
    quality_score: Optional[int] = Field(default=None, ge=1, le=5)
    relevance_score: Optional[int] = Field(default=None, ge=1, le=5)
    
    # Metadata
    tags: Optional[str] = None  # JSON array for categorization
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_deleted: bool = Field(default=False)  # Soft delete only

# Policy Documents and Procedures
class PolicyDocument(SQLModel, table=True):
    """Policy and procedure document management"""
    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id")
    
    # Document identification
    document_id: str = Field(unique=True)
    title: str = Field(min_length=3, max_length=200)
    document_type: str  # "POLICY", "PROCEDURE", "STANDARD", "GUIDELINE"
    category: str  # "SECURITY", "PRIVACY", "AI_GOVERNANCE", "HR", "IT"
    
    # Document details
    version: str = Field(default="1.0")
    description: Optional[str] = None
    file_path: str
    file_size: int
    content_hash: str
    
    # Lifecycle management
    status: Literal["DRAFT", "UNDER_REVIEW", "APPROVED", "PUBLISHED", "ARCHIVED"] = "DRAFT"
    effective_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    review_frequency_months: int = Field(default=12)
    next_review_date: Optional[datetime] = None
    
    # Ownership and approval
    owner_id: int = Field(foreign_key="user.id")
    approver_id: Optional[int] = Field(default=None, foreign_key="user.id")
    approval_date: Optional[datetime] = None
    
    # Related frameworks
    frameworks: str = Field(default='["ISO27001"]')  # JSON array
    control_mappings: Optional[str] = None  # JSON object mapping to controls
    
    # Training and awareness
    training_required: bool = Field(default=False)
    training_completion_tracked: bool = Field(default=False)
    acknowledgment_required: bool = Field(default=False)
    
    # AI-specific policy attributes
    applies_to_ai_systems: bool = Field(default=False)
    ai_risk_categories: Optional[str] = None  # JSON array
    human_oversight_requirements: Optional[str] = None
    
    # Distribution and access
    distribution_list: Optional[str] = None  # JSON array of roles/users
    public_facing: bool = Field(default=False)
    confidential: bool = Field(default=False)
    
    # Version control
    previous_version_id: Optional[int] = None
    change_summary: Optional[str] = None
    change_reason: Optional[str] = None
    
    # Metadata
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    tags: Optional[str] = None  # JSON array

# AI Bias Testing and Monitoring
class BiasTest(SQLModel, table=True):
    """AI bias testing and monitoring for fairness"""
    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id")
    
    # Test identification
    test_id: str = Field(unique=True, default_factory=lambda: f"BIAS-{uuid.uuid4().hex[:8].upper()}")
    model_id: str = Field(foreign_key="aimodel.model_id")
    test_name: str
    test_type: str  # "DEMOGRAPHIC_PARITY", "EQUALIZED_ODDS", "INDIVIDUAL_FAIRNESS"
    
    # Test configuration
    protected_attributes: str  # JSON array ["race", "gender", "age"]
    test_dataset_path: str
    test_dataset_size: int
    test_methodology: str
    
    # Test execution
    execution_date: datetime = Field(default_factory=datetime.utcnow)
    execution_duration_seconds: int
    test_environment: str
    tool_used: str  # "FAIRLEARN", "AIF360", "WHAT_IF_TOOL"
    
    # Results and metrics
    bias_metrics: str  # JSON object with metric results
    statistical_parity_diff: Optional[float] = None
    equalized_odds_diff: Optional[float] = None
    demographic_parity_ratio: Optional[float] = None
    
    # Thresholds and compliance
    bias_threshold_exceeded: bool = Field(default=False)
    exceeded_metrics: Optional[str] = None  # JSON array
    compliance_status: Literal["PASS", "FAIL", "INCONCLUSIVE"] = "PASS"
    
    # Remediation
    remediation_required: bool = Field(default=False)
    remediation_plan: Optional[str] = None
    remediation_timeline: Optional[datetime] = None
    
    # Approval and sign-off
    approved_for_production: bool = Field(default=False)
    approved_by: Optional[str] = None
    approval_date: Optional[datetime] = None
    approval_conditions: Optional[str] = None  # JSON array
    
    # Evidence and documentation
    test_report_path: Optional[str] = None
    raw_results_path: Optional[str] = None
    evidence_hash: Optional[str] = None
    
    # Metadata
    created_by: str
    tags: Optional[str] = None  # JSON array
    notes: Optional[str] = None

# Model Cards for AI Documentation
class ModelCard(SQLModel, table=True):
    """Model cards for AI transparency and documentation"""
    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id")
    
    # Model identification
    model_id: str = Field(foreign_key="aimodel.model_id")
    card_version: str = Field(default="1.0")
    card_id: str = Field(unique=True)
    
    # Model details (structured as per Google Model Cards)
    model_details: str  # JSON object: name, version, type, info, owner, license
    intended_use: str  # JSON object: primary use, primary users, out-of-scope uses
    factors: str  # JSON object: relevant factors, evaluation factors
    metrics: str  # JSON object: model performance measures
    evaluation_data: str  # JSON object: datasets, motivation, preprocessing
    training_data: str  # JSON object: datasets, motivation, preprocessing
    quantitative_analyses: str  # JSON object: unitary results, intersectional results
    ethical_considerations: str  # JSON object: sensitive use, risks, mitigations
    caveats_recommendations: str  # JSON object: limitations, recommendations
    
    # AI Risk Assessment
    risk_assessment: str  # JSON object with risk analysis
    bias_assessment: str  # JSON object with bias evaluation
    safety_assessment: str  # JSON object with safety evaluation
    
    # Governance and compliance
    approved_use_cases: str  # JSON array
    prohibited_use_cases: str  # JSON array
    monitoring_requirements: str  # JSON object
    human_oversight_requirements: str  # JSON object
    
    # Publication and access
    published: bool = Field(default=False)
    publication_date: Optional[datetime] = None
    public_facing: bool = Field(default=False)
    file_path: Optional[str] = None  # Path to published model card
    
    # Review and updates
    last_reviewed: datetime = Field(default_factory=datetime.utcnow)
    review_frequency_months: int = Field(default=6)
    next_review_date: Optional[datetime] = None
    
    # Approval workflow
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: Optional[str] = None
    approval_date: Optional[datetime] = None
    
    # Metadata
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    change_log: Optional[str] = None  # JSON array

# Utility functions for model validation and helpers
def generate_content_hash(content: str) -> str:
    """Generate SHA-256 hash of content for integrity verification"""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def calculate_risk_score(likelihood: int, impact: int) -> int:
    """Calculate risk score from likelihood and impact (1-5 scale)"""
    return likelihood * impact

def is_high_risk(risk_score: int, appetite_threshold: int = 15) -> bool:
    """Determine if risk score exceeds appetite threshold"""
    return risk_score > appetite_threshold

def generate_unique_id(prefix: str) -> str:
    """Generate unique ID with prefix"""
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"

# Relationship definitions (for SQLModel relationships if needed)
# Note: These would be defined using back_populates if bidirectional relationships are needed