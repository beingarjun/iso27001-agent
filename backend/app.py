from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from sqlmodel import Session, select
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import uuid
import json
import asyncio
from pathlib import Path
import io
import csv

from .models import *
from .deps import get_db, get_settings, get_current_user
from .agents.compliance_workflow import create_compliance_agent
from .agents.tools.security_scanners import create_security_scanner, create_ai_bias_scanner
from .agents.tools.evidence_manager import create_evidence_manager
from .reporting.report_generator import create_report_generator

settings = get_settings()

# Create FastAPI app
app = FastAPI(
    title="ISO 27001 Compliance Agent",
    description="Enterprise-grade GRC platform with AI governance (ISO 27001 + ISO 42001)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2 scheme
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{settings.oauth_base_url}/auth",
    tokenUrl=f"{settings.oauth_base_url}/token",
    scopes={"read": "Read access", "write": "Write access", "admin": "Admin access"}
)

# Initialize services
compliance_agent = create_compliance_agent()
security_scanner = create_security_scanner()
ai_bias_scanner = create_ai_bias_scanner()
evidence_manager = create_evidence_manager()
report_generator = create_report_generator()

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "services": {
            "database": "connected",
            "compliance_agent": "ready",
            "security_scanner": "ready",
            "report_generator": "ready"
        }
    }

# Authentication endpoints
@app.post("/auth/login")
async def login(credentials: Dict[str, str], db: Session = Depends(get_db)):
    """User login endpoint"""
    try:
        # In production, integrate with OAuth2/OIDC provider
        email = credentials.get("email")
        password = credentials.get("password")
        
        if not email or not password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email and password required"
            )
        
        # Mock authentication - replace with real OAuth2/OIDC
        user = db.exec(select(User).where(User.email == email)).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Generate mock JWT token - replace with real token generation
        access_token = f"mock_token_{uuid.uuid4().hex}"
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "role": user.role,
                "org_id": user.org_id
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

# Organization management
@app.get("/api/organizations/{org_id}")
async def get_organization(
    org_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get organization details"""
    if current_user.org_id != org_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    
    org = db.exec(select(Organization).where(Organization.id == org_id)).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    return org

@app.put("/api/organizations/{org_id}")
async def update_organization(
    org_id: int,
    org_data: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update organization settings"""
    if current_user.role not in [UserRole.ADMIN, UserRole.COMPLIANCE_MANAGER]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    org = db.exec(select(Organization).where(Organization.id == org_id)).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Update allowed fields
    for field, value in org_data.items():
        if hasattr(org, field) and field not in ['id', 'created_at']:
            setattr(org, field, value)
    
    db.add(org)
    db.commit()
    db.refresh(org)
    
    return org

# Compliance workflow endpoints
@app.post("/api/compliance/scan")
async def trigger_compliance_scan(
    scan_request: Dict[str, Any],
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Trigger comprehensive compliance scan"""
    
    org_id = current_user.org_id
    scan_types = scan_request.get("scan_types", ["sast", "dependency", "secrets", "iac"])
    target_path = scan_request.get("target_path", "/app")
    
    # Start scan in background
    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
    
    background_tasks.add_task(
        run_compliance_scan_background,
        scan_id=scan_id,
        org_id=org_id,
        user_id=str(current_user.id),
        target_path=target_path,
        scan_types=scan_types
    )
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "org_id": org_id,
        "scan_types": scan_types,
        "estimated_duration": "5-10 minutes"
    }

async def run_compliance_scan_background(
    scan_id: str,
    org_id: int,
    user_id: str,
    target_path: str,
    scan_types: List[str]
):
    """Background task for running compliance scan"""
    try:
        # Run security scan
        scan_results = await security_scanner.run_comprehensive_scan(
            org_id=org_id,
            target_path=target_path,
            scan_types=scan_types
        )
        
        # Run AI bias assessment if AI models exist
        # This would check for AI models in the org and test them
        
        # Run compliance workflow
        workflow_result = await compliance_agent.run_compliance_workflow(
            org_id=org_id,
            user_id=user_id,
            workflow_type="security_scan",
            initial_message=f"Process security scan results for scan {scan_id}",
            context={
                "scan_id": scan_id,
                "scan_results": scan_results,
                "target_path": target_path
            }
        )
        
        # Store results in database (implementation depends on your storage strategy)
        
    except Exception as e:
        print(f"Error in background scan {scan_id}: {str(e)}")

@app.get("/api/compliance/scans/{scan_id}")
async def get_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get scan status and results"""
    
    # Mock response - replace with actual scan status lookup
    return {
        "scan_id": scan_id,
        "status": "completed",
        "org_id": current_user.org_id,
        "findings_count": 12,
        "high_severity_count": 3,
        "evidence_packages": 12,
        "approval_required": True,
        "completion_time": datetime.utcnow().isoformat()
    }

# Finding management
@app.get("/api/findings")
async def list_findings(
    org_id: int = None,
    severity: str = None,
    status: str = None,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List findings with filters"""
    
    if org_id and current_user.org_id != org_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    
    query = select(Finding)
    
    if org_id:
        query = query.where(Finding.org_id == org_id)
    elif current_user.role != UserRole.ADMIN:
        query = query.where(Finding.org_id == current_user.org_id)
    
    if severity:
        query = query.where(Finding.severity == severity)
    
    if status:
        query = query.where(Finding.status == status)
    
    query = query.offset(offset).limit(limit)
    
    findings = db.exec(query).all()
    
    return {
        "findings": findings,
        "total": len(findings),
        "limit": limit,
        "offset": offset
    }

@app.get("/api/findings/{finding_id}")
async def get_finding(
    finding_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get finding details"""
    
    finding = db.exec(select(Finding).where(Finding.id == finding_id)).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    if finding.org_id != current_user.org_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return finding

@app.post("/api/findings/{finding_id}/approve")
async def approve_finding(
    finding_id: int,
    approval_data: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Approve or reject finding"""
    
    if current_user.role not in [UserRole.ADMIN, UserRole.COMPLIANCE_MANAGER]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    finding = db.exec(select(Finding).where(Finding.id == finding_id)).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    approval_status = approval_data.get("status")  # "APPROVED" or "REJECTED"
    approval_reason = approval_data.get("reason", "")
    
    finding.approval_status = ApprovalStatus(approval_status)
    finding.approval_reason = approval_reason
    finding.approved_by = current_user.email
    finding.approval_date = datetime.utcnow()
    
    # Set expiry for approvals (time-boxed)
    if approval_status == "APPROVED":
        finding.approval_expiry = datetime.utcnow() + timedelta(days=90)
    
    db.add(finding)
    db.commit()
    db.refresh(finding)
    
    return finding

# Risk management
@app.get("/api/risks")
async def list_risks(
    org_id: int = None,
    status: str = None,
    category: str = None,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List risks with filters"""
    
    if org_id and current_user.org_id != org_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    
    query = select(RiskRegister)
    
    if org_id:
        query = query.where(RiskRegister.org_id == org_id)
    elif current_user.role != UserRole.ADMIN:
        query = query.where(RiskRegister.org_id == current_user.org_id)
    
    if status:
        query = query.where(RiskRegister.status == status)
    
    if category:
        query = query.where(RiskRegister.category == category)
    
    query = query.offset(offset).limit(limit)
    
    risks = db.exec(query).all()
    
    return {
        "risks": risks,
        "total": len(risks),
        "limit": limit,
        "offset": offset
    }

@app.post("/api/risks")
async def create_risk(
    risk_data: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new risk"""
    
    if current_user.role not in [UserRole.ADMIN, UserRole.COMPLIANCE_MANAGER]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Calculate risk scores
    inherent_likelihood = risk_data.get("inherent_likelihood", 3)
    inherent_impact = risk_data.get("inherent_impact", 3)
    residual_likelihood = risk_data.get("residual_likelihood", inherent_likelihood)
    residual_impact = risk_data.get("residual_impact", inherent_impact)
    
    risk = RiskRegister(
        org_id=current_user.org_id,
        title=risk_data["title"],
        description=risk_data["description"],
        category=risk_data.get("category", "Operational"),
        inherent_likelihood=inherent_likelihood,
        inherent_impact=inherent_impact,
        inherent_risk_score=inherent_likelihood * inherent_impact,
        residual_likelihood=residual_likelihood,
        residual_impact=residual_impact,
        residual_risk_score=residual_likelihood * residual_impact,
        owner_id=current_user.id,
        created_by=current_user.email
    )
    
    # Check if exceeds risk appetite
    org = db.exec(select(Organization).where(Organization.id == current_user.org_id)).first()
    if org:
        risk.exceeds_appetite = risk.residual_risk_score > org.risk_appetite_score
    
    db.add(risk)
    db.commit()
    db.refresh(risk)
    
    return risk

@app.post("/api/risks/{risk_id}/accept")
async def accept_risk(
    risk_id: int,
    acceptance_data: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Accept risk with time-boxed approval"""
    
    if current_user.role not in [UserRole.ADMIN, UserRole.COMPLIANCE_MANAGER]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    risk = db.exec(select(RiskRegister).where(RiskRegister.id == risk_id)).first()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    
    # Risk acceptance with time-boxing
    risk.status = RiskStatus.ACCEPTED
    risk.risk_acceptance_approver = current_user.email
    risk.risk_acceptance_reason = acceptance_data.get("reason", "")
    risk.risk_acceptance_conditions = json.dumps(acceptance_data.get("conditions", []))
    risk.acceptance_signed = True
    risk.acceptance_signature_hash = f"signature_{uuid.uuid4().hex}"
    
    # Set expiry (max 12 months for high risks)
    max_months = 6 if risk.residual_risk_score > 15 else 12
    risk.risk_acceptance_expiry = datetime.utcnow() + timedelta(days=30 * max_months)
    risk.acceptance_review_date = datetime.utcnow() + timedelta(days=90)
    
    db.add(risk)
    db.commit()
    db.refresh(risk)
    
    return risk

# Reports and deliverables
@app.post("/api/reports/statement-of-applicability")
async def generate_soa_report(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate Statement of Applicability"""
    
    if current_user.role not in [UserRole.ADMIN, UserRole.COMPLIANCE_MANAGER]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Get controls data
    controls = db.exec(select(ControlImplementation).where(
        ControlImplementation.org_id == current_user.org_id
    )).all()
    
    # Get org info
    org = db.exec(select(Organization).where(Organization.id == current_user.org_id)).first()
    
    controls_data = [
        {
            "control_id": control.control_id,
            "control_title": control.control_title,
            "control_description": control.control_description,
            "status": control.status,
            "implementation_status": control.implementation_status,
            "owner": control.owner_id,
            "implementation_approach": control.implementation_approach,
            "evidence_location": control.evidence_location,
            "testing_frequency": control.testing_frequency,
            "exclusion_reason": control.exclusion_reason,
            "not_applicable_reason": control.not_applicable_reason
        }
        for control in controls
    ]
    
    org_info = {
        "name": org.name if org else "Unknown Organization",
        "scope_definition": org.scope_definition if org else "To be defined"
    }
    
    result = await report_generator.generate_statement_of_applicability(
        org_id=current_user.org_id,
        controls_data=controls_data,
        org_info=org_info
    )
    
    return result

@app.post("/api/reports/risk-register")
async def generate_risk_register_report(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate Risk Register"""
    
    if current_user.role not in [UserRole.ADMIN, UserRole.COMPLIANCE_MANAGER]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Get risks data
    risks = db.exec(select(RiskRegister).where(
        RiskRegister.org_id == current_user.org_id
    )).all()
    
    risks_data = [
        {
            "risk_id": risk.risk_id,
            "title": risk.title,
            "category": risk.category,
            "description": risk.description,
            "owner": risk.owner_id,
            "inherent_likelihood": risk.inherent_likelihood,
            "inherent_impact": risk.inherent_impact,
            "inherent_risk_score": risk.inherent_risk_score,
            "residual_likelihood": risk.residual_likelihood,
            "residual_impact": risk.residual_impact,
            "residual_risk_score": risk.residual_risk_score,
            "status": risk.status,
            "mitigation_actions": [],  # Would be populated from related CAPAs
            "target_closure_date": risk.target_closure_date,
            "last_reviewed": risk.last_reviewed,
            "exceeds_appetite": risk.exceeds_appetite
        }
        for risk in risks
    ]
    
    org = db.exec(select(Organization).where(Organization.id == current_user.org_id)).first()
    org_info = {
        "name": org.name if org else "Unknown Organization"
    }
    
    result = await report_generator.generate_risk_register(
        org_id=current_user.org_id,
        risks_data=risks_data,
        org_info=org_info
    )
    
    return result

@app.get("/api/reports/{report_id}/download")
async def download_report(
    report_id: str,
    format: str = "pdf",
    current_user: User = Depends(get_current_user)
):
    """Download generated report"""
    
    # Find report file
    reports_dir = Path("reports")
    report_file = None
    
    # Search in different subdirectories
    for subdir in ["statements", "risk_registers", "model_cards", "management_reviews", "release_reports"]:
        file_path = reports_dir / subdir / f"{report_id}.{format}"
        if file_path.exists():
            report_file = file_path
            break
    
    if not report_file:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(
        path=report_file,
        filename=f"{report_id}.{format}",
        media_type="application/octet-stream"
    )

# =============================================================================
# EVIDENCE MANAGEMENT ENDPOINTS
# =============================================================================

@app.post("/evidence/store")
async def store_evidence(
    title: str,
    description: str,
    evidence_type: str,
    file_content: bytes,
    file_name: str,
    mime_type: str,
    finding_id: Optional[int] = None,
    control_id: Optional[str] = None,
    audit_period: Optional[str] = None,
    is_sensitive: bool = False,
    authorized_roles: Optional[List[str]] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Store evidence with immutable storage and chain of custody"""
    try:
        # Store evidence in vault
        result = evidence_manager.store_evidence(
            title=title,
            description=description,
            evidence_type=evidence_type,
            file_content=file_content,
            file_name=file_name,
            mime_type=mime_type,
            org_id=current_user.org_id,
            collected_by=current_user.email,
            finding_id=finding_id,
            control_id=control_id,
            audit_period=audit_period,
            is_sensitive=is_sensitive,
            authorized_roles=authorized_roles
        )
        
        # Create database record
        evidence_record = Evidence(
            evidence_id=result["evidence_id"],
            title=title,
            description=description,
            evidence_type=evidence_type,
            file_name=file_name,
            file_size=result["file_size"],
            mime_type=mime_type,
            content_hash=result["content_hash"],
            vault_path=result["vault_path"],
            org_id=current_user.org_id,
            collected_by=current_user.email,
            finding_id=finding_id,
            control_id=control_id,
            audit_period=audit_period,
            is_sensitive=is_sensitive,
            authorized_roles=json.dumps(authorized_roles) if authorized_roles else None
        )
        
        db.add(evidence_record)
        db.commit()
        db.refresh(evidence_record)
        
        return {
            "evidence_id": result["evidence_id"],
            "content_hash": result["content_hash"],
            "stored_at": result["stored_at"],
            "database_id": evidence_record.id
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Evidence storage failed: {str(e)}")

@app.get("/evidence/{evidence_id}")
async def retrieve_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve evidence with access control"""
    try:
        # Check database record exists
        evidence_record = db.exec(
            select(Evidence).where(Evidence.evidence_id == evidence_id)
        ).first()
        
        if not evidence_record:
            raise HTTPException(status_code=404, detail="Evidence not found")
        
        # Check organization access
        if evidence_record.org_id != current_user.org_id and current_user.role != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Retrieve from vault
        file_content, metadata = evidence_manager.retrieve_evidence(
            evidence_id=evidence_id,
            requesting_user=current_user.email,
            user_roles=[current_user.role.value]
        )
        
        return StreamingResponse(
            io.BytesIO(file_content),
            media_type=evidence_record.mime_type,
            headers={"Content-Disposition": f"attachment; filename={evidence_record.file_name}"}
        )
        
    except Exception as e:
        if "Access denied" in str(e):
            raise HTTPException(status_code=403, detail=str(e))
        raise HTTPException(status_code=500, detail=f"Evidence retrieval failed: {str(e)}")

@app.get("/evidence/{evidence_id}/metadata")
async def get_evidence_metadata(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get evidence metadata without downloading file"""
    evidence_record = db.exec(
        select(Evidence).where(Evidence.evidence_id == evidence_id)
    ).first()
    
    if not evidence_record:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    # Check organization access
    if evidence_record.org_id != current_user.org_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return {
        "evidence_id": evidence_record.evidence_id,
        "title": evidence_record.title,
        "description": evidence_record.description,
        "evidence_type": evidence_record.evidence_type,
        "file_name": evidence_record.file_name,
        "file_size": evidence_record.file_size,
        "mime_type": evidence_record.mime_type,
        "content_hash": evidence_record.content_hash,
        "collected_by": evidence_record.collected_by,
        "collection_date": evidence_record.collection_date,
        "is_sensitive": evidence_record.is_sensitive,
        "finding_id": evidence_record.finding_id,
        "control_id": evidence_record.control_id,
        "audit_period": evidence_record.audit_period
    }

@app.post("/evidence/verify-integrity")
async def verify_evidence_integrity(
    evidence_ids: List[str],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Verify integrity of evidence files"""
    results = []
    
    for evidence_id in evidence_ids:
        # Check database record
        evidence_record = db.exec(
            select(Evidence).where(Evidence.evidence_id == evidence_id)
        ).first()
        
        if not evidence_record:
            results.append({
                "evidence_id": evidence_id,
                "status": "NOT_FOUND_IN_DB",
                "verified_at": datetime.utcnow().isoformat()
            })
            continue
        
        # Check organization access
        if evidence_record.org_id != current_user.org_id and current_user.role != UserRole.ADMIN:
            results.append({
                "evidence_id": evidence_id,
                "status": "ACCESS_DENIED",
                "verified_at": datetime.utcnow().isoformat()
            })
            continue
        
        # Verify integrity
        integrity_result = evidence_manager.verify_evidence_integrity(evidence_id)
        results.append(integrity_result)
    
    return {
        "verification_id": f"VERIFY-{uuid.uuid4().hex[:8].upper()}",
        "verified_by": current_user.email,
        "verified_at": datetime.utcnow().isoformat(),
        "total_evidence": len(evidence_ids),
        "results": results
    }

@app.get("/evidence/organization/{org_id}/list")
async def list_organization_evidence(
    org_id: int,
    skip: int = 0,
    limit: int = 100,
    evidence_type: Optional[str] = None,
    audit_period: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List evidence for an organization"""
    
    # Check organization access
    if org_id != current_user.org_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Build query
    query = select(Evidence).where(Evidence.org_id == org_id)
    
    if evidence_type:
        query = query.where(Evidence.evidence_type == evidence_type)
    
    if audit_period:
        query = query.where(Evidence.audit_period == audit_period)
    
    query = query.offset(skip).limit(limit).order_by(Evidence.collection_date.desc())
    
    evidence_list = db.exec(query).all()
    
    return {
        "org_id": org_id,
        "total_count": len(evidence_list),
        "evidence": [
            {
                "evidence_id": e.evidence_id,
                "title": e.title,
                "evidence_type": e.evidence_type,
                "file_name": e.file_name,
                "file_size": e.file_size,
                "collected_by": e.collected_by,
                "collection_date": e.collection_date,
                "finding_id": e.finding_id,
                "control_id": e.control_id,
                "audit_period": e.audit_period,
                "is_sensitive": e.is_sensitive
            }
            for e in evidence_list
        ]
    }

@app.post("/evidence/export")
async def export_evidence_for_audit(
    org_id: int,
    audit_period: str,
    export_format: str = "json",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Export evidence for audit purposes"""
    
    # Check organization access
    if org_id != current_user.org_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    
    try:
        export_result = evidence_manager.export_evidence_for_audit(
            org_id=org_id,
            audit_period=audit_period,
            export_format=export_format
        )
        
        return {
            "export_id": export_result["export_id"],
            "export_file": export_result["export_file"],
            "evidence_count": export_result["evidence_count"],
            "exported_at": export_result["exported_at"],
            "exported_by": current_user.email
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Evidence export failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)