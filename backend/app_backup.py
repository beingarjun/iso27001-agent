from fastapi import FastAPI, Depends, HTTPException, statusimport asyncio"""

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from fastapi.middleware.cors import CORSMiddlewareimport jsonFastAPI application for ISO 27001 Agent with SSE and human-in-the-loop workflow

from fastapi.responses import StreamingResponse

from sqlmodel import Session, selectfrom datetime import datetime"""

from datetime import datetime, timedelta

import jsonfrom fastapi import FastAPI, Depends, HTTPExceptionimport asyncio

import asyncio

from typing import List, Optionalfrom fastapi.responses import StreamingResponseimport json



# Local importsfrom fastapi.middleware.cors import CORSMiddlewarefrom datetime import datetime

from .deps import get_session, settings, create_db_and_tables

from .models import (from sqlmodel import selectfrom typing import List, Dict, Any, Optional

    Organization, User, Finding, ScanRun, StatementOfApplicability,

    RiskRegister, CAPA, ControlLibrary, UserRole, ApprovalStatus,from .deps import init_db, get_session, settingsfrom contextlib import asynccontextmanager

    create_audit_trail_entry, generate_evidence_hash

)from .models import ScanRun, Finding



# Initialize FastAPI with enterprise metadatafrom .agents.graph import app_graphfrom fastapi import FastAPI, Depends, HTTPException, BackgroundTasks

app = FastAPI(

    title="ISO 27001 Enterprise Agent",from .agents.lcel_pipeline import pipelinefrom fastapi.responses import StreamingResponse

    description="Enterprise-grade compliance automation platform",

    version="1.0.0",from fastapi.middleware.cors import CORSMiddleware

    docs_url="/docs" if settings.DEBUG else None,

    redoc_url="/redoc" if settings.DEBUG else Noneapp = FastAPI(title="ISO 27001 Agent API", version="1.0.0")from sqlmodel import select, Session

)



# CORS middleware for frontend

app.add_middleware(# Add CORS middleware for frontendfrom .deps import init_db, get_session, get_settings, Settings

    CORSMiddleware,

    allow_origins=["http://localhost:3000", "https://app.iso27001-agent.com"],app.add_middleware(from .models import (

    allow_credentials=True,

    allow_methods=["*"],    CORSMiddleware,    ScanRun, Finding, AuditLog,

    allow_headers=["*"],

)    allow_origins=["http://localhost:3000"],  # Next.js default port    ScanRequest, ScanResponse, FindingUpdate,



# Security    allow_credentials=True,    ApprovalStatus, ScanStatus

security = HTTPBearer()

    allow_methods=["*"],)

@app.on_event("startup")

async def startup_event():    allow_headers=["*"],from .agents.graph import app_graph

    """Initialize database and load default data"""

    create_db_and_tables())from .agents.lcel_pipeline import (

    await load_control_library()

    stream_compliance_analysis,

async def load_control_library():

    """Load ISO 27001:2022 control library"""@app.on_event("startup")    stream_finding_explanation, 

    # This would load the complete control library

    # For now, we'll add a few sample controlsasync def startup_event():    stream_remediation_guidance

    pass

    init_db())

# Authentication and authorization

async def get_current_user(

    credentials: HTTPAuthorizationCredentials = Depends(security),

    session: Session = Depends(get_session)@app.post("/scan/start")

) -> User:

    """Get current authenticated user"""def start_scan(host: str = settings.HOST_DEFAULT, session=Depends(get_session)):@asynccontextmanager

    # In production, verify JWT token here

    # For demo, we'll use a simple approach    """Start a new security scan for the given host"""async def lifespan(app: FastAPI):

    token = credentials.credentials

        run = ScanRun(host=host, status="RUNNING")    """Application lifespan events"""

    # Decode token and get user (simplified)

    user = session.exec(select(User).where(User.email == "admin@example.com")).first()    session.add(run)    # Startup

    if not user:

        raise HTTPException(    session.commit()    init_db()

            status_code=status.HTTP_401_UNAUTHORIZED,

            detail="Could not validate credentials"    session.refresh(run)    yield

        )

    return user        # Shutdown - add cleanup if needed



async def require_role(required_role: UserRole):    # Fire-and-wait pattern for demo: invoke once to create findings

    """Role-based access control decorator"""

    def role_checker(current_user: User = Depends(get_current_user)):    try:

        if current_user.role != required_role and current_user.role != UserRole.ADMIN:

            raise HTTPException(        state = app_graph.invoke({"host": host, "run_id": run.id})# Create FastAPI app

                status_code=status.HTTP_403_FORBIDDEN,

                detail=f"Required role: {required_role}"        app = FastAPI(

            )

        return current_user        # Persist findings for approval    title="ISO 27001 Agent",

    return role_checker

        for finding_data in state["findings"]:    description="AI-powered ISO 27001 compliance agent with human-in-the-loop approval workflow",

# Health and status endpoints

@app.get("/health")            f = Finding(    version="1.0.0",

async def health_check():

    """System health check"""                control=finding_data["control"],    lifespan=lifespan

    return {

        "status": "healthy",                severity=finding_data["severity"],)

        "timestamp": datetime.utcnow(),

        "version": settings.APP_VERSION,                title=finding_data["title"],

        "environment": "development" if settings.DEBUG else "production"

    }                detail=finding_data["detail"],# Configure CORS



@app.get("/")                host=hostapp.add_middleware(

async def root():

    """Root endpoint with API information"""            )    CORSMiddleware,

    return {

        "message": "ISO 27001 Enterprise Agent API",            session.add(f)    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000"],

        "version": settings.APP_VERSION,

        "docs": "/docs" if settings.DEBUG else "Contact support for API documentation"            allow_credentials=True,

    }

        run.status = "WAITING_APPROVAL" if state.get("requires_approval") else "DONE"    allow_methods=["*"],

# Organization management

@app.get("/api/v1/organization", response_model=Organization)        if run.status == "DONE":    allow_headers=["*"],

async def get_organization(

    current_user: User = Depends(get_current_user),            run.finished_at = datetime.utcnow())

    session: Session = Depends(get_session)

):            

    """Get current user's organization"""

    org = session.get(Organization, current_user.org_id)        session.commit()

    if not org:

        raise HTTPException(status_code=404, detail="Organization not found")        return {def log_audit_event(

    return org

            "run_id": run.id,     session: Session,

# Compliance Dashboard endpoints

@app.get("/api/v1/dashboard/metrics")            "requires_approval": state.get("requires_approval", False),    user_email: str,

async def get_dashboard_metrics(

    current_user: User = Depends(get_current_user),            "status": run.status    action: str,

    session: Session = Depends(get_session)

):        }    resource_type: str,

    """Get compliance dashboard metrics"""

    org_id = current_user.org_id    except Exception as e:    resource_id: Optional[str] = None,

    

    # Control coverage        run.status = "FAILED"    details: Optional[Dict[str, Any]] = None

    total_controls = session.exec(

        select(StatementOfApplicability).where(StatementOfApplicability.org_id == org_id)        session.commit()):

    ).all()

    implemented_controls = [c for c in total_controls if c.implementation_status == "IMPLEMENTED"]        raise HTTPException(500, f"Scan failed: {str(e)}")    """Log audit event for compliance tracking"""

    

    # Risk metrics    audit_log = AuditLog(

    risks = session.exec(

        select(RiskRegister).where(RiskRegister.org_id == org_id)@app.get("/findings")        user_email=user_email,

    ).all()

    high_risks = [r for r in risks if r.residual_risk_score >= 15]def list_findings(host: str = settings.HOST_DEFAULT, session=Depends(get_session)):        action=action,

    

    # Finding metrics    """List all findings for a host"""        resource_type=resource_type,

    findings = session.exec(

        select(Finding).where(Finding.org_id == org_id)    findings = session.exec(        resource_id=resource_id,

    ).all()

    open_findings = [f for f in findings if f.status == "OPEN"]        select(Finding)        details=json.dumps(details) if details else None

    

    # CAPA metrics        .where(Finding.host == host)    )

    capas = session.exec(

        select(CAPA).where(CAPA.org_id == org_id)        .order_by(Finding.created_at.desc())    session.add(audit_log)

    ).all()

    overdue_capas = [c for c in capas if c.due_date < datetime.utcnow() and c.status != "CLOSED"]    ).all()    session.commit()

    

    return {    return findings

        "control_coverage": {

            "total": len(total_controls),

            "implemented": len(implemented_controls),

            "percentage": round((len(implemented_controls) / len(total_controls)) * 100, 1) if total_controls else 0@app.post("/approve")@app.get("/")

        },

        "risk_posture": {def approve_finding(finding_id: int, approved_by: str, reason: str = "", session=Depends(get_session)):async def root():

            "total_risks": len(risks),

            "high_risks": len(high_risks),    """Approve a security finding"""    """Health check endpoint"""

            "avg_risk_score": round(sum(r.residual_risk_score for r in risks) / len(risks), 1) if risks else 0

        },    finding = session.get(Finding, finding_id)    return {

        "findings": {

            "total": len(findings),    if not finding:        "message": "ISO 27001 Agent API",

            "open": len(open_findings),

            "critical": len([f for f in open_findings if f.severity == "CRITICAL"]),        raise HTTPException(404, "Finding not found")        "version": "1.0.0",

            "high": len([f for f in open_findings if f.severity == "HIGH"])

        },            "status": "healthy",

        "capas": {

            "total": len(capas),    finding.approval_status = "APPROVED"        "timestamp": datetime.utcnow().isoformat()

            "overdue": len(overdue_capas),

            "completion_rate": round((len([c for c in capas if c.status == "CLOSED"]) / len(capas)) * 100, 1) if capas else 0    finding.approved_by = approved_by    }

        }

    }    finding.approval_reason = reason



# Findings management    session.add(finding)

@app.get("/api/v1/findings", response_model=List[Finding])

async def list_findings(    session.commit()@app.post("/scan/start", response_model=ScanResponse)

    severity: Optional[str] = None,

    status: Optional[str] = None,    return {"ok": True, "message": "Finding approved"}async def start_scan(

    limit: int = 100,

    current_user: User = Depends(get_current_user),    request: ScanRequest,

    session: Session = Depends(get_session)

):@app.post("/reject")    background_tasks: BackgroundTasks,

    """List findings with optional filters"""

    query = select(Finding).where(Finding.org_id == current_user.org_id)def reject_finding(finding_id: int, approved_by: str, reason: str = "", session=Depends(get_session)):    session: Session = Depends(get_session),

    

    if severity:    """Reject a security finding"""    settings: Settings = Depends(get_settings)

        query = query.where(Finding.severity == severity)

    if status:    finding = session.get(Finding, finding_id)):

        query = query.where(Finding.status == status)

        if not finding:    """Start a new security scan"""

    query = query.limit(limit).order_by(Finding.identified_date.desc())

    findings = session.exec(query).all()        raise HTTPException(404, "Finding not found")    

    

    return findings        # Create scan run record



@app.post("/api/v1/findings/{finding_id}/approve")    finding.approval_status = "REJECTED"    scan_run = ScanRun(

async def approve_finding(

    finding_id: int,    finding.approved_by = approved_by        host=request.host,

    reason: str,

    current_user: User = Depends(require_role(UserRole.COMPLIANCE_MANAGER)),    finding.approval_reason = reason        status="RUNNING",

    session: Session = Depends(get_session)

):    session.add(finding)        initiated_by=request.initiated_by,

    """Approve a finding (requires compliance manager role)"""

    finding = session.get(Finding, finding_id)    session.commit()        scan_config=json.dumps(request.scan_types) if request.scan_types else None

    if not finding or finding.org_id != current_user.org_id:

        raise HTTPException(status_code=404, detail="Finding not found")    return {"ok": True, "message": "Finding rejected"}    )

    

    # Update finding    session.add(scan_run)

    finding.approval_status = ApprovalStatus.APPROVED

    finding.approval_reason = reason@app.post("/scan/continue")    session.commit()

    finding.approved_by = current_user.email

    finding.approval_date = datetime.utcnow()def continue_after_approvals(run_id: int, host: str = settings.HOST_DEFAULT, session=Depends(get_session)):    session.refresh(scan_run)

    

    # Create audit trail    """Continue scan after approvals are completed"""    

    audit_entry = create_audit_trail_entry(

        user_id=str(current_user.id),    run = session.get(ScanRun, run_id)    # Log audit event

        action="APPROVE_FINDING",

        resource_type="Finding",    if not run:    log_audit_event(

        resource_id=str(finding_id),

        details={"reason": reason}        raise HTTPException(404, "Run not found")        session, 

    )

                request.initiated_by or "system",

    session.add(finding)

    session.commit()    # Re-enter graph; human_gate node will proceed if no PENDING findings        "START_SCAN",

    

    return {"status": "approved", "message": "Finding approved successfully"}    try:        "scan_run",



@app.post("/api/v1/findings/{finding_id}/reject")        state = app_graph.invoke({"host": host, "run_id": run_id})        str(scan_run.id),

async def reject_finding(

    finding_id: int,                {"host": request.host}

    reason: str,

    current_user: User = Depends(require_role(UserRole.COMPLIANCE_MANAGER)),        if state.get("requires_approval"):    )

    session: Session = Depends(get_session)

):            run.status = "WAITING_APPROVAL"    

    """Reject a finding (requires compliance manager role)"""

    finding = session.get(Finding, finding_id)        else:    # Start background scan

    if not finding or finding.org_id != current_user.org_id:

        raise HTTPException(status_code=404, detail="Finding not found")            run.status = "DONE"    background_tasks.add_task(execute_scan_workflow, scan_run.id, request.host)

    

    finding.approval_status = ApprovalStatus.REJECTED            run.finished_at = datetime.utcnow()    

    finding.approval_reason = reason

    finding.approved_by = current_user.email                return ScanResponse(

    finding.approval_date = datetime.utcnow()

            session.add(run)        run_id=scan_run.id,

    session.add(finding)

    session.commit()        session.commit()        status="RUNNING",

    

    return {"status": "rejected", "message": "Finding rejected successfully"}        return {"status": run.status}        requires_approval=False,



# Risk management    except Exception as e:        message="Scan started successfully"

@app.get("/api/v1/risks", response_model=List[RiskRegister])

async def list_risks(        run.status = "FAILED"    )

    status: Optional[str] = None,

    severity: Optional[str] = None,        session.commit()

    current_user: User = Depends(get_current_user),

    session: Session = Depends(get_session)        raise HTTPException(500, f"Continue failed: {str(e)}")

):

    """List organizational risks"""async def execute_scan_workflow(run_id: int, host: str):

    query = select(RiskRegister).where(RiskRegister.org_id == current_user.org_id)

    @app.get("/stream/explain")    """Execute the LangGraph workflow in background"""

    if status:

        query = query.where(RiskRegister.status == status)async def stream_explain(host: str = settings.HOST_DEFAULT):    

    

    risks = session.exec(query.order_by(RiskRegister.residual_risk_score.desc())).all()    """Stream LCEL explanation via Server-Sent Events"""    try:

    

    if severity:    async def event_generator():        # Initialize workflow state

        if severity == "HIGH":

            risks = [r for r in risks if r.residual_risk_score >= 15]        try:        initial_state = {

        elif severity == "MEDIUM":

            risks = [r for r in risks if 10 <= r.residual_risk_score < 15]            async for event in pipeline.astream_events({"host": host}, version="v2"):            "host": host,

        elif severity == "LOW":

            risks = [r for r in risks if r.residual_risk_score < 10]                if event["event"] == "on_chat_model_stream":            "run_id": run_id,

    

    return risks                    chunk = event["data"]["chunk"].content or ""            "scan_config": {



@app.post("/api/v1/risks/{risk_id}/accept")                    if chunk:                "npm_audit": True,

async def accept_risk(

    risk_id: int,                        yield f"data: {json.dumps({'chunk': chunk})}\n\n"                "safety_check": True,

    acceptance_reason: str,

    expiry_months: int = 12,        except Exception as e:                "bandit_scan": True,

    current_user: User = Depends(require_role(UserRole.COMPLIANCE_MANAGER)),

    session: Session = Depends(get_session)            yield f"data: {json.dumps({'error': str(e)})}\n\n"                "ssl_check": True,

):

    """Accept a risk with time-boxed expiry"""                    "http_headers": True,

    risk = session.get(RiskRegister, risk_id)

    if not risk or risk.org_id != current_user.org_id:    return StreamingResponse(event_generator(), media_type="text/event-stream")                "port_scan": False

        raise HTTPException(status_code=404, detail="Risk not found")

                }

    risk.status = "ACCEPTED"

    risk.risk_acceptance_approver = current_user.email@app.get("/runs")        }

    risk.risk_acceptance_reason = acceptance_reason

    risk.risk_acceptance_expiry = datetime.utcnow() + timedelta(days=expiry_months * 30)def list_runs(session=Depends(get_session)):        

    risk.acceptance_review_date = datetime.utcnow()

        """List all scan runs"""        # Run the workflow

    session.add(risk)

    session.commit()    runs = session.exec(select(ScanRun).order_by(ScanRun.started_at.desc())).all()        final_state = app_graph.invoke(initial_state)

    

    return {"status": "accepted", "expiry": risk.risk_acceptance_expiry}    return runs        



# CAPA management        # Update scan run with results

@app.get("/api/v1/capas", response_model=List[CAPA])

async def list_capas(@app.get("/health")        with next(get_session()) as session:

    status: Optional[str] = None,

    assigned_to: Optional[str] = None,def health_check():            scan_run = session.get(ScanRun, run_id)

    current_user: User = Depends(get_current_user),

    session: Session = Depends(get_session)    """Health check endpoint"""            if scan_run:

):

    """List CAPAs with optional filters"""    return {"status": "healthy", "timestamp": datetime.utcnow()}                findings = final_state.get("findings", [])

    query = select(CAPA).where(CAPA.org_id == current_user.org_id)                high_severity_count = sum(

                        1 for f in findings if f.get("severity") in ["HIGH", "CRITICAL"]

    if status:                )

        query = query.where(CAPA.status == status)                

    if assigned_to:                # Create finding records

        query = query.where(CAPA.assigned_to == assigned_to)                for finding_data in findings:

                        finding = Finding(

    capas = session.exec(query.order_by(CAPA.due_date.asc())).all()                        control=finding_data["control"],

    return capas                        severity=finding_data["severity"],

                        title=finding_data["title"],

# Statement of Applicability (SoA)                        detail=finding_data["detail"],

@app.get("/api/v1/soa/export")                        host=host,

async def export_soa(                        scan_run_id=run_id,

    framework: str = "ISO27001",                        evidence=finding_data.get("evidence"),

    current_user: User = Depends(require_role(UserRole.AUDITOR)),                        remediation=finding_data.get("remediation"),

    session: Session = Depends(get_session)                        control_family=finding_data.get("control_family")

):                    )

    """Export Statement of Applicability"""                    session.add(finding)

    controls = session.exec(                

        select(StatementOfApplicability)                # Update scan run status

        .where(StatementOfApplicability.org_id == current_user.org_id)                scan_run.findings_count = len(findings)

        .order_by(StatementOfApplicability.control_id)                scan_run.high_severity_count = high_severity_count

    ).all()                scan_run.graph_state = json.dumps(final_state)

                    

    soa_data = {                if final_state.get("requires_approval", False):

        "organization": current_user.org_id,                    scan_run.status = "WAITING_APPROVAL"

        "framework": framework,                else:

        "export_date": datetime.utcnow().isoformat(),                    scan_run.status = "DONE"

        "controls": [                    scan_run.finished_at = datetime.utcnow()

            {                

                "control_id": c.control_id,                session.add(scan_run)

                "status": c.status,                session.commit()

                "rationale": c.rationale,    

                "implementation_status": c.implementation_status,    except Exception as e:

                "owner": c.responsible_party,        # Update scan run with error

                "last_reviewed": c.last_reviewed.isoformat() if c.last_reviewed else None        with next(get_session()) as session:

            }            scan_run = session.get(ScanRun, run_id)

            for c in controls            if scan_run:

        ]                scan_run.status = "FAILED"

    }                scan_run.error_message = str(e)

                    scan_run.finished_at = datetime.utcnow()

    return soa_data                session.add(scan_run)

                session.commit()

# Scan management

@app.post("/api/v1/scans/start")

async def start_scan(@app.get("/scans", response_model=List[ScanRun])

    target_host: str = settings.HOST_DEFAULT,async def list_scans(

    scan_type: str = "AUTOMATED",    host: Optional[str] = None,

    current_user: User = Depends(get_current_user),    limit: int = 50,

    session: Session = Depends(get_session)    session: Session = Depends(get_session)

):):

    """Start a security and compliance scan"""    """List scan runs"""

    # Create scan run record    

    scan_run = ScanRun(    query = select(ScanRun)

        org_id=current_user.org_id,    if host:

        host=target_host,        query = query.where(ScanRun.host == host)

        status="RUNNING",    

        scan_type=scan_type    query = query.order_by(ScanRun.started_at.desc()).limit(limit)

    )    scans = session.exec(query).all()

        return scans

    session.add(scan_run)

    session.commit()

    session.refresh(scan_run)@app.get("/scans/{run_id}")

    async def get_scan(run_id: int, session: Session = Depends(get_session)):

    # TODO: Trigger LangGraph workflow    """Get specific scan details"""

    # For now, return the scan ID    

        scan_run = session.get(ScanRun, run_id)

    return {    if not scan_run:

        "scan_id": scan_run.id,        raise HTTPException(status_code=404, detail="Scan run not found")

        "status": "started",    

        "target": target_host,    return scan_run

        "message": "Scan initiated successfully"

    }

@app.get("/findings", response_model=List[Finding])

@app.get("/api/v1/scans/{scan_id}")async def list_findings(

async def get_scan_status(    host: Optional[str] = None,

    scan_id: int,    status: Optional[ApprovalStatus] = None,

    current_user: User = Depends(get_current_user),    severity: Optional[str] = None,

    session: Session = Depends(get_session)    limit: int = 100,

):    session: Session = Depends(get_session)

    """Get scan status and results"""):

    scan = session.get(ScanRun, scan_id)    """List findings with optional filters"""

    if not scan or scan.org_id != current_user.org_id:    

        raise HTTPException(status_code=404, detail="Scan not found")    query = select(Finding)

        

    return {    if host:

        "id": scan.id,        query = query.where(Finding.host == host)

        "status": scan.status,    if status:

        "host": scan.host,        query = query.where(Finding.approval_status == status)

        "started_at": scan.started_at,    if severity:

        "finished_at": scan.finished_at        query = query.where(Finding.severity == severity)

    }    

    query = query.order_by(Finding.created_at.desc()).limit(limit)

# Real-time compliance explanation stream    findings = session.exec(query).all()

@app.get("/api/v1/stream/compliance-explanation")    return findings

async def stream_compliance_explanation(

    target_host: str = settings.HOST_DEFAULT,

    current_user: User = Depends(get_current_user)@app.get("/findings/{finding_id}")

):async def get_finding(finding_id: int, session: Session = Depends(get_session)):

    """Stream real-time compliance analysis via SSE"""    """Get specific finding details"""

    async def generate_explanation():    

        """Generate streaming compliance explanation"""    finding = session.get(Finding, finding_id)

        phases = [    if not finding:

            "Initializing ISO 27001 compliance assessment...",        raise HTTPException(status_code=404, detail="Finding not found")

            "Scanning security controls and configurations...",    

            "Analyzing access controls and authentication mechanisms...",    return finding

            "Reviewing data protection and privacy controls...",

            "Evaluating incident response and business continuity...",

            "Generating compliance findings and recommendations...",@app.post("/findings/{finding_id}/approve")

            "Assessment complete - preparing compliance report..."async def approve_finding(

        ]    finding_id: int,

            update: FindingUpdate,

        for phase in phases:    session: Session = Depends(get_session)

            yield f"data: {json.dumps({'phase': phase, 'timestamp': datetime.utcnow().isoformat()})}\n\n"):

            await asyncio.sleep(2)  # Simulate processing time    """Approve a finding"""

            

        yield f"data: {json.dumps({'phase': 'COMPLETE', 'status': 'success'})}\n\n"    finding = session.get(Finding, finding_id)

        if not finding:

    return StreamingResponse(        raise HTTPException(status_code=404, detail="Finding not found")

        generate_explanation(),    

        media_type="text/event-stream",    finding.approval_status = "APPROVED"

        headers={    finding.approval_reason = update.approval_reason

            "Cache-Control": "no-cache",    finding.approved_by = update.approved_by

            "Connection": "keep-alive",    finding.approved_at = datetime.utcnow()

        }    

    )    session.add(finding)

    session.commit()

# Administrative endpoints    

@app.post("/api/v1/admin/seed-data")    # Log audit event

async def seed_data(    log_audit_event(

    current_user: User = Depends(require_role(UserRole.ADMIN)),        session,

    session: Session = Depends(get_session)        update.approved_by,

):        "APPROVE_FINDING",

    """Seed database with sample data (admin only)"""        "finding",

    # This would create sample organizations, users, controls, etc.        str(finding_id),

    # For production, this should be removed or protected        {"reason": update.approval_reason}

        )

    return {"message": "Sample data seeded successfully"}    

    return {"message": "Finding approved successfully"}

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(@app.post("/findings/{finding_id}/reject")

        "app:app",async def reject_finding(

        host="0.0.0.0",    finding_id: int,

        port=8000,    update: FindingUpdate,

        reload=settings.DEBUG    session: Session = Depends(get_session)

    )):
    """Reject a finding"""
    
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    finding.approval_status = "REJECTED"
    finding.approval_reason = update.approval_reason
    finding.approved_by = update.approved_by
    finding.approved_at = datetime.utcnow()
    
    session.add(finding)
    session.commit()
    
    # Log audit event
    log_audit_event(
        session,
        update.approved_by,
        "REJECT_FINDING", 
        "finding",
        str(finding_id),
        {"reason": update.approval_reason}
    )
    
    return {"message": "Finding rejected successfully"}


@app.post("/scans/{run_id}/continue")
async def continue_scan_after_approvals(
    run_id: int,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session)
):
    """Continue scan workflow after human approvals"""
    
    scan_run = session.get(ScanRun, run_id)
    if not scan_run:
        raise HTTPException(status_code=404, detail="Scan run not found")
    
    # Check if there are still pending approvals
    pending_count = session.exec(
        select(Finding).where(
            Finding.host == scan_run.host,
            Finding.approval_status == "PENDING",
            Finding.severity.in_(["HIGH", "CRITICAL"])
        )
    ).all()
    
    if len(pending_count) > 0:
        return {
            "message": f"Still {len(pending_count)} pending approvals",
            "status": "WAITING_APPROVAL"
        }
    
    # Continue workflow
    background_tasks.add_task(continue_workflow, run_id)
    
    return {"message": "Continuing scan workflow", "status": "PROCESSING"}


async def continue_workflow(run_id: int):
    """Continue the workflow after approvals"""
    
    with next(get_session()) as session:
        scan_run = session.get(ScanRun, run_id)
        if not scan_run:
            return
        
        try:
            # Parse previous state
            previous_state = json.loads(scan_run.graph_state or "{}")
            
            # Re-invoke workflow from human_gate node
            final_state = app_graph.invoke(previous_state)
            
            # Update scan run
            scan_run.status = "DONE"
            scan_run.finished_at = datetime.utcnow()
            scan_run.graph_state = json.dumps(final_state)
            
            # Save report if generated
            if final_state.get("report_md"):
                report_path = f"./reports/scan_{run_id}_report.md"
                with open(report_path, "w") as f:
                    f.write(final_state["report_md"])
                scan_run.report_path = report_path
            
            session.add(scan_run)
            session.commit()
            
        except Exception as e:
            scan_run.status = "FAILED"
            scan_run.error_message = str(e)
            scan_run.finished_at = datetime.utcnow()
            session.add(scan_run)
            session.commit()


# Streaming endpoints for real-time analysis
@app.get("/stream/compliance")
async def stream_compliance_analysis_endpoint(
    host: str,
    run_id: Optional[int] = None
):
    """Stream compliance analysis using LCEL pipeline"""
    
    async def event_generator():
        try:
            # Get scan data
            scan_data = {"host": host}
            
            if run_id:
                with next(get_session()) as session:
                    scan_run = session.get(ScanRun, run_id)
                    if scan_run and scan_run.graph_state:
                        state = json.loads(scan_run.graph_state)
                        scan_data.update(state)
            
            # Stream analysis
            async for chunk in stream_compliance_analysis(scan_data):
                if chunk:
                    yield f"data: {json.dumps({'chunk': chunk})}\n\n"
        
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


@app.get("/stream/finding/{finding_id}")
async def stream_finding_explanation_endpoint(finding_id: int, session: Session = Depends(get_session)):
    """Stream detailed explanation of a specific finding"""
    
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    async def event_generator():
        try:
            finding_data = {
                "control": finding.control,
                "severity": finding.severity,
                "title": finding.title,
                "detail": finding.detail,
                "evidence": finding.evidence or ""
            }
            
            async for chunk in stream_finding_explanation(finding_data):
                if chunk:
                    yield f"data: {json.dumps({'chunk': chunk})}\n\n"
        
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


@app.get("/stream/remediation/{finding_id}")
async def stream_remediation_guidance_endpoint(finding_id: int, session: Session = Depends(get_session)):
    """Stream detailed remediation guidance for a finding"""
    
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    async def event_generator():
        try:
            finding_data = {
                "control": finding.control,
                "title": finding.title,
                "detail": finding.detail,
                "evidence": finding.evidence or ""
            }
            
            async for chunk in stream_remediation_guidance(finding_data):
                if chunk:
                    yield f"data: {json.dumps({'chunk': chunk})}\n\n"
        
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)