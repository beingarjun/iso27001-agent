"""
FastAPI application for ISO 27001 Agent with SSE and human-in-the-loop workflow
"""
import asyncio
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import select, Session

from .deps import init_db, get_session, get_settings, Settings
from .models import (
    ScanRun, Finding, AuditLog,
    ScanRequest, ScanResponse, FindingUpdate,
    ApprovalStatus, ScanStatus
)
from .agents.graph import app_graph
from .agents.lcel_pipeline import (
    stream_compliance_analysis,
    stream_finding_explanation, 
    stream_remediation_guidance
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    init_db()
    yield
    # Shutdown - add cleanup if needed


# Create FastAPI app
app = FastAPI(
    title="ISO 27001 Agent",
    description="AI-powered ISO 27001 compliance agent with human-in-the-loop approval workflow",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def log_audit_event(
    session: Session,
    user_email: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
):
    """Log audit event for compliance tracking"""
    audit_log = AuditLog(
        user_email=user_email,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=json.dumps(details) if details else None
    )
    session.add(audit_log)
    session.commit()


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "message": "ISO 27001 Agent API",
        "version": "1.0.0",
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/scan/start", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings)
):
    """Start a new security scan"""
    
    # Create scan run record
    scan_run = ScanRun(
        host=request.host,
        status="RUNNING",
        initiated_by=request.initiated_by,
        scan_config=json.dumps(request.scan_types) if request.scan_types else None
    )
    session.add(scan_run)
    session.commit()
    session.refresh(scan_run)
    
    # Log audit event
    log_audit_event(
        session, 
        request.initiated_by or "system",
        "START_SCAN",
        "scan_run",
        str(scan_run.id),
        {"host": request.host}
    )
    
    # Start background scan
    background_tasks.add_task(execute_scan_workflow, scan_run.id, request.host)
    
    return ScanResponse(
        run_id=scan_run.id,
        status="RUNNING",
        requires_approval=False,
        message="Scan started successfully"
    )


async def execute_scan_workflow(run_id: int, host: str):
    """Execute the LangGraph workflow in background"""
    
    try:
        # Initialize workflow state
        initial_state = {
            "host": host,
            "run_id": run_id,
            "scan_config": {
                "npm_audit": True,
                "safety_check": True,
                "bandit_scan": True,
                "ssl_check": True,
                "http_headers": True,
                "port_scan": False
            }
        }
        
        # Run the workflow
        final_state = app_graph.invoke(initial_state)
        
        # Update scan run with results
        with next(get_session()) as session:
            scan_run = session.get(ScanRun, run_id)
            if scan_run:
                findings = final_state.get("findings", [])
                high_severity_count = sum(
                    1 for f in findings if f.get("severity") in ["HIGH", "CRITICAL"]
                )
                
                # Create finding records
                for finding_data in findings:
                    finding = Finding(
                        control=finding_data["control"],
                        severity=finding_data["severity"],
                        title=finding_data["title"],
                        detail=finding_data["detail"],
                        host=host,
                        scan_run_id=run_id,
                        evidence=finding_data.get("evidence"),
                        remediation=finding_data.get("remediation"),
                        control_family=finding_data.get("control_family")
                    )
                    session.add(finding)
                
                # Update scan run status
                scan_run.findings_count = len(findings)
                scan_run.high_severity_count = high_severity_count
                scan_run.graph_state = json.dumps(final_state)
                
                if final_state.get("requires_approval", False):
                    scan_run.status = "WAITING_APPROVAL"
                else:
                    scan_run.status = "DONE"
                    scan_run.finished_at = datetime.utcnow()
                
                session.add(scan_run)
                session.commit()
    
    except Exception as e:
        # Update scan run with error
        with next(get_session()) as session:
            scan_run = session.get(ScanRun, run_id)
            if scan_run:
                scan_run.status = "FAILED"
                scan_run.error_message = str(e)
                scan_run.finished_at = datetime.utcnow()
                session.add(scan_run)
                session.commit()


@app.get("/scans", response_model=List[ScanRun])
async def list_scans(
    host: Optional[str] = None,
    limit: int = 50,
    session: Session = Depends(get_session)
):
    """List scan runs"""
    
    query = select(ScanRun)
    if host:
        query = query.where(ScanRun.host == host)
    
    query = query.order_by(ScanRun.started_at.desc()).limit(limit)
    scans = session.exec(query).all()
    return scans


@app.get("/scans/{run_id}")
async def get_scan(run_id: int, session: Session = Depends(get_session)):
    """Get specific scan details"""
    
    scan_run = session.get(ScanRun, run_id)
    if not scan_run:
        raise HTTPException(status_code=404, detail="Scan run not found")
    
    return scan_run


@app.get("/findings", response_model=List[Finding])
async def list_findings(
    host: Optional[str] = None,
    status: Optional[ApprovalStatus] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    session: Session = Depends(get_session)
):
    """List findings with optional filters"""
    
    query = select(Finding)
    
    if host:
        query = query.where(Finding.host == host)
    if status:
        query = query.where(Finding.approval_status == status)
    if severity:
        query = query.where(Finding.severity == severity)
    
    query = query.order_by(Finding.created_at.desc()).limit(limit)
    findings = session.exec(query).all()
    return findings


@app.get("/findings/{finding_id}")
async def get_finding(finding_id: int, session: Session = Depends(get_session)):
    """Get specific finding details"""
    
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return finding


@app.post("/findings/{finding_id}/approve")
async def approve_finding(
    finding_id: int,
    update: FindingUpdate,
    session: Session = Depends(get_session)
):
    """Approve a finding"""
    
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    finding.approval_status = "APPROVED"
    finding.approval_reason = update.approval_reason
    finding.approved_by = update.approved_by
    finding.approved_at = datetime.utcnow()
    
    session.add(finding)
    session.commit()
    
    # Log audit event
    log_audit_event(
        session,
        update.approved_by,
        "APPROVE_FINDING",
        "finding",
        str(finding_id),
        {"reason": update.approval_reason}
    )
    
    return {"message": "Finding approved successfully"}


@app.post("/findings/{finding_id}/reject")
async def reject_finding(
    finding_id: int,
    update: FindingUpdate,
    session: Session = Depends(get_session)
):
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