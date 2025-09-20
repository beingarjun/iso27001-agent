"""
LangGraph workflow for ISO 27001 compliance scanning with human-in-the-loop approval
"""
from typing import TypedDict, List, Literal, Dict, Any
from langgraph.graph import StateGraph, END
from pydantic import BaseModel
from datetime import datetime
import json

from .tools.scanners import (
    npm_audit_json, 
    safety_check_json, 
    bandit_scan_json, 
    check_ssl_openssl,
    check_http_headers,
    scan_open_ports
)
from .tools.normalize import (
    summarize_npm_audit, 
    summarize_safety, 
    summarize_bandit, 
    summarize_ssl,
    summarize_http_headers,
    create_unified_summary
)


class FindingItem(BaseModel):
    """Individual security finding"""
    control: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""


class AgentState(TypedDict):
    """State shared across all nodes in the workflow"""
    host: str
    run_id: int
    scan_config: Dict[str, bool]
    
    # Scan results
    raw_scan_results: Dict[str, Any]
    normalized_summaries: Dict[str, Any]
    unified_summary: Dict[str, Any]
    
    # Findings and analysis
    findings: List[Dict[str, Any]]
    requires_approval: bool
    approval_pending_count: int
    
    # Report generation
    report_md: str
    report_path: str
    
    # Error handling
    errors: List[str]
    status: str


def plan_node(state: AgentState) -> Dict[str, Any]:
    """Initial planning node - sets up scan configuration"""
    
    # Default scan configuration
    default_config = {
        "npm_audit": True,
        "safety_check": True, 
        "bandit_scan": True,
        "ssl_check": True,
        "http_headers": True,
        "port_scan": False  # Disabled by default for external hosts
    }
    
    scan_config = state.get("scan_config", default_config)
    
    return {
        "scan_config": scan_config,
        "findings": [],
        "requires_approval": False,
        "approval_pending_count": 0,
        "errors": [],
        "status": "PLANNING",
        "raw_scan_results": {},
        "normalized_summaries": {}
    }


def scan_node(state: AgentState) -> Dict[str, Any]:
    """Execute all configured security scans"""
    
    host = state["host"]
    scan_config = state.get("scan_config", {})
    raw_results = {}
    errors = list(state.get("errors", []))
    
    # Run npm audit if enabled
    if scan_config.get("npm_audit", True):
        try:
            raw_results["npm_audit"] = npm_audit_json("./frontend")
        except Exception as e:
            errors.append(f"npm audit failed: {str(e)}")
            raw_results["npm_audit"] = {"success": False, "error": str(e)}
    
    # Run safety check if enabled
    if scan_config.get("safety_check", True):
        try:
            raw_results["safety"] = safety_check_json("./backend/requirements.txt")
        except Exception as e:
            errors.append(f"Safety check failed: {str(e)}")
            raw_results["safety"] = {"success": False, "error": str(e)}
    
    # Run bandit scan if enabled
    if scan_config.get("bandit_scan", True):
        try:
            raw_results["bandit"] = bandit_scan_json("./backend")
        except Exception as e:
            errors.append(f"Bandit scan failed: {str(e)}")
            raw_results["bandit"] = {"success": False, "error": str(e)}
    
    # Run SSL check if enabled
    if scan_config.get("ssl_check", True):
        try:
            raw_results["ssl"] = check_ssl_openssl(host)
        except Exception as e:
            errors.append(f"SSL check failed: {str(e)}")
            raw_results["ssl"] = {"success": False, "error": str(e)}
    
    # Run HTTP headers check if enabled
    if scan_config.get("http_headers", True):
        try:
            raw_results["http_headers"] = check_http_headers(f"https://{host}")
        except Exception as e:
            errors.append(f"HTTP headers check failed: {str(e)}")
            raw_results["http_headers"] = {"success": False, "error": str(e)}
    
    # Run port scan if enabled (usually disabled for external hosts)
    if scan_config.get("port_scan", False):
        try:
            raw_results["port_scan"] = scan_open_ports(host)
        except Exception as e:
            errors.append(f"Port scan failed: {str(e)}")
            raw_results["port_scan"] = {"success": False, "error": str(e)}
    
    return {
        "raw_scan_results": raw_results,
        "errors": errors,
        "status": "SCANNING_COMPLETE"
    }


def normalize_node(state: AgentState) -> Dict[str, Any]:
    """Normalize scan results into standard format"""
    
    raw_results = state.get("raw_scan_results", {})
    normalized = {}
    
    # Normalize each scan type
    if "npm_audit" in raw_results:
        normalized["npm_audit"] = summarize_npm_audit(raw_results["npm_audit"])
    
    if "safety" in raw_results:
        normalized["safety"] = summarize_safety(raw_results["safety"])
    
    if "bandit" in raw_results:
        normalized["bandit"] = summarize_bandit(raw_results["bandit"])
    
    if "ssl" in raw_results:
        normalized["ssl"] = summarize_ssl(raw_results["ssl"])
    
    if "http_headers" in raw_results:
        normalized["http_headers"] = summarize_http_headers(raw_results["http_headers"])
    
    # Create unified summary
    unified = create_unified_summary(normalized)
    
    return {
        "normalized_summaries": normalized,
        "unified_summary": unified,
        "status": "NORMALIZATION_COMPLETE"
    }


def decide_node(state: AgentState) -> Dict[str, Any]:
    """Analyze results and create findings with ISO 27001 control mapping"""
    
    summaries = state.get("normalized_summaries", {})
    findings: List[Dict[str, Any]] = []
    
    # Check npm audit results
    npm_summary = summaries.get("npm_audit", {})
    if npm_summary.get("success") and npm_summary.get("total_vulns", 0) > 0:
        severity_breakdown = npm_summary.get("severity_breakdown", {})
        if severity_breakdown.get("high", 0) + severity_breakdown.get("critical", 0) > 0:
            severity = "HIGH"
        elif severity_breakdown.get("moderate", 0) > 0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        findings.append({
            "control": "A.12.6.1",
            "control_family": "System Acquisition, Development and Maintenance",
            "severity": severity,
            "title": "Vulnerable npm dependencies detected",
            "detail": f"Found {npm_summary['total_vulns']} vulnerabilities in npm packages. " +
                     f"Critical: {severity_breakdown.get('critical', 0)}, " +
                     f"High: {severity_breakdown.get('high', 0)}, " +
                     f"Moderate: {severity_breakdown.get('moderate', 0)}",
            "evidence": json.dumps(npm_summary.get("vulnerable_packages", [])[:5]),
            "remediation": "; ".join(npm_summary.get("recommendations", []))
        })
    
    # Check safety results  
    safety_summary = summaries.get("safety", {})
    if safety_summary.get("success") and safety_summary.get("total_vulns", 0) > 0:
        severity_breakdown = safety_summary.get("severity_breakdown", {})
        if severity_breakdown.get("high", 0) > 0:
            severity = "HIGH"
        elif severity_breakdown.get("medium", 0) > 0:
            severity = "MEDIUM"  
        else:
            severity = "LOW"
        
        findings.append({
            "control": "A.12.6.1", 
            "control_family": "System Acquisition, Development and Maintenance",
            "severity": severity,
            "title": "Vulnerable Python dependencies detected",
            "detail": f"Found {safety_summary['total_vulns']} vulnerabilities in Python packages.",
            "evidence": json.dumps(safety_summary.get("vulnerable_packages", [])[:5]),
            "remediation": "; ".join(safety_summary.get("recommendations", []))
        })
    
    # Check bandit results
    bandit_summary = summaries.get("bandit", {})
    if bandit_summary.get("success") and bandit_summary.get("total_issues", 0) > 0:
        severity_breakdown = bandit_summary.get("severity_breakdown", {})
        if severity_breakdown.get("HIGH", 0) > 0:
            severity = "HIGH"
        elif severity_breakdown.get("MEDIUM", 0) > 0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        findings.append({
            "control": "A.14.2.1",
            "control_family": "System Acquisition, Development and Maintenance", 
            "severity": severity,
            "title": "Code security issues detected",
            "detail": f"Found {bandit_summary['total_issues']} security issues in code. " +
                     f"High: {severity_breakdown.get('HIGH', 0)}, " +
                     f"Medium: {severity_breakdown.get('MEDIUM', 0)}",
            "evidence": json.dumps(bandit_summary.get("issue_categories", [])[:3]),
            "remediation": "; ".join(bandit_summary.get("recommendations", []))
        })
    
    # Check SSL results
    ssl_summary = summaries.get("ssl", {})
    if ssl_summary.get("success"):
        if not ssl_summary.get("certificate_valid", True):
            days_until_expiry = ssl_summary.get("days_until_expiry", 0)
            if days_until_expiry <= 7:
                severity = "HIGH"
            elif days_until_expiry <= 30:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            findings.append({
                "control": "A.10.1.1",
                "control_family": "Cryptography",
                "severity": severity,
                "title": "TLS/SSL certificate issues",
                "detail": f"Certificate expires in {days_until_expiry} days or has other issues.",
                "evidence": json.dumps(ssl_summary.get("security_issues", [])),
                "remediation": "; ".join(ssl_summary.get("recommendations", []))
            })
    
    # Check HTTP headers
    headers_summary = summaries.get("http_headers", {})
    if headers_summary.get("success"):
        security_score = headers_summary.get("security_score", 100)
        if security_score < 80:
            if security_score < 50:
                severity = "HIGH"
            elif security_score < 70:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            findings.append({
                "control": "A.13.1.1",
                "control_family": "Communications Security",
                "severity": severity,
                "title": "Missing HTTP security headers",
                "detail": f"Security headers compliance: {security_score:.1f}%. " +
                         f"Missing {len(headers_summary.get('missing_headers', []))} important headers.",
                "evidence": json.dumps(headers_summary.get("missing_headers", [])),
                "remediation": "; ".join(headers_summary.get("recommendations", []))
            })
    
    # Determine if human approval is required
    high_severity_count = sum(1 for f in findings if f["severity"] in ["HIGH", "CRITICAL"])
    requires_approval = high_severity_count > 0
    
    return {
        "findings": findings,
        "requires_approval": requires_approval,
        "approval_pending_count": high_severity_count,
        "status": "ANALYSIS_COMPLETE"
    }


def human_gate_node(state: AgentState) -> Dict[str, Any]:
    """Human approval gate - waits for security officer approval of high-severity findings"""
    
    # This node checks the database for pending approvals
    # In a real implementation, this would query the database to check
    # if all high-severity findings have been approved or rejected
    
    from sqlmodel import select
    from ..deps import get_session
    from ..models import Finding
    
    host = state["host"]
    
    # Check for pending approvals in database
    with next(get_session()) as session:
        pending_findings = session.exec(
            select(Finding).where(
                Finding.host == host,
                Finding.approval_status == "PENDING",
                Finding.severity.in_(["HIGH", "CRITICAL"])
            )
        ).all()
    
    pending_count = len(pending_findings)
    
    return {
        "approval_pending_count": pending_count,
        "requires_approval": pending_count > 0,
        "status": "WAITING_APPROVAL" if pending_count > 0 else "APPROVALS_COMPLETE"
    }


def report_node(state: AgentState) -> Dict[str, Any]:
    """Generate final compliance report"""
    
    host = state["host"]
    findings = state.get("findings", [])
    unified_summary = state.get("unified_summary", {})
    
    # Generate markdown report
    report_lines = [
        f"# ISO 27001 Compliance Report",
        f"**Target Host:** {host}",
        f"**Scan Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Report Generated:** {datetime.utcnow().isoformat()}",
        "",
        "## Executive Summary",
        f"- Total Issues Found: {unified_summary.get('total_issues', 0)}",
        f"- High Severity Issues: {unified_summary.get('high_severity_issues', 0)}",
        f"- Risk Level: {unified_summary.get('risk_level', 'UNKNOWN')}",
        f"- Risk Score: {unified_summary.get('risk_score', 0)}/100",
        "",
        "## Findings by Control",
        ""
    ]
    
    if not findings:
        report_lines.append("✅ **No security findings identified.** The target system appears to comply with scanned ISO 27001 controls.")
    else:
        for finding in findings:
            report_lines.extend([
                f"### {finding['control']} - {finding['title']}",
                f"**Severity:** {finding['severity']}",
                f"**Control Family:** {finding.get('control_family', 'Unknown')}",
                f"**Description:** {finding['detail']}",
                "",
                f"**Remediation:** {finding.get('remediation', 'No specific remediation provided.')}",
                ""
            ])
    
    # Add scan summaries
    scanner_summaries = unified_summary.get("scanner_summaries", [])
    if scanner_summaries:
        report_lines.extend([
            "## Scan Details",
            ""
        ])
        for summary in scanner_summaries:
            status = "✅" if summary["success"] else "❌"
            report_lines.append(f"- {status} **{summary['scanner']}**: {summary['summary']}")
    
    # Add recommendations
    recommendations = unified_summary.get("recommendations", [])
    if recommendations:
        report_lines.extend([
            "",
            "## Recommendations",
            ""
        ])
        for i, rec in enumerate(recommendations, 1):
            report_lines.append(f"{i}. {rec}")
    
    report_lines.extend([
        "",
        "---",
        f"*Report generated by ISO 27001 Agent on {datetime.utcnow().strftime('%Y-%m-%d')}*"
    ])
    
    report_md = "\n".join(report_lines)
    
    return {
        "report_md": report_md,
        "status": "REPORT_COMPLETE"
    }


# Build the LangGraph workflow
def create_workflow() -> StateGraph:
    """Create and configure the LangGraph workflow"""
    
    graph = StateGraph(AgentState)
    
    # Add nodes
    graph.add_node("plan", plan_node)
    graph.add_node("scan", scan_node)
    graph.add_node("normalize", normalize_node)
    graph.add_node("decide", decide_node)
    graph.add_node("human_gate", human_gate_node)
    graph.add_node("report", report_node)
    
    # Set entry point
    graph.set_entry_point("plan")
    
    # Add edges
    graph.add_edge("plan", "scan")
    graph.add_edge("scan", "normalize")
    graph.add_edge("normalize", "decide")
    
    # Conditional edge after decide - go to human gate if approval needed
    graph.add_conditional_edges(
        "decide",
        lambda state: "human_gate" if state.get("requires_approval", False) else "report",
        {
            "human_gate": "human_gate",
            "report": "report"
        }
    )
    
    # Loop on human_gate until all approvals are cleared
    graph.add_conditional_edges(
        "human_gate", 
        lambda state: "human_gate" if state.get("requires_approval", False) else "report",
        {
            "human_gate": "human_gate",
            "report": "report"
        }
    )
    
    # Report is terminal
    graph.add_edge("report", END)
    
    return graph


# Compile the workflow
workflow_graph = create_workflow()
app_graph = workflow_graph.compile()