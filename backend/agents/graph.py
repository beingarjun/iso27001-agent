from typing import TypedDict, List, Literal, Any"""

from langgraph.graph import StateGraph, ENDLangGraph workflow for ISO 27001 compliance scanning with human-in-the-loop approval

from pydantic import BaseModel"""

from .tools.scanners import npm_audit_json, safety_check_json, bandit_scan_json, check_ssl_openssl, run_custom_security_checksfrom typing import TypedDict, List, Literal, Dict, Any

from .tools.normalize import summarize_npm_audit, summarize_safety, summarize_bandit, summarize_ssl, summarize_custom_checksfrom langgraph.graph import StateGraph, END

from pydantic import BaseModel

class FindingItem(BaseModel):from datetime import datetime

    control: strimport json

    severity: Literal["LOW", "MEDIUM", "HIGH"]

    title: strfrom .tools.scanners import (

    detail: str    npm_audit_json, 

    safety_check_json, 

class AgentState(TypedDict):    bandit_scan_json, 

    host: str    check_ssl_openssl,

    summaries: dict    check_http_headers,

    findings: List[dict]  # List of FindingItem dicts    scan_open_ports

    requires_approval: bool)

    report_md: strfrom .tools.normalize import (

    run_id: int  # FK to ScanRun    summarize_npm_audit, 

    scan_phase: str  # Track current phase    summarize_safety, 

    summarize_bandit, 

def plan_node(state: AgentState) -> dict:    summarize_ssl,

    """Planning phase - initialize the scan"""    summarize_http_headers,

    return {    create_unified_summary

        "findings": [],)

        "requires_approval": False,

        "scan_phase": "planning",

        "summaries": {}class FindingItem(BaseModel):

    }    """Individual security finding"""

    control: str

def scan_node(state: AgentState) -> dict:    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    """Scanning phase - run all security scans"""    title: str

    host = state["host"]    detail: str

        evidence: str = ""

    # Run all security scans    remediation: str = ""

    try:

        npm_data = npm_audit_json()

        npm_summary = summarize_npm_audit(npm_data)class AgentState(TypedDict):

    except Exception as e:    """State shared across all nodes in the workflow"""

        npm_summary = {"total_vulns": 0, "summary": f"NPM scan failed: {str(e)}"}    host: str

        run_id: int

    try:    scan_config: Dict[str, bool]

        safety_data = safety_check_json()    

        safety_summary = summarize_safety(safety_data)    # Scan results

    except Exception as e:    raw_scan_results: Dict[str, Any]

        safety_summary = {"total_vulns": 0, "summary": f"Safety scan failed: {str(e)}"}    normalized_summaries: Dict[str, Any]

        unified_summary: Dict[str, Any]

    try:    

        bandit_data = bandit_scan_json(".")    # Findings and analysis

        bandit_summary = summarize_bandit(bandit_data)    findings: List[Dict[str, Any]]

    except Exception as e:    requires_approval: bool

        bandit_summary = {"total_issues": 0, "summary": f"Bandit scan failed: {str(e)}"}    approval_pending_count: int

        

    try:    # Report generation

        ssl_data = check_ssl_openssl(host)    report_md: str

        ssl_summary = summarize_ssl(ssl_data)    report_path: str

    except Exception as e:    

        ssl_summary = {"valid": False, "summary": f"SSL check failed: {str(e)}"}    # Error handling

        errors: List[str]

    try:    status: str

        custom_data = run_custom_security_checks()

        custom_summary = summarize_custom_checks(custom_data)

    except Exception as e:def plan_node(state: AgentState) -> Dict[str, Any]:

        custom_summary = {"total_issues": 0, "summary": f"Custom checks failed: {str(e)}"}    """Initial planning node - sets up scan configuration"""

        

    return {    # Default scan configuration

        "summaries": {    default_config = {

            "npm": npm_summary,        "npm_audit": True,

            "safety": safety_summary,        "safety_check": True, 

            "bandit": bandit_summary,        "bandit_scan": True,

            "ssl": ssl_summary,        "ssl_check": True,

            "custom": custom_summary        "http_headers": True,

        },        "port_scan": False  # Disabled by default for external hosts

        "scan_phase": "scanning_complete"    }

    }    

    scan_config = state.get("scan_config", default_config)

def decide_node(state: AgentState) -> dict:    

    """Decision phase - analyze scan results and create findings"""    return {

    summaries = state["summaries"]        "scan_config": scan_config,

    findings = []        "findings": [],

            "requires_approval": False,

    # Check NPM vulnerabilities        "approval_pending_count": 0,

    npm = summaries.get("npm", {})        "errors": [],

    if npm.get("total_vulns", 0) > 0:        "status": "PLANNING",

        severity = "HIGH" if npm.get("by_severity", {}).get("critical", 0) > 0 or npm.get("by_severity", {}).get("high", 0) > 0 else "MEDIUM"        "raw_scan_results": {},

        findings.append(FindingItem(        "normalized_summaries": {}

            control="A.12.6.1",    }

            severity=severity,

            title="NPM Dependency Vulnerabilities",

            detail=f"Found {npm.get('total_vulns')} vulnerabilities in NPM packages. {npm.get('summary', '')}"def scan_node(state: AgentState) -> Dict[str, Any]:

        ))    """Execute all configured security scans"""

        

    # Check Python package vulnerabilities    host = state["host"]

    safety = summaries.get("safety", {})    scan_config = state.get("scan_config", {})

    if safety.get("total_vulns", 0) > 0:    raw_results = {}

        findings.append(FindingItem(    errors = list(state.get("errors", []))

            control="A.12.6.1",    

            severity="HIGH",    # Run npm audit if enabled

            title="Python Package Vulnerabilities",    if scan_config.get("npm_audit", True):

            detail=f"Found {safety.get('total_vulns')} vulnerable Python packages. {safety.get('summary', '')}"        try:

        ))            raw_results["npm_audit"] = npm_audit_json("./frontend")

            except Exception as e:

    # Check Bandit code security issues            errors.append(f"npm audit failed: {str(e)}")

    bandit = summaries.get("bandit", {})            raw_results["npm_audit"] = {"success": False, "error": str(e)}

    if bandit.get("counts", {}).get("HIGH", 0) > 0:    

        findings.append(FindingItem(    # Run safety check if enabled

            control="A.14.2.1",    if scan_config.get("safety_check", True):

            severity="HIGH",        try:

            title="High-Severity Code Security Issues",            raw_results["safety"] = safety_check_json("./backend/requirements.txt")

            detail=f"Found {bandit.get('counts', {}).get('HIGH', 0)} high-severity security issues in code. {bandit.get('summary', '')}"        except Exception as e:

        ))            errors.append(f"Safety check failed: {str(e)}")

    elif bandit.get("total_issues", 0) > 0:            raw_results["safety"] = {"success": False, "error": str(e)}

        findings.append(FindingItem(    

            control="A.14.2.1",    # Run bandit scan if enabled

            severity="MEDIUM",    if scan_config.get("bandit_scan", True):

            title="Code Security Issues",        try:

            detail=f"Found {bandit.get('total_issues')} security issues in code. {bandit.get('summary', '')}"            raw_results["bandit"] = bandit_scan_json("./backend")

        ))        except Exception as e:

                errors.append(f"Bandit scan failed: {str(e)}")

    # Check SSL/TLS configuration            raw_results["bandit"] = {"success": False, "error": str(e)}

    ssl = summaries.get("ssl", {})    

    if not ssl.get("valid", False) or ssl.get("issues", []):    # Run SSL check if enabled

        severity = "HIGH" if not ssl.get("valid", False) else "MEDIUM"    if scan_config.get("ssl_check", True):

        findings.append(FindingItem(        try:

            control="A.10.1.1",            raw_results["ssl"] = check_ssl_openssl(host)

            severity=severity,        except Exception as e:

            title="TLS/SSL Configuration Issues",            errors.append(f"SSL check failed: {str(e)}")

            detail=f"SSL/TLS issues detected: {ssl.get('summary', 'SSL validation failed')}"            raw_results["ssl"] = {"success": False, "error": str(e)}

        ))    

        # Run HTTP headers check if enabled

    # Check custom security issues    if scan_config.get("http_headers", True):

    custom = summaries.get("custom", {})        try:

    if custom.get("total_issues", 0) > 0:            raw_results["http_headers"] = check_http_headers(f"https://{host}")

        findings.append(FindingItem(        except Exception as e:

            control="A.9.1.2",            errors.append(f"HTTP headers check failed: {str(e)}")

            severity="MEDIUM",            raw_results["http_headers"] = {"success": False, "error": str(e)}

            title="System Configuration Issues",    

            detail=f"Found {custom.get('total_issues')} configuration security issues. {custom.get('summary', '')}"    # Run port scan if enabled (usually disabled for external hosts)

        ))    if scan_config.get("port_scan", False):

            try:

    # Convert findings to dict format            raw_results["port_scan"] = scan_open_ports(host)

    findings_dicts = [f.model_dump() for f in findings]        except Exception as e:

                errors.append(f"Port scan failed: {str(e)}")

    # Determine if human approval is required (any HIGH severity findings)            raw_results["port_scan"] = {"success": False, "error": str(e)}

    requires_approval = any(f.severity == "HIGH" for f in findings)    

        return {

    return {        "raw_scan_results": raw_results,

        "findings": findings_dicts,        "errors": errors,

        "requires_approval": requires_approval,        "status": "SCANNING_COMPLETE"

        "scan_phase": "decision_complete"    }

    }



def human_gate_node(state: AgentState) -> dict:def normalize_node(state: AgentState) -> Dict[str, Any]:

    """Human approval gate - check if all HIGH findings are approved/rejected"""    """Normalize scan results into standard format"""

    from sqlmodel import select    

    from ..deps import get_session    raw_results = state.get("raw_scan_results", {})

    from ..models import Finding    normalized = {}

        

    host = state["host"]    # Normalize each scan type

        if "npm_audit" in raw_results:

    with get_session() as session:        normalized["npm_audit"] = summarize_npm_audit(raw_results["npm_audit"])

        # Check for pending HIGH severity findings    

        pending_findings = session.exec(    if "safety" in raw_results:

            select(Finding).where(        normalized["safety"] = summarize_safety(raw_results["safety"])

                Finding.host == host,    

                Finding.severity == "HIGH",    if "bandit" in raw_results:

                Finding.approval_status == "PENDING"        normalized["bandit"] = summarize_bandit(raw_results["bandit"])

            )    

        ).all()    if "ssl" in raw_results:

            normalized["ssl"] = summarize_ssl(raw_results["ssl"])

    # If there are still pending HIGH findings, stay in approval gate    

    still_requires_approval = len(pending_findings) > 0    if "http_headers" in raw_results:

            normalized["http_headers"] = summarize_http_headers(raw_results["http_headers"])

    return {    

        "requires_approval": still_requires_approval,    # Create unified summary

        "scan_phase": "awaiting_approval" if still_requires_approval else "approval_complete"    unified = create_unified_summary(normalized)

    }    

    return {

def report_node(state: AgentState) -> dict:        "normalized_summaries": normalized,

    """Generate final report"""        "unified_summary": unified,

    host = state["host"]        "status": "NORMALIZATION_COMPLETE"

    findings = state["findings"]    }

    summaries = state["summaries"]

    

    # Build markdown reportdef decide_node(state: AgentState) -> Dict[str, Any]:

    lines = [    """Analyze results and create findings with ISO 27001 control mapping"""

        f"# ISO 27001 Security Assessment Report",    

        f"**Host:** {host}",    summaries = state.get("normalized_summaries", {})

        f"**Scan Date:** {__import__('datetime').datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",    findings: List[Dict[str, Any]] = []

        f"**Total Findings:** {len(findings)}",    

        "",    # Check npm audit results

        "## Executive Summary",    npm_summary = summaries.get("npm_audit", {})

        ""    if npm_summary.get("success") and npm_summary.get("total_vulns", 0) > 0:

    ]        severity_breakdown = npm_summary.get("severity_breakdown", {})

            if severity_breakdown.get("high", 0) + severity_breakdown.get("critical", 0) > 0:

    # Add summary statistics            severity = "HIGH"

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}        elif severity_breakdown.get("moderate", 0) > 0:

    for finding in findings:            severity = "MEDIUM"

        severity_counts[finding.get("severity", "LOW")] += 1        else:

                severity = "LOW"

    lines.extend([        

        f"- **High Severity:** {severity_counts['HIGH']} findings",        findings.append({

        f"- **Medium Severity:** {severity_counts['MEDIUM']} findings",             "control": "A.12.6.1",

        f"- **Low Severity:** {severity_counts['LOW']} findings",            "control_family": "System Acquisition, Development and Maintenance",

        "",            "severity": severity,

        "## Detailed Findings",            "title": "Vulnerable npm dependencies detected",

        ""            "detail": f"Found {npm_summary['total_vulns']} vulnerabilities in npm packages. " +

    ])                     f"Critical: {severity_breakdown.get('critical', 0)}, " +

                         f"High: {severity_breakdown.get('high', 0)}, " +

    # Add each finding                     f"Moderate: {severity_breakdown.get('moderate', 0)}",

    for i, finding in enumerate(findings, 1):            "evidence": json.dumps(npm_summary.get("vulnerable_packages", [])[:5]),

        lines.extend([            "remediation": "; ".join(npm_summary.get("recommendations", []))

            f"### Finding {i}: {finding.get('title', 'Untitled')}",        })

            f"**Control:** {finding.get('control', 'N/A')}",    

            f"**Severity:** {finding.get('severity', 'LOW')}",    # Check safety results  

            f"**Description:** {finding.get('detail', 'No description')}",    safety_summary = summaries.get("safety", {})

            ""    if safety_summary.get("success") and safety_summary.get("total_vulns", 0) > 0:

        ])        severity_breakdown = safety_summary.get("severity_breakdown", {})

            if severity_breakdown.get("high", 0) > 0:

    # Add scan summaries            severity = "HIGH"

    lines.extend([        elif severity_breakdown.get("medium", 0) > 0:

        "## Scan Details",            severity = "MEDIUM"  

        ""        else:

    ])            severity = "LOW"

            

    for scan_type, summary in summaries.items():        findings.append({

        lines.extend([            "control": "A.12.6.1", 

            f"### {scan_type.upper()} Scan",            "control_family": "System Acquisition, Development and Maintenance",

            f"{summary.get('summary', 'No summary available')}",            "severity": severity,

            ""            "title": "Vulnerable Python dependencies detected",

        ])            "detail": f"Found {safety_summary['total_vulns']} vulnerabilities in Python packages.",

                "evidence": json.dumps(safety_summary.get("vulnerable_packages", [])[:5]),

    report_md = "\n".join(lines)            "remediation": "; ".join(safety_summary.get("recommendations", []))

            })

    return {    

        "report_md": report_md,    # Check bandit results

        "scan_phase": "complete"    bandit_summary = summaries.get("bandit", {})

    }    if bandit_summary.get("success") and bandit_summary.get("total_issues", 0) > 0:

        severity_breakdown = bandit_summary.get("severity_breakdown", {})

# Build the LangGraph workflow        if severity_breakdown.get("HIGH", 0) > 0:

graph = StateGraph(AgentState)            severity = "HIGH"

        elif severity_breakdown.get("MEDIUM", 0) > 0:

# Add nodes            severity = "MEDIUM"

graph.add_node("plan", plan_node)        else:

graph.add_node("scan", scan_node)            severity = "LOW"

graph.add_node("decide", decide_node)        

graph.add_node("human_gate", human_gate_node)        findings.append({

graph.add_node("report", report_node)            "control": "A.14.2.1",

            "control_family": "System Acquisition, Development and Maintenance", 

# Set entry point            "severity": severity,

graph.set_entry_point("plan")            "title": "Code security issues detected",

            "detail": f"Found {bandit_summary['total_issues']} security issues in code. " +

# Add linear flow edges                     f"High: {severity_breakdown.get('HIGH', 0)}, " +

graph.add_edge("plan", "scan")                     f"Medium: {severity_breakdown.get('MEDIUM', 0)}",

graph.add_edge("scan", "decide")            "evidence": json.dumps(bandit_summary.get("issue_categories", [])[:3]),

            "remediation": "; ".join(bandit_summary.get("recommendations", []))

# Conditional edge from decide: if approval needed, go to human_gate, otherwise report        })

graph.add_conditional_edges(    

    "decide",    # Check SSL results

    lambda state: "human_gate" if state.get("requires_approval", False) else "report",    ssl_summary = summaries.get("ssl", {})

    {    if ssl_summary.get("success"):

        "human_gate": "human_gate",        if not ssl_summary.get("certificate_valid", True):

        "report": "report"            days_until_expiry = ssl_summary.get("days_until_expiry", 0)

    }            if days_until_expiry <= 7:

)                severity = "HIGH"

            elif days_until_expiry <= 30:

# Conditional edge from human_gate: stay in gate if still needs approval, otherwise report                severity = "MEDIUM"

graph.add_conditional_edges(            else:

    "human_gate",                 severity = "LOW"

    lambda state: "human_gate" if state.get("requires_approval", False) else "report",            

    {            findings.append({

        "human_gate": "human_gate",                "control": "A.10.1.1",

        "report": "report"                "control_family": "Cryptography",

    }                "severity": severity,

)                "title": "TLS/SSL certificate issues",

                "detail": f"Certificate expires in {days_until_expiry} days or has other issues.",

# End after report                "evidence": json.dumps(ssl_summary.get("security_issues", [])),

graph.add_edge("report", END)                "remediation": "; ".join(ssl_summary.get("recommendations", []))

            })

# Compile the graph    

app_graph = graph.compile()    # Check HTTP headers
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