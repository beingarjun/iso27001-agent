"""
ISO 27001 Compliance Agent - LangGraph Workflow Implementation
Enterprise-grade compliance automation with AI governance (ISO 42001)
"""

from typing import Dict, List, Optional, Literal, Any, TypedDict, Annotated
from datetime import datetime, timedelta
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph.message import add_messages
import json
import asyncio
from pathlib import Path
import hashlib
import uuid

from ..models import *
from ..deps import get_settings

settings = get_settings()

# Workflow State Definition
class ComplianceWorkflowState(TypedDict):
    """State for compliance automation workflow"""
    messages: Annotated[List, add_messages]
    org_id: int
    user_id: str
    workflow_type: str  # "risk_assessment", "control_review", "finding_analysis", "ai_governance"
    context: Dict[str, Any]
    findings: List[Dict]
    risks: List[Dict]
    controls: List[Dict]
    ai_models: List[Dict]
    human_approval_required: bool
    approval_pending: bool
    approval_reason: str
    evidence_collected: List[Dict]
    recommendations: List[Dict]
    current_step: str
    execution_log: List[Dict]
    error_occurred: bool
    error_message: str

# Tools for the compliance agent
@tool
async def scan_code_repository(repo_path: str, scan_types: List[str]) -> Dict[str, Any]:
    """
    Scan code repository for security vulnerabilities and compliance issues
    
    Args:
        repo_path: Path to the code repository
        scan_types: Types of scans to perform ["sast", "dependency", "secrets", "iac"]
    
    Returns:
        Dict containing scan results with findings
    """
    findings = []
    evidence_files = []
    
    try:
        # Simulated scanning logic - replace with actual scanner integrations
        scan_results = {
            "scan_id": f"SCAN-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.utcnow().isoformat(),
            "repo_path": repo_path,
            "scan_types": scan_types,
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
        
        # SAST Scan simulation
        if "sast" in scan_types:
            sast_findings = [
                {
                    "type": "sast",
                    "severity": "HIGH",
                    "title": "SQL Injection vulnerability detected",
                    "description": "User input not properly sanitized before database query",
                    "file": "src/models/user.py",
                    "line": 45,
                    "cwe": "CWE-89",
                    "affected_controls": ["A.8.24", "A.14.2.1"]
                },
                {
                    "type": "sast", 
                    "severity": "MEDIUM",
                    "title": "Hardcoded credentials found",
                    "description": "API key found in source code",
                    "file": "config/settings.py",
                    "line": 12,
                    "cwe": "CWE-798",
                    "affected_controls": ["A.9.4.3"]
                }
            ]
            scan_results["findings"].extend(sast_findings)
        
        # Dependency scan simulation
        if "dependency" in scan_types:
            dep_findings = [
                {
                    "type": "dependency",
                    "severity": "CRITICAL",
                    "title": "Known vulnerability in requests library",
                    "description": "CVE-2023-32681: Requests vulnerable to unintended proxy usage",
                    "package": "requests==2.28.0",
                    "cve": "CVE-2023-32681",
                    "affected_controls": ["A.12.6.1", "A.8.31"]
                }
            ]
            scan_results["findings"].extend(dep_findings)
        
        # Update summary counts
        for finding in scan_results["findings"]:
            scan_results["summary"]["total_findings"] += 1
            severity = finding["severity"].lower()
            if severity in scan_results["summary"]:
                scan_results["summary"][severity] += 1
        
        return scan_results
        
    except Exception as e:
        return {
            "error": str(e),
            "scan_id": None,
            "findings": []
        }

@tool
async def assess_ai_model_bias(model_id: str, test_config: Dict) -> Dict[str, Any]:
    """
    Assess AI model for bias and fairness issues
    
    Args:
        model_id: ID of the AI model to test
        test_config: Configuration for bias testing
    
    Returns:
        Dict containing bias assessment results
    """
    try:
        # Simulated bias testing - replace with actual bias testing frameworks
        bias_results = {
            "test_id": f"BIAS-{uuid.uuid4().hex[:8].upper()}",
            "model_id": model_id,
            "timestamp": datetime.utcnow().isoformat(),
            "test_config": test_config,
            "metrics": {
                "demographic_parity_diff": 0.15,  # Threshold: 0.1
                "equalized_odds_diff": 0.08,      # Threshold: 0.1
                "statistical_parity_diff": 0.12   # Threshold: 0.1
            },
            "threshold_violations": [
                {
                    "metric": "demographic_parity_diff",
                    "value": 0.15,
                    "threshold": 0.1,
                    "severity": "HIGH",
                    "protected_attribute": "race"
                },
                {
                    "metric": "statistical_parity_diff", 
                    "value": 0.12,
                    "threshold": 0.1,
                    "severity": "MEDIUM",
                    "protected_attribute": "gender"
                }
            ],
            "compliance_status": "FAIL",
            "recommendations": [
                "Retrain model with balanced dataset",
                "Implement fairness constraints during training",
                "Add bias monitoring in production"
            ]
        }
        
        return bias_results
        
    except Exception as e:
        return {
            "error": str(e),
            "test_id": None,
            "compliance_status": "ERROR"
        }

@tool
async def generate_evidence_package(finding_id: str, evidence_types: List[str]) -> Dict[str, Any]:
    """
    Generate comprehensive evidence package for findings
    
    Args:
        finding_id: ID of the finding to collect evidence for
        evidence_types: Types of evidence to collect
    
    Returns:
        Dict containing evidence package details
    """
    try:
        evidence_package = {
            "package_id": f"EVD-{uuid.uuid4().hex[:8].upper()}",
            "finding_id": finding_id,
            "timestamp": datetime.utcnow().isoformat(),
            "evidence_items": [],
            "integrity_hash": None
        }
        
        # Collect different types of evidence
        for evidence_type in evidence_types:
            if evidence_type == "screenshot":
                evidence_item = {
                    "type": "screenshot",
                    "file_path": f"evidence/screenshots/{finding_id}_screenshot.png",
                    "description": "Screenshot of vulnerability in web interface",
                    "hash": hashlib.sha256(f"screenshot_data_{finding_id}".encode()).hexdigest(),
                    "timestamp": datetime.utcnow().isoformat()
                }
            elif evidence_type == "log_file":
                evidence_item = {
                    "type": "log_file",
                    "file_path": f"evidence/logs/{finding_id}_access.log",
                    "description": "Access logs showing unauthorized access attempts",
                    "hash": hashlib.sha256(f"log_data_{finding_id}".encode()).hexdigest(),
                    "timestamp": datetime.utcnow().isoformat()
                }
            elif evidence_type == "scan_output":
                evidence_item = {
                    "type": "scan_output",
                    "file_path": f"evidence/scans/{finding_id}_scan_report.json",
                    "description": "Raw scanner output with vulnerability details",
                    "hash": hashlib.sha256(f"scan_data_{finding_id}".encode()).hexdigest(),
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                continue
                
            evidence_package["evidence_items"].append(evidence_item)
        
        # Generate integrity hash for entire package
        package_content = json.dumps(evidence_package["evidence_items"], sort_keys=True)
        evidence_package["integrity_hash"] = hashlib.sha256(package_content.encode()).hexdigest()
        
        return evidence_package
        
    except Exception as e:
        return {
            "error": str(e),
            "package_id": None
        }

@tool
async def check_control_implementation(control_id: str, org_id: int) -> Dict[str, Any]:
    """
    Check implementation status of a specific control
    
    Args:
        control_id: ISO 27001 control ID (e.g., "A.8.24")
        org_id: Organization ID
    
    Returns:
        Dict containing control implementation status
    """
    try:
        # Simulated control check - replace with actual implementation
        control_status = {
            "control_id": control_id,
            "org_id": org_id,
            "timestamp": datetime.utcnow().isoformat(),
            "implementation_status": "PARTIALLY_IMPLEMENTED",
            "compliance_percentage": 75,
            "gaps_identified": [
                "Automated monitoring not fully configured",
                "Documentation needs update",
                "Training completion at 60%"
            ],
            "evidence_available": True,
            "last_assessment": "2024-01-15",
            "next_review_due": "2024-04-15",
            "responsible_party": "IT Security Team",
            "recommendations": [
                "Complete monitoring tool configuration",
                "Update control documentation",
                "Schedule remaining training sessions"
            ]
        }
        
        return control_status
        
    except Exception as e:
        return {
            "error": str(e),
            "control_id": control_id,
            "implementation_status": "ERROR"
        }

# LangGraph Workflow Implementation
class ComplianceAgent:
    """Main compliance automation agent with LangGraph workflows"""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model="gpt-4o",
            temperature=0.1,
            openai_api_key=settings.openai_api_key
        )
        
        # Define tools
        self.tools = [
            scan_code_repository,
            assess_ai_model_bias, 
            generate_evidence_package,
            check_control_implementation
        ]
        
        # Create tool node
        self.tool_node = ToolNode(self.tools)
        
        # Initialize workflow graph
        self.workflow = self._create_workflow()
        self.memory = MemorySaver()
        
    def _create_workflow(self) -> StateGraph:
        """Create the LangGraph workflow for compliance automation"""
        
        # Create workflow graph
        workflow = StateGraph(ComplianceWorkflowState)
        
        # Add nodes
        workflow.add_node("analyzer", self._analyze_request)
        workflow.add_node("scanner", self._execute_scans)
        workflow.add_node("ai_assessor", self._assess_ai_risks)
        workflow.add_node("evidence_collector", self._collect_evidence)
        workflow.add_node("risk_evaluator", self._evaluate_risks)
        workflow.add_node("human_approval", self._require_human_approval)
        workflow.add_node("report_generator", self._generate_reports)
        workflow.add_node("tools", self.tool_node)
        
        # Set entry point
        workflow.set_entry_point("analyzer")
        
        # Add edges and conditional routing
        workflow.add_edge("analyzer", "scanner")
        workflow.add_edge("scanner", "ai_assessor")
        workflow.add_edge("ai_assessor", "evidence_collector")
        workflow.add_edge("evidence_collector", "risk_evaluator")
        
        # Conditional edge for human approval
        workflow.add_conditional_edges(
            "risk_evaluator",
            self._should_require_approval,
            {
                "human_approval": "human_approval",
                "report_generator": "report_generator"
            }
        )
        
        workflow.add_edge("human_approval", "report_generator")
        workflow.add_edge("report_generator", END)
        
        return workflow
    
    async def _analyze_request(self, state: ComplianceWorkflowState) -> ComplianceWorkflowState:
        """Analyze incoming request and determine workflow path"""
        
        system_prompt = """You are an expert ISO 27001 compliance analyst with deep knowledge of:
        - ISO 27001:2022 controls and requirements
        - ISO 42001 AI governance standards
        - Risk assessment methodologies
        - Security scanning and vulnerability management
        - Evidence collection and audit preparation
        
        Analyze the request and determine:
        1. What type of compliance activity is needed
        2. Which scans or assessments to perform
        3. What evidence needs to be collected
        4. Risk levels and approval requirements
        
        Consider AI governance requirements for any AI/ML systems involved."""
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            MessagesPlaceholder(variable_name="messages"),
            ("human", "Analyze this compliance request and provide your assessment.")
        ])
        
        messages = [prompt.format_messages(messages=state["messages"])[0]]
        response = await self.llm.ainvoke(messages)
        
        # Update state based on analysis
        state["current_step"] = "analysis_complete"
        state["context"]["analysis"] = response.content
        state["execution_log"].append({
            "step": "analyzer",
            "timestamp": datetime.utcnow().isoformat(),
            "result": "Analysis completed"
        })
        
        return state
    
    async def _execute_scans(self, state: ComplianceWorkflowState) -> ComplianceWorkflowState:
        """Execute security scans based on analysis"""
        
        # Determine what scans to run based on context
        scan_config = {
            "repo_path": state["context"].get("repo_path", "/app"),
            "scan_types": ["sast", "dependency", "secrets", "iac"]
        }
        
        # Execute scans using tools
        scan_results = await scan_code_repository.ainvoke(scan_config)
        
        # Process findings
        findings = []
        for finding_data in scan_results.get("findings", []):
            finding = {
                "id": f"FIND-{uuid.uuid4().hex[:8].upper()}",
                "title": finding_data["title"],
                "description": finding_data["description"],
                "severity": finding_data["severity"],
                "type": finding_data["type"],
                "source": "AUTOMATED_SCAN",
                "affected_controls": finding_data.get("affected_controls", []),
                "raw_data": finding_data
            }
            findings.append(finding)
        
        state["findings"] = findings
        state["current_step"] = "scanning_complete"
        state["execution_log"].append({
            "step": "scanner",
            "timestamp": datetime.utcnow().isoformat(),
            "result": f"Found {len(findings)} security findings"
        })
        
        return state
    
    async def _assess_ai_risks(self, state: ComplianceWorkflowState) -> ComplianceWorkflowState:
        """Assess AI-specific risks and bias issues"""
        
        ai_findings = []
        
        # Check if there are AI models to assess
        ai_models = state.get("ai_models", [])
        
        for model in ai_models:
            bias_config = {
                "protected_attributes": ["race", "gender", "age"],
                "test_dataset": "test_data/bias_test.csv",
                "metrics": ["demographic_parity", "equalized_odds"]
            }
            
            bias_results = await assess_ai_model_bias.ainvoke({
                "model_id": model["id"],
                "test_config": bias_config
            })
            
            # Convert bias violations to findings
            for violation in bias_results.get("threshold_violations", []):
                finding = {
                    "id": f"AI-BIAS-{uuid.uuid4().hex[:8].upper()}",
                    "title": f"AI Bias Detected: {violation['metric']}",
                    "description": f"Model {model['id']} violates {violation['metric']} threshold",
                    "severity": violation["severity"],
                    "type": "AI_BIAS",
                    "source": "AI_EVALUATION",
                    "model_affected": model["id"],
                    "bias_metric": violation["metric"],
                    "raw_data": violation
                }
                ai_findings.append(finding)
        
        # Add AI findings to state
        state["findings"].extend(ai_findings)
        state["current_step"] = "ai_assessment_complete"
        state["execution_log"].append({
            "step": "ai_assessor",
            "timestamp": datetime.utcnow().isoformat(),
            "result": f"Assessed {len(ai_models)} AI models, found {len(ai_findings)} bias issues"
        })
        
        return state
    
    async def _collect_evidence(self, state: ComplianceWorkflowState) -> ComplianceWorkflowState:
        """Collect evidence for all findings"""
        
        evidence_packages = []
        
        for finding in state["findings"]:
            evidence_types = ["scan_output"]
            
            # Add specific evidence types based on finding type
            if finding["type"] == "sast":
                evidence_types.extend(["screenshot", "log_file"])
            elif finding["type"] == "AI_BIAS":
                evidence_types.extend(["test_report", "metrics_data"])
            
            evidence_package = await generate_evidence_package.ainvoke({
                "finding_id": finding["id"],
                "evidence_types": evidence_types
            })
            
            evidence_packages.append(evidence_package)
        
        state["evidence_collected"] = evidence_packages
        state["current_step"] = "evidence_collection_complete"
        state["execution_log"].append({
            "step": "evidence_collector",
            "timestamp": datetime.utcnow().isoformat(),
            "result": f"Collected evidence for {len(evidence_packages)} findings"
        })
        
        return state
    
    async def _evaluate_risks(self, state: ComplianceWorkflowState) -> ComplianceWorkflowState:
        """Evaluate risks and determine if human approval is needed"""
        
        high_risk_findings = []
        requires_approval = False
        
        for finding in state["findings"]:
            if finding["severity"] in ["HIGH", "CRITICAL"]:
                high_risk_findings.append(finding)
                requires_approval = True
            
            # AI bias findings always require approval
            if finding["type"] == "AI_BIAS":
                requires_approval = True
        
        # Calculate risk scores and priorities
        risk_summary = {
            "total_findings": len(state["findings"]),
            "high_risk_count": len(high_risk_findings),
            "requires_approval": requires_approval,
            "approval_reason": "HIGH or CRITICAL severity findings detected" if requires_approval else None
        }
        
        state["human_approval_required"] = requires_approval
        state["approval_reason"] = risk_summary["approval_reason"]
        state["context"]["risk_summary"] = risk_summary
        state["current_step"] = "risk_evaluation_complete"
        state["execution_log"].append({
            "step": "risk_evaluator",
            "timestamp": datetime.utcnow().isoformat(),
            "result": f"Risk evaluation complete. Approval required: {requires_approval}"
        })
        
        return state
    
    def _should_require_approval(self, state: ComplianceWorkflowState) -> str:
        """Conditional function to determine if human approval is needed"""
        return "human_approval" if state["human_approval_required"] else "report_generator"
    
    async def _require_human_approval(self, state: ComplianceWorkflowState) -> ComplianceWorkflowState:
        """Handle human approval workflow"""
        
        # In a real implementation, this would:
        # 1. Send notification to approvers
        # 2. Create approval task in UI
        # 3. Wait for human decision
        # 4. Log approval decision
        
        approval_request = {
            "request_id": f"APPROVAL-{uuid.uuid4().hex[:8].upper()}",
            "reason": state["approval_reason"],
            "findings_count": len(state["findings"]),
            "high_risk_count": len([f for f in state["findings"] if f["severity"] in ["HIGH", "CRITICAL"]]),
            "ai_findings_count": len([f for f in state["findings"] if f["type"] == "AI_BIAS"]),
            "requested_at": datetime.utcnow().isoformat(),
            "status": "PENDING"
        }
        
        state["approval_pending"] = True
        state["context"]["approval_request"] = approval_request
        state["current_step"] = "awaiting_human_approval"
        state["execution_log"].append({
            "step": "human_approval",
            "timestamp": datetime.utcnow().isoformat(),
            "result": "Human approval requested"
        })
        
        return state
    
    async def _generate_reports(self, state: ComplianceWorkflowState) -> ComplianceWorkflowState:
        """Generate compliance reports and deliverables"""
        
        # Generate different report types
        reports = []
        
        # Finding Summary Report
        finding_report = {
            "type": "finding_summary",
            "timestamp": datetime.utcnow().isoformat(),
            "total_findings": len(state["findings"]),
            "by_severity": {
                "CRITICAL": len([f for f in state["findings"] if f["severity"] == "CRITICAL"]),
                "HIGH": len([f for f in state["findings"] if f["severity"] == "HIGH"]),
                "MEDIUM": len([f for f in state["findings"] if f["severity"] == "MEDIUM"]),
                "LOW": len([f for f in state["findings"] if f["severity"] == "LOW"])
            },
            "by_type": {},
            "recommendations": []
        }
        
        # Count by type
        for finding in state["findings"]:
            finding_type = finding["type"]
            finding_report["by_type"][finding_type] = finding_report["by_type"].get(finding_type, 0) + 1
        
        reports.append(finding_report)
        
        # Risk Register Update
        risk_register_update = {
            "type": "risk_register_update",
            "timestamp": datetime.utcnow().isoformat(),
            "new_risks_identified": len(state["findings"]),
            "ai_risks_identified": len([f for f in state["findings"] if f["type"] == "AI_BIAS"]),
            "control_gaps_found": sum(len(f.get("affected_controls", [])) for f in state["findings"])
        }
        
        reports.append(risk_register_update)
        
        state["context"]["generated_reports"] = reports
        state["current_step"] = "workflow_complete"
        state["execution_log"].append({
            "step": "report_generator",
            "timestamp": datetime.utcnow().isoformat(),
            "result": f"Generated {len(reports)} reports"
        })
        
        return state
    
    async def run_compliance_workflow(
        self,
        org_id: int,
        user_id: str,
        workflow_type: str,
        initial_message: str,
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Run the compliance workflow
        
        Args:
            org_id: Organization ID
            user_id: User ID initiating the workflow
            workflow_type: Type of workflow to run
            initial_message: Initial message/request
            context: Additional context for the workflow
        
        Returns:
            Dict containing workflow results
        """
        
        # Initialize state
        initial_state = ComplianceWorkflowState(
            messages=[HumanMessage(content=initial_message)],
            org_id=org_id,
            user_id=user_id,
            workflow_type=workflow_type,
            context=context or {},
            findings=[],
            risks=[],
            controls=[],
            ai_models=context.get("ai_models", []) if context else [],
            human_approval_required=False,
            approval_pending=False,
            approval_reason="",
            evidence_collected=[],
            recommendations=[],
            current_step="initializing",
            execution_log=[],
            error_occurred=False,
            error_message=""
        )
        
        try:
            # Compile and run workflow
            app = self.workflow.compile(checkpointer=self.memory)
            
            # Run workflow
            final_state = await app.ainvoke(
                initial_state,
                config={"configurable": {"thread_id": f"compliance-{org_id}-{uuid.uuid4().hex[:8]}"}}
            )
            
            return {
                "success": True,
                "workflow_id": f"WF-{uuid.uuid4().hex[:8].upper()}",
                "final_state": final_state,
                "findings_count": len(final_state["findings"]),
                "evidence_packages": len(final_state["evidence_collected"]),
                "approval_required": final_state["human_approval_required"],
                "execution_log": final_state["execution_log"]
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "workflow_id": None,
                "final_state": None
            }

# Factory function for creating agents
def create_compliance_agent() -> ComplianceAgent:
    """Factory function to create and configure compliance agent"""
    return ComplianceAgent()