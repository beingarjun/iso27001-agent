"""
CI/CD Pipeline Integration
Security gates with automated scanning and HIGH finding blocking
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from .tools.security_scanners import SecurityScanner
from .tools.evidence_collector import EvidenceCollector

class PipelineIntegration:
    """CI/CD pipeline security gates and automation"""
    
    def __init__(self, security_scanner: SecurityScanner, evidence_collector: EvidenceCollector):
        self.security_scanner = security_scanner
        self.evidence_collector = evidence_collector
    
    async def run_security_gate(
        self,
        project_path: str,
        branch: str,
        commit_sha: str,
        pipeline_id: str
    ) -> Dict[str, Any]:
        """Execute security gate with multiple scans"""
        
        gate_result = {
            "pipeline_id": pipeline_id,
            "project_path": project_path,
            "branch": branch,
            "commit_sha": commit_sha,
            "started_at": datetime.utcnow().isoformat(),
            "gate_status": "RUNNING",
            "scans": {},
            "blocking_findings": [],
            "gate_passed": False
        }
        
        try:
            # Run security scans in parallel
            scan_tasks = [
                self._run_sast_scan(project_path, pipeline_id),
                self._run_dependency_scan(project_path, pipeline_id),
                self._run_secrets_scan(project_path, pipeline_id),
                self._run_iac_scan(project_path, pipeline_id)
            ]
            
            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Process scan results
            high_findings = []
            for i, result in enumerate(scan_results):
                scan_type = ["sast", "dependency", "secrets", "iac"][i]
                
                if isinstance(result, Exception):
                    gate_result["scans"][scan_type] = {"error": str(result)}
                    continue
                
                gate_result["scans"][scan_type] = result
                
                # Check for HIGH/CRITICAL findings
                findings = result.get("findings", [])
                for finding in findings:
                    if finding.get("severity") in ["HIGH", "CRITICAL"]:
                        high_findings.append({
                            "scan_type": scan_type,
                            "finding": finding,
                            "blocking": True
                        })
            
            gate_result["blocking_findings"] = high_findings
            gate_result["gate_passed"] = len(high_findings) == 0
            gate_result["gate_status"] = "PASSED" if gate_result["gate_passed"] else "BLOCKED"
            
            # Generate evidence
            if gate_result["gate_passed"]:
                await self._generate_gate_evidence(gate_result)
            
            return gate_result
            
        except Exception as e:
            gate_result["gate_status"] = "ERROR"
            gate_result["error"] = str(e)
            return gate_result
        
        finally:
            gate_result["completed_at"] = datetime.utcnow().isoformat()
    
    async def generate_github_action(self, config: Dict[str, Any]) -> str:
        """Generate GitHub Actions workflow for security gates"""
        
        workflow = {
            "name": "Security Gate",
            "on": {
                "pull_request": {"branches": ["main", "develop"]},
                "push": {"branches": ["main"]}
            },
            "jobs": {
                "security-scan": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "actions/checkout@v4"},
                        {"name": "Set up Python", "uses": "actions/setup-python@v4", "with": {"python-version": "3.11"}},
                        {"name": "Install dependencies", "run": "pip install bandit safety semgrep trivy"},
                        {"name": "Run SAST", "run": "bandit -r . -f json -o bandit-report.json || true"},
                        {"name": "Run Dependency Check", "run": "safety check --json --output safety-report.json || true"},
                        {"name": "Run Secrets Scan", "run": "docker run --rm -v \"$PWD:/pwd\" trufflesecurity/trufflehog:latest filesystem /pwd --json > secrets-report.json || true"},
                        {"name": "Evaluate Security Gate", "run": "python .github/scripts/security-gate.py"}
                    ]
                }
            }
        }
        
        return json.dumps(workflow, indent=2)
    
    async def generate_jenkins_pipeline(self, config: Dict[str, Any]) -> str:
        """Generate Jenkins pipeline for security gates"""
        
        pipeline = """
pipeline {
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Security Scans') {
            parallel {
                stage('SAST') {
                    steps {
                        sh 'bandit -r . -f json -o bandit-report.json || true'
                    }
                }
                stage('Dependencies') {
                    steps {
                        sh 'safety check --json --output safety-report.json || true'
                    }
                }
                stage('Secrets') {
                    steps {
                        sh 'docker run --rm -v "$PWD:/pwd" trufflesecurity/trufflehog:latest filesystem /pwd --json > secrets-report.json || true'
                    }
                }
            }
        }
        
        stage('Security Gate') {
            steps {
                script {
                    def gateResult = sh(script: 'python scripts/security-gate.py', returnStatus: true)
                    if (gateResult != 0) {
                        error('Security gate failed - HIGH/CRITICAL findings detected')
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: '*-report.json', fingerprint: true
        }
    }
}
"""
        return pipeline
    
    async def _run_sast_scan(self, project_path: str, pipeline_id: str) -> Dict[str, Any]:
        """Run SAST scan"""
        return await self.security_scanner.run_scan("sast", project_path)
    
    async def _run_dependency_scan(self, project_path: str, pipeline_id: str) -> Dict[str, Any]:
        """Run dependency scan"""
        return await self.security_scanner.run_scan("dependency", project_path)
    
    async def _run_secrets_scan(self, project_path: str, pipeline_id: str) -> Dict[str, Any]:
        """Run secrets scan"""
        return await self.security_scanner.run_scan("secrets", project_path)
    
    async def _run_iac_scan(self, project_path: str, pipeline_id: str) -> Dict[str, Any]:
        """Run IaC scan"""
        return await self.security_scanner.run_scan("iac", project_path)
    
    async def _generate_gate_evidence(self, gate_result: Dict[str, Any]):
        """Generate evidence for successful security gate"""
        evidence_title = f"Security Gate - {gate_result['pipeline_id']}"
        evidence_content = json.dumps(gate_result, indent=2, default=str)
        
        await self.evidence_collector.store_evidence(
            title=evidence_title,
            description=f"Security gate results for pipeline {gate_result['pipeline_id']}",
            evidence_type="SECURITY_GATE",
            file_content=evidence_content.encode('utf-8'),
            file_name=f"security_gate_{gate_result['pipeline_id']}.json",
            mime_type="application/json",
            org_id=1,  # Would be dynamic
            collected_by="pipeline_automation"
        )

def create_pipeline_integration(security_scanner: SecurityScanner, evidence_collector: EvidenceCollector) -> PipelineIntegration:
    """Create pipeline integration instance"""
    return PipelineIntegration(security_scanner, evidence_collector)