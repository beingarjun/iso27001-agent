"""
Security Scanning Tools Integration
Enterprise-grade security scanning with multiple tool support
"""

import asyncio
import json
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import hashlib
import xml.etree.ElementTree as ET
import logging

from ..models import Finding, Evidence
from ..deps import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

class SecurityScanner:
    """Unified security scanning interface"""
    
    def __init__(self):
        self.scan_history = []
        self.evidence_dir = Path("evidence/scans")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    async def run_comprehensive_scan(
        self,
        org_id: int,
        target_path: str,
        scan_types: List[str] = None,
        config: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Run comprehensive security scan with multiple tools
        
        Args:
            org_id: Organization ID
            target_path: Path to scan (code repo, container, etc.)
            scan_types: Types of scans to run
            config: Additional configuration
        
        Returns:
            Comprehensive scan results
        """
        if scan_types is None:
            scan_types = ["sast", "dependency", "secrets", "container", "iac"]
        
        scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        start_time = datetime.utcnow()
        
        results = {
            "scan_id": scan_id,
            "org_id": org_id,
            "target_path": target_path,
            "scan_types": scan_types,
            "start_time": start_time.isoformat(),
            "end_time": None,
            "duration_seconds": None,
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "by_tool": {},
                "by_category": {}
            },
            "evidence_files": [],
            "errors": []
        }
        
        try:
            # Run different scan types
            for scan_type in scan_types:
                try:
                    logger.info(f"Running {scan_type} scan for org {org_id}")
                    
                    if scan_type == "sast":
                        scan_result = await self._run_sast_scan(target_path, scan_id)
                    elif scan_type == "dependency":
                        scan_result = await self._run_dependency_scan(target_path, scan_id)
                    elif scan_type == "secrets":
                        scan_result = await self._run_secrets_scan(target_path, scan_id)
                    elif scan_type == "container":
                        scan_result = await self._run_container_scan(target_path, scan_id)
                    elif scan_type == "iac":
                        scan_result = await self._run_iac_scan(target_path, scan_id)
                    else:
                        continue
                    
                    # Merge results
                    if scan_result.get("findings"):
                        results["findings"].extend(scan_result["findings"])
                    
                    if scan_result.get("evidence_files"):
                        results["evidence_files"].extend(scan_result["evidence_files"])
                    
                    if scan_result.get("errors"):
                        results["errors"].extend(scan_result["errors"])
                    
                    # Update summary by tool
                    results["summary"]["by_tool"][scan_type] = {
                        "findings_count": len(scan_result.get("findings", [])),
                        "status": "completed",
                        "duration": scan_result.get("duration_seconds", 0)
                    }
                    
                except Exception as e:
                    logger.error(f"Error running {scan_type} scan: {str(e)}")
                    results["errors"].append({
                        "scan_type": scan_type,
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    results["summary"]["by_tool"][scan_type] = {
                        "findings_count": 0,
                        "status": "error",
                        "error": str(e)
                    }
            
            # Calculate final summary
            for finding in results["findings"]:
                severity = finding["severity"].lower()
                results["summary"]["total_findings"] += 1
                
                if severity in results["summary"]:
                    results["summary"][severity] += 1
                
                category = finding.get("category", "unknown")
                results["summary"]["by_category"][category] = results["summary"]["by_category"].get(category, 0) + 1
            
            end_time = datetime.utcnow()
            results["end_time"] = end_time.isoformat()
            results["duration_seconds"] = (end_time - start_time).total_seconds()
            
            # Store scan history
            self.scan_history.append(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error in comprehensive scan: {str(e)}")
            results["errors"].append({
                "scan_type": "comprehensive",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            })
            return results
    
    async def _run_sast_scan(self, target_path: str, scan_id: str) -> Dict[str, Any]:
        """Run Static Application Security Testing (SAST) scan"""
        
        # Simulated SAST results - replace with actual tools like:
        # - Bandit (Python)
        # - ESLint Security (JavaScript)
        # - Semgrep
        # - CodeQL
        
        findings = [
            {
                "id": f"SAST-{uuid.uuid4().hex[:8].upper()}",
                "title": "SQL Injection vulnerability",
                "description": "User input not properly sanitized before database query",
                "severity": "HIGH",
                "category": "injection",
                "cwe": "CWE-89",
                "file_path": "src/models/user.py",
                "line_number": 45,
                "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
                "recommendation": "Use parameterized queries or ORM methods",
                "tool": "bandit",
                "rule_id": "B608",
                "confidence": "HIGH",
                "affected_controls": ["A.8.24", "A.14.2.1"]
            },
            {
                "id": f"SAST-{uuid.uuid4().hex[:8].upper()}",
                "title": "Hard-coded credentials",
                "description": "API key found in source code",
                "severity": "MEDIUM",
                "category": "secrets",
                "cwe": "CWE-798",
                "file_path": "config/settings.py",
                "line_number": 12,
                "code_snippet": "API_KEY = \"sk-1234567890abcdef\"",
                "recommendation": "Move credentials to environment variables",
                "tool": "bandit",
                "rule_id": "B105",
                "confidence": "HIGH",
                "affected_controls": ["A.9.4.3"]
            },
            {
                "id": f"SAST-{uuid.uuid4().hex[:8].upper()}",
                "title": "Insecure random number generation",
                "description": "Use of weak random number generator",
                "severity": "LOW",
                "category": "crypto",
                "cwe": "CWE-338",
                "file_path": "src/utils/token.py",
                "line_number": 23,
                "code_snippet": "token = random.random()",
                "recommendation": "Use cryptographically secure random number generator",
                "tool": "bandit",
                "rule_id": "B311",
                "confidence": "MEDIUM",
                "affected_controls": ["A.10.1.1"]
            }
        ]
        
        # Create evidence file
        evidence_file = self.evidence_dir / f"{scan_id}_sast_report.json"
        evidence_content = {
            "scan_type": "sast",
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            "target_path": target_path,
            "tool_version": "bandit-1.7.5",
            "findings": findings,
            "scan_stats": {
                "files_scanned": 156,
                "lines_of_code": 12450,
                "scan_duration_seconds": 45
            }
        }
        
        with open(evidence_file, 'w') as f:
            json.dump(evidence_content, f, indent=2)
        
        return {
            "findings": findings,
            "evidence_files": [str(evidence_file)],
            "duration_seconds": 45,
            "errors": []
        }
    
    async def _run_dependency_scan(self, target_path: str, scan_id: str) -> Dict[str, Any]:
        """Run dependency vulnerability scan"""
        
        # Simulated dependency scan results - replace with actual tools like:
        # - Safety (Python)
        # - npm audit (Node.js)
        # - OWASP Dependency Check
        # - Snyk
        
        findings = [
            {
                "id": f"DEP-{uuid.uuid4().hex[:8].upper()}",
                "title": "Known vulnerability in requests library",
                "description": "Requests library vulnerable to unintended proxy usage",
                "severity": "CRITICAL",
                "category": "dependency",
                "cve": "CVE-2023-32681",
                "package": "requests",
                "current_version": "2.28.0",
                "fixed_version": "2.31.0",
                "cvss_score": 9.1,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "recommendation": "Update requests to version 2.31.0 or later",
                "tool": "safety",
                "affected_controls": ["A.12.6.1", "A.8.31"]
            },
            {
                "id": f"DEP-{uuid.uuid4().hex[:8].upper()}",
                "title": "Vulnerability in Pillow library",
                "description": "Pillow library vulnerable to buffer overflow",
                "severity": "HIGH",
                "category": "dependency",
                "cve": "CVE-2023-44271",
                "package": "Pillow",
                "current_version": "9.5.0",
                "fixed_version": "10.0.1",
                "cvss_score": 7.5,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "recommendation": "Update Pillow to version 10.0.1 or later",
                "tool": "safety",
                "affected_controls": ["A.12.6.1"]
            },
            {
                "id": f"DEP-{uuid.uuid4().hex[:8].upper()}",
                "title": "Outdated FastAPI version",
                "description": "FastAPI version may have security issues",
                "severity": "MEDIUM",
                "category": "dependency",
                "cve": None,
                "package": "fastapi",
                "current_version": "0.95.0",
                "fixed_version": "0.104.1",
                "cvss_score": None,
                "vector": None,
                "recommendation": "Update FastAPI to latest version",
                "tool": "safety",
                "affected_controls": ["A.12.6.1"]
            }
        ]
        
        # Create evidence file
        evidence_file = self.evidence_dir / f"{scan_id}_dependency_report.json"
        evidence_content = {
            "scan_type": "dependency",
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            "target_path": target_path,
            "tool_version": "safety-2.3.4",
            "findings": findings,
            "scan_stats": {
                "packages_scanned": 89,
                "vulnerabilities_found": len(findings),
                "scan_duration_seconds": 15
            }
        }
        
        with open(evidence_file, 'w') as f:
            json.dump(evidence_content, f, indent=2)
        
        return {
            "findings": findings,
            "evidence_files": [str(evidence_file)],
            "duration_seconds": 15,
            "errors": []
        }
    
    async def _run_secrets_scan(self, target_path: str, scan_id: str) -> Dict[str, Any]:
        """Run secrets detection scan"""
        
        # Simulated secrets scan - replace with actual tools like:
        # - TruffleHog
        # - GitLeaks
        # - detect-secrets
        
        findings = [
            {
                "id": f"SECRET-{uuid.uuid4().hex[:8].upper()}",
                "title": "AWS Access Key detected",
                "description": "AWS access key found in configuration file",
                "severity": "CRITICAL",
                "category": "secrets",
                "secret_type": "aws_access_key",
                "file_path": ".env.example",
                "line_number": 8,
                "pattern_match": "AKIA[0-9A-Z]{16}",
                "entropy_score": 4.2,
                "recommendation": "Remove secret from code and rotate credentials",
                "tool": "trufflehog",
                "affected_controls": ["A.9.4.3", "A.10.1.2"]
            },
            {
                "id": f"SECRET-{uuid.uuid4().hex[:8].upper()}",
                "title": "Database password in code",
                "description": "Database connection string with password found",
                "severity": "HIGH",
                "category": "secrets",
                "secret_type": "database_password",
                "file_path": "scripts/backup.py",
                "line_number": 15,
                "pattern_match": "postgresql://user:password@host:5432/db",
                "entropy_score": 3.8,
                "recommendation": "Use environment variables for database credentials",
                "tool": "trufflehog",
                "affected_controls": ["A.9.4.3"]
            },
            {
                "id": f"SECRET-{uuid.uuid4().hex[:8].upper()}",
                "title": "Private key detected",
                "description": "RSA private key found in repository",
                "severity": "HIGH",
                "category": "secrets",
                "secret_type": "rsa_private_key",
                "file_path": "certs/test_key.pem",
                "line_number": 1,
                "pattern_match": "-----BEGIN RSA PRIVATE KEY-----",
                "entropy_score": 4.5,
                "recommendation": "Remove private key from repository and regenerate",
                "tool": "trufflehog",
                "affected_controls": ["A.10.1.2"]
            }
        ]
        
        # Create evidence file
        evidence_file = self.evidence_dir / f"{scan_id}_secrets_report.json"
        evidence_content = {
            "scan_type": "secrets",
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            "target_path": target_path,
            "tool_version": "trufflehog-3.54.0",
            "findings": findings,
            "scan_stats": {
                "files_scanned": 234,
                "commits_scanned": 156,
                "secrets_found": len(findings),
                "scan_duration_seconds": 120
            }
        }
        
        with open(evidence_file, 'w') as f:
            json.dump(evidence_content, f, indent=2)
        
        return {
            "findings": findings,
            "evidence_files": [str(evidence_file)],
            "duration_seconds": 120,
            "errors": []
        }
    
    async def _run_container_scan(self, target_path: str, scan_id: str) -> Dict[str, Any]:
        """Run container security scan"""
        
        # Simulated container scan - replace with actual tools like:
        # - Trivy
        # - Grype
        # - Clair
        # - Docker Scout
        
        findings = [
            {
                "id": f"CONTAINER-{uuid.uuid4().hex[:8].upper()}",
                "title": "Critical vulnerability in base image",
                "description": "OpenSSL vulnerability in Ubuntu base image",
                "severity": "CRITICAL",
                "category": "container",
                "cve": "CVE-2023-5678",
                "package": "openssl",
                "current_version": "3.0.2-0ubuntu1.10",
                "fixed_version": "3.0.2-0ubuntu1.12",
                "layer": "sha256:abc123...",
                "image": "ubuntu:22.04",
                "cvss_score": 9.8,
                "recommendation": "Update base image to latest version",
                "tool": "trivy",
                "affected_controls": ["A.12.6.1", "A.8.31"]
            },
            {
                "id": f"CONTAINER-{uuid.uuid4().hex[:8].upper()}",
                "title": "Container running as root",
                "description": "Container configured to run as root user",
                "severity": "HIGH",
                "category": "container_config",
                "misconfiguration": "ROOT_USER",
                "dockerfile_line": 25,
                "instruction": "USER root",
                "recommendation": "Create and use non-root user",
                "tool": "trivy",
                "affected_controls": ["A.9.2.3"]
            },
            {
                "id": f"CONTAINER-{uuid.uuid4().hex[:8].upper()}",
                "title": "Secrets in environment variables",
                "description": "Sensitive data exposed in environment variables",
                "severity": "MEDIUM",
                "category": "container_secrets",
                "env_var": "DATABASE_PASSWORD",
                "dockerfile_line": 18,
                "instruction": "ENV DATABASE_PASSWORD=secret123",
                "recommendation": "Use secrets management instead of environment variables",
                "tool": "trivy",
                "affected_controls": ["A.9.4.3"]
            }
        ]
        
        # Create evidence file
        evidence_file = self.evidence_dir / f"{scan_id}_container_report.json"
        evidence_content = {
            "scan_type": "container",
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            "target_path": target_path,
            "tool_version": "trivy-0.45.1",
            "findings": findings,
            "scan_stats": {
                "images_scanned": 3,
                "vulnerabilities_found": len(findings),
                "scan_duration_seconds": 180
            }
        }
        
        with open(evidence_file, 'w') as f:
            json.dump(evidence_content, f, indent=2)
        
        return {
            "findings": findings,
            "evidence_files": [str(evidence_file)],
            "duration_seconds": 180,
            "errors": []
        }
    
    async def _run_iac_scan(self, target_path: str, scan_id: str) -> Dict[str, Any]:
        """Run Infrastructure as Code (IaC) security scan"""
        
        # Simulated IaC scan - replace with actual tools like:
        # - Checkov
        # - Terrascan
        # - KICS
        # - Trivy (IaC mode)
        
        findings = [
            {
                "id": f"IAC-{uuid.uuid4().hex[:8].upper()}",
                "title": "S3 bucket publicly accessible",
                "description": "S3 bucket configured with public read access",
                "severity": "HIGH",
                "category": "iac",
                "resource_type": "aws_s3_bucket",
                "resource_name": "app-storage-bucket",
                "file_path": "terraform/s3.tf",
                "line_number": 15,
                "rule_id": "CKV_AWS_20",
                "recommendation": "Remove public access and use IAM policies",
                "tool": "checkov",
                "affected_controls": ["A.9.1.2", "A.13.1.3"]
            },
            {
                "id": f"IAC-{uuid.uuid4().hex[:8].upper()}",
                "title": "Security group allows all traffic",
                "description": "Security group configured with 0.0.0.0/0 access",
                "severity": "MEDIUM",
                "category": "iac",
                "resource_type": "aws_security_group",
                "resource_name": "web-sg",
                "file_path": "terraform/security_groups.tf",
                "line_number": 8,
                "rule_id": "CKV_AWS_24",
                "recommendation": "Restrict source IP ranges to specific networks",
                "tool": "checkov",
                "affected_controls": ["A.13.1.1"]
            },
            {
                "id": f"IAC-{uuid.uuid4().hex[:8].upper()}",
                "title": "RDS instance without encryption",
                "description": "RDS database instance not configured with encryption",
                "severity": "MEDIUM",
                "category": "iac",
                "resource_type": "aws_db_instance",
                "resource_name": "main-database",
                "file_path": "terraform/rds.tf",
                "line_number": 22,
                "rule_id": "CKV_AWS_16",
                "recommendation": "Enable encryption at rest for RDS instance",
                "tool": "checkov",
                "affected_controls": ["A.10.1.1"]
            }
        ]
        
        # Create evidence file
        evidence_file = self.evidence_dir / f"{scan_id}_iac_report.json"
        evidence_content = {
            "scan_type": "iac",
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            "target_path": target_path,
            "tool_version": "checkov-2.4.9",
            "findings": findings,
            "scan_stats": {
                "files_scanned": 23,
                "resources_scanned": 145,
                "violations_found": len(findings),
                "scan_duration_seconds": 35
            }
        }
        
        with open(evidence_file, 'w') as f:
            json.dump(evidence_content, f, indent=2)
        
        return {
            "findings": findings,
            "evidence_files": [str(evidence_file)],
            "duration_seconds": 35,
            "errors": []
        }

# AI-specific scanning and bias detection
class AIBiasScanner:
    """AI bias and fairness testing scanner"""
    
    def __init__(self):
        self.test_history = []
        self.evidence_dir = Path("evidence/bias_tests")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    async def run_bias_assessment(
        self,
        model_id: str,
        test_config: Dict[str, Any],
        org_id: int
    ) -> Dict[str, Any]:
        """
        Run comprehensive bias assessment for AI model
        
        Args:
            model_id: ID of the AI model to test
            test_config: Testing configuration
            org_id: Organization ID
        
        Returns:
            Bias assessment results
        """
        test_id = f"BIAS-{uuid.uuid4().hex[:8].upper()}"
        start_time = datetime.utcnow()
        
        # Simulated bias testing - replace with actual bias testing frameworks like:
        # - Fairlearn
        # - AIF360
        # - What-If Tool
        # - ML Fairness Gym
        
        results = {
            "test_id": test_id,
            "model_id": model_id,
            "org_id": org_id,
            "timestamp": start_time.isoformat(),
            "test_config": test_config,
            "metrics": {
                "demographic_parity_diff": 0.15,  # Threshold: 0.1
                "equalized_odds_diff": 0.08,      # Threshold: 0.1
                "statistical_parity_diff": 0.12,  # Threshold: 0.1
                "individual_fairness": 0.85,      # Threshold: 0.9
                "treatment_equality": 0.92,       # Threshold: 0.9
                "calibration": 0.88               # Threshold: 0.9
            },
            "threshold_violations": [],
            "protected_attributes": test_config.get("protected_attributes", ["race", "gender", "age"]),
            "test_dataset_size": test_config.get("dataset_size", 10000),
            "compliance_status": "PASS",
            "recommendations": [],
            "evidence_files": []
        }
        
        # Check threshold violations
        thresholds = {
            "demographic_parity_diff": 0.1,
            "equalized_odds_diff": 0.1,
            "statistical_parity_diff": 0.1,
            "individual_fairness": 0.9,
            "treatment_equality": 0.9,
            "calibration": 0.9
        }
        
        for metric, value in results["metrics"].items():
            threshold = thresholds.get(metric)
            if threshold:
                if metric in ["individual_fairness", "treatment_equality", "calibration"]:
                    # Higher is better for these metrics
                    if value < threshold:
                        violation = {
                            "metric": metric,
                            "value": value,
                            "threshold": threshold,
                            "severity": "HIGH" if value < (threshold - 0.05) else "MEDIUM",
                            "description": f"{metric} below acceptable threshold"
                        }
                        results["threshold_violations"].append(violation)
                else:
                    # Lower is better for difference metrics
                    if value > threshold:
                        violation = {
                            "metric": metric,
                            "value": value,
                            "threshold": threshold,
                            "severity": "HIGH" if value > (threshold + 0.05) else "MEDIUM",
                            "description": f"{metric} exceeds acceptable threshold"
                        }
                        results["threshold_violations"].append(violation)
        
        # Set overall compliance status
        if results["threshold_violations"]:
            results["compliance_status"] = "FAIL"
            
            # Generate recommendations
            results["recommendations"] = [
                "Retrain model with balanced dataset",
                "Implement fairness constraints during training",
                "Add bias monitoring in production",
                "Review protected attribute handling",
                "Consider demographic parity post-processing"
            ]
        else:
            results["recommendations"] = [
                "Continue monitoring model performance",
                "Regular bias assessments recommended",
                "Document bias testing procedures"
            ]
        
        # Create detailed evidence file
        evidence_file = self.evidence_dir / f"{test_id}_bias_assessment.json"
        evidence_content = {
            "test_summary": results,
            "detailed_metrics": {
                "by_protected_attribute": {
                    "race": {
                        "demographic_parity": {"white": 0.85, "black": 0.70, "hispanic": 0.72, "asian": 0.88},
                        "equalized_odds": {"white": 0.91, "black": 0.83, "hispanic": 0.85, "asian": 0.93}
                    },
                    "gender": {
                        "demographic_parity": {"male": 0.82, "female": 0.70, "non_binary": 0.68},
                        "equalized_odds": {"male": 0.89, "female": 0.81, "non_binary": 0.79}
                    }
                },
                "confusion_matrices": {
                    "overall": {"tp": 1250, "fp": 180, "tn": 8300, "fn": 270},
                    "by_race": {
                        "white": {"tp": 520, "fp": 45, "tn": 3200, "fn": 85},
                        "black": {"tp": 180, "fp": 65, "tn": 1100, "fn": 95}
                    }
                }
            },
            "model_info": {
                "model_type": "classification",
                "training_data_size": 50000,
                "features_count": 45,
                "model_architecture": "random_forest"
            }
        }
        
        with open(evidence_file, 'w') as f:
            json.dump(evidence_content, f, indent=2)
        
        results["evidence_files"].append(str(evidence_file))
        
        # Store test history
        self.test_history.append(results)
        
        return results

# Factory functions
def create_security_scanner() -> SecurityScanner:
    """Create and configure security scanner"""
    return SecurityScanner()

def create_ai_bias_scanner() -> AIBiasScanner:
    """Create and configure AI bias scanner"""
    return AIBiasScanner()