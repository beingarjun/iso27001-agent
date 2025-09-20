"""
Evidence Collection Automation
Automated evidence collection from security scans, compliance checks, and manual uploads
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import uuid

from .evidence_manager import EvidenceManager
from .security_scanners import SecurityScanner, AIBiasScanner
from ...models import Finding, Evidence, ControlImplementation

logger = logging.getLogger(__name__)

class EvidenceCollector:
    """Automated evidence collection and processing"""
    
    def __init__(self, evidence_manager: EvidenceManager):
        self.evidence_manager = evidence_manager
        self.security_scanner = SecurityScanner()
        self.ai_bias_scanner = AIBiasScanner()
    
    async def collect_scan_evidence(
        self,
        scan_type: str,
        target: str,
        org_id: int,
        collected_by: str,
        audit_period: Optional[str] = None,
        control_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Collect evidence from security scans
        
        Args:
            scan_type: Type of scan (sast, dependency, secrets, container, iac)
            target: Scan target (file path, container image, etc.)
            org_id: Organization ID
            collected_by: User collecting evidence
            audit_period: Audit period
            control_id: Related control ID
        
        Returns:
            Dict containing evidence collection results
        """
        
        try:
            collection_id = f"SCAN-{scan_type.upper()}-{uuid.uuid4().hex[:8].upper()}"
            
            # Perform security scan
            if scan_type == "ai_bias":
                scan_result = await self.ai_bias_scanner.scan_ai_bias(
                    model_path=target,
                    test_data_path=None,  # Will be provided separately
                    fairness_metrics=["demographic_parity", "equalized_odds"]
                )
            else:
                scan_result = await self.security_scanner.run_scan(
                    scan_type=scan_type,
                    target=target
                )
            
            # Generate evidence files
            evidence_files = []
            
            # 1. Scan report (JSON)
            report_content = json.dumps(scan_result, indent=2, default=str)
            report_evidence = self.evidence_manager.store_evidence(
                title=f"{scan_type.upper()} Scan Report",
                description=f"Automated {scan_type} security scan results for {target}",
                evidence_type="SCAN_REPORT",
                file_content=report_content.encode('utf-8'),
                file_name=f"{collection_id}_report.json",
                mime_type="application/json",
                org_id=org_id,
                collected_by=collected_by,
                control_id=control_id,
                audit_period=audit_period,
                is_sensitive=scan_result.get("has_high_severity", False)
            )
            evidence_files.append(report_evidence)
            
            # 2. Summary report (Markdown)
            summary_md = self._generate_scan_summary(scan_result, scan_type, target)
            summary_evidence = self.evidence_manager.store_evidence(
                title=f"{scan_type.upper()} Scan Summary",
                description=f"Human-readable summary of {scan_type} scan results",
                evidence_type="SUMMARY_REPORT",
                file_content=summary_md.encode('utf-8'),
                file_name=f"{collection_id}_summary.md",
                mime_type="text/markdown",
                org_id=org_id,
                collected_by=collected_by,
                control_id=control_id,
                audit_period=audit_period
            )
            evidence_files.append(summary_evidence)
            
            # 3. Findings export (CSV)
            if scan_result.get("findings"):
                findings_csv = self._generate_findings_csv(scan_result["findings"])
                findings_evidence = self.evidence_manager.store_evidence(
                    title=f"{scan_type.upper()} Findings Export",
                    description=f"CSV export of findings from {scan_type} scan",
                    evidence_type="FINDINGS_EXPORT",
                    file_content=findings_csv.encode('utf-8'),
                    file_name=f"{collection_id}_findings.csv",
                    mime_type="text/csv",
                    org_id=org_id,
                    collected_by=collected_by,
                    control_id=control_id,
                    audit_period=audit_period
                )
                evidence_files.append(findings_evidence)
            
            # 4. Tool configuration (JSON)
            tool_config = {
                "scan_type": scan_type,
                "target": target,
                "scan_timestamp": datetime.utcnow().isoformat(),
                "tool_version": scan_result.get("tool_version", "unknown"),
                "scan_duration": scan_result.get("scan_duration", 0),
                "parameters": scan_result.get("scan_parameters", {})
            }
            config_evidence = self.evidence_manager.store_evidence(
                title=f"{scan_type.upper()} Tool Configuration",
                description=f"Configuration and metadata for {scan_type} scan execution",
                evidence_type="TOOL_CONFIG",
                file_content=json.dumps(tool_config, indent=2).encode('utf-8'),
                file_name=f"{collection_id}_config.json",
                mime_type="application/json",
                org_id=org_id,
                collected_by=collected_by,
                control_id=control_id,
                audit_period=audit_period
            )
            evidence_files.append(config_evidence)
            
            return {
                "collection_id": collection_id,
                "scan_type": scan_type,
                "target": target,
                "evidence_count": len(evidence_files),
                "evidence_files": evidence_files,
                "scan_summary": {
                    "total_findings": len(scan_result.get("findings", [])),
                    "high_severity": len([f for f in scan_result.get("findings", []) if f.get("severity") == "HIGH"]),
                    "medium_severity": len([f for f in scan_result.get("findings", []) if f.get("severity") == "MEDIUM"]),
                    "low_severity": len([f for f in scan_result.get("findings", []) if f.get("severity") == "LOW"]),
                    "scan_duration": scan_result.get("scan_duration", 0)
                },
                "collected_at": datetime.utcnow().isoformat(),
                "collected_by": collected_by
            }
            
        except Exception as e:
            logger.error(f"Evidence collection failed for {scan_type} scan: {str(e)}")
            raise Exception(f"Evidence collection failed: {str(e)}")
    
    async def collect_control_evidence(
        self,
        control_id: str,
        implementation_details: Dict[str, Any],
        org_id: int,
        collected_by: str,
        audit_period: str
    ) -> Dict[str, Any]:
        """
        Collect evidence for control implementation
        
        Args:
            control_id: ISO 27001 control identifier
            implementation_details: Control implementation details
            org_id: Organization ID
            collected_by: User collecting evidence
            audit_period: Audit period
        
        Returns:
            Dict containing evidence collection results
        """
        
        try:
            collection_id = f"CTRL-{control_id}-{uuid.uuid4().hex[:8].upper()}"
            evidence_files = []
            
            # 1. Implementation documentation
            impl_doc = self._generate_control_implementation_doc(control_id, implementation_details)
            impl_evidence = self.evidence_manager.store_evidence(
                title=f"Control {control_id} Implementation Documentation",
                description=f"Detailed implementation documentation for ISO 27001 control {control_id}",
                evidence_type="IMPLEMENTATION_DOC",
                file_content=impl_doc.encode('utf-8'),
                file_name=f"{collection_id}_implementation.md",
                mime_type="text/markdown",
                org_id=org_id,
                collected_by=collected_by,
                control_id=control_id,
                audit_period=audit_period
            )
            evidence_files.append(impl_evidence)
            
            # 2. Evidence index
            evidence_index = {
                "control_id": control_id,
                "control_title": implementation_details.get("title", ""),
                "implementation_status": implementation_details.get("status", ""),
                "implementation_date": implementation_details.get("implementation_date", ""),
                "responsible_party": implementation_details.get("responsible_party", ""),
                "evidence_collection_date": datetime.utcnow().isoformat(),
                "collected_by": collected_by,
                "audit_period": audit_period,
                "supporting_evidence": []
            }
            
            # 3. Collect supporting evidence based on control type
            if "access_control" in control_id.lower():
                # Collect access control evidence
                access_evidence = await self._collect_access_control_evidence(
                    control_id, org_id, collected_by, audit_period
                )
                evidence_files.extend(access_evidence)
                evidence_index["supporting_evidence"].extend([e["evidence_id"] for e in access_evidence])
            
            elif "vulnerability" in control_id.lower():
                # Collect vulnerability management evidence
                vuln_evidence = await self._collect_vulnerability_evidence(
                    control_id, org_id, collected_by, audit_period
                )
                evidence_files.extend(vuln_evidence)
                evidence_index["supporting_evidence"].extend([e["evidence_id"] for e in vuln_evidence])
            
            elif "backup" in control_id.lower():
                # Collect backup evidence
                backup_evidence = await self._collect_backup_evidence(
                    control_id, org_id, collected_by, audit_period
                )
                evidence_files.extend(backup_evidence)
                evidence_index["supporting_evidence"].extend([e["evidence_id"] for e in backup_evidence])
            
            # Save evidence index
            index_evidence = self.evidence_manager.store_evidence(
                title=f"Control {control_id} Evidence Index",
                description=f"Index of all evidence collected for control {control_id}",
                evidence_type="EVIDENCE_INDEX",
                file_content=json.dumps(evidence_index, indent=2, default=str).encode('utf-8'),
                file_name=f"{collection_id}_index.json",
                mime_type="application/json",
                org_id=org_id,
                collected_by=collected_by,
                control_id=control_id,
                audit_period=audit_period
            )
            evidence_files.append(index_evidence)
            
            return {
                "collection_id": collection_id,
                "control_id": control_id,
                "evidence_count": len(evidence_files),
                "evidence_files": evidence_files,
                "evidence_index": evidence_index,
                "collected_at": datetime.utcnow().isoformat(),
                "collected_by": collected_by
            }
            
        except Exception as e:
            logger.error(f"Control evidence collection failed for {control_id}: {str(e)}")
            raise Exception(f"Control evidence collection failed: {str(e)}")
    
    async def collect_ai_governance_evidence(
        self,
        model_id: str,
        model_details: Dict[str, Any],
        org_id: int,
        collected_by: str,
        audit_period: str
    ) -> Dict[str, Any]:
        """
        Collect evidence for AI governance (ISO 42001)
        
        Args:
            model_id: AI model identifier
            model_details: Model details and metadata
            org_id: Organization ID
            collected_by: User collecting evidence
            audit_period: Audit period
        
        Returns:
            Dict containing AI governance evidence
        """
        
        try:
            collection_id = f"AI-{model_id}-{uuid.uuid4().hex[:8].upper()}"
            evidence_files = []
            
            # 1. Model card
            model_card = self._generate_model_card(model_id, model_details)
            card_evidence = self.evidence_manager.store_evidence(
                title=f"AI Model Card - {model_id}",
                description=f"Comprehensive model card for AI model {model_id}",
                evidence_type="MODEL_CARD",
                file_content=model_card.encode('utf-8'),
                file_name=f"{collection_id}_model_card.md",
                mime_type="text/markdown",
                org_id=org_id,
                collected_by=collected_by,
                audit_period=audit_period,
                is_sensitive=True,
                authorized_roles=["AI_GOVERNANCE_LEAD", "ADMIN"]
            )
            evidence_files.append(card_evidence)
            
            # 2. Bias testing results
            if model_details.get("bias_testing_enabled", False):
                bias_results = await self.ai_bias_scanner.scan_ai_bias(
                    model_path=model_details.get("model_path", ""),
                    test_data_path=model_details.get("test_data_path", ""),
                    fairness_metrics=["demographic_parity", "equalized_odds", "statistical_parity"]
                )
                
                bias_evidence = self.evidence_manager.store_evidence(
                    title=f"AI Bias Testing Results - {model_id}",
                    description=f"Comprehensive bias testing results for model {model_id}",
                    evidence_type="BIAS_TEST_RESULTS",
                    file_content=json.dumps(bias_results, indent=2, default=str).encode('utf-8'),
                    file_name=f"{collection_id}_bias_results.json",
                    mime_type="application/json",
                    org_id=org_id,
                    collected_by=collected_by,
                    audit_period=audit_period,
                    is_sensitive=True,
                    authorized_roles=["AI_GOVERNANCE_LEAD", "ADMIN"]
                )
                evidence_files.append(bias_evidence)
            
            # 3. Risk assessment
            risk_assessment = self._generate_ai_risk_assessment(model_id, model_details)
            risk_evidence = self.evidence_manager.store_evidence(
                title=f"AI Risk Assessment - {model_id}",
                description=f"Risk assessment for AI model {model_id}",
                evidence_type="RISK_ASSESSMENT",
                file_content=risk_assessment.encode('utf-8'),
                file_name=f"{collection_id}_risk_assessment.md",
                mime_type="text/markdown",
                org_id=org_id,
                collected_by=collected_by,
                audit_period=audit_period,
                is_sensitive=True,
                authorized_roles=["AI_GOVERNANCE_LEAD", "ADMIN"]
            )
            evidence_files.append(risk_evidence)
            
            return {
                "collection_id": collection_id,
                "model_id": model_id,
                "evidence_count": len(evidence_files),
                "evidence_files": evidence_files,
                "collected_at": datetime.utcnow().isoformat(),
                "collected_by": collected_by
            }
            
        except Exception as e:
            logger.error(f"AI governance evidence collection failed for {model_id}: {str(e)}")
            raise Exception(f"AI governance evidence collection failed: {str(e)}")
    
    def _generate_scan_summary(self, scan_result: Dict, scan_type: str, target: str) -> str:
        """Generate human-readable scan summary"""
        findings = scan_result.get("findings", [])
        
        summary = f"""# {scan_type.upper()} Scan Summary

## Scan Details
- **Target:** {target}
- **Scan Type:** {scan_type}
- **Timestamp:** {datetime.utcnow().isoformat()}
- **Duration:** {scan_result.get('scan_duration', 0)} seconds

## Results Overview
- **Total Findings:** {len(findings)}
- **High Severity:** {len([f for f in findings if f.get('severity') == 'HIGH'])}
- **Medium Severity:** {len([f for f in findings if f.get('severity') == 'MEDIUM'])}
- **Low Severity:** {len([f for f in findings if f.get('severity') == 'LOW'])}

## Top Findings
"""
        
        # Add top 5 high severity findings
        high_findings = [f for f in findings if f.get('severity') == 'HIGH'][:5]
        for i, finding in enumerate(high_findings, 1):
            summary += f"\n{i}. **{finding.get('title', 'Unknown')}**\n"
            summary += f"   - Severity: {finding.get('severity', 'Unknown')}\n"
            summary += f"   - Description: {finding.get('description', 'No description')}\n"
        
        return summary
    
    def _generate_findings_csv(self, findings: List[Dict]) -> str:
        """Generate CSV export of findings"""
        import csv
        import io
        
        output = io.StringIO()
        fieldnames = ['title', 'severity', 'description', 'file_path', 'line_number', 'rule_id', 'cwe_id']
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for finding in findings:
            writer.writerow({
                'title': finding.get('title', ''),
                'severity': finding.get('severity', ''),
                'description': finding.get('description', ''),
                'file_path': finding.get('file_path', ''),
                'line_number': finding.get('line_number', ''),
                'rule_id': finding.get('rule_id', ''),
                'cwe_id': finding.get('cwe_id', '')
            })
        
        return output.getvalue()
    
    def _generate_control_implementation_doc(self, control_id: str, details: Dict) -> str:
        """Generate control implementation documentation"""
        return f"""# Control {control_id} Implementation Documentation

## Control Details
- **Control ID:** {control_id}
- **Title:** {details.get('title', 'Unknown')}
- **Status:** {details.get('status', 'Unknown')}
- **Implementation Date:** {details.get('implementation_date', 'Unknown')}
- **Responsible Party:** {details.get('responsible_party', 'Unknown')}

## Implementation Description
{details.get('description', 'No description provided')}

## Implementation Evidence
{details.get('evidence_description', 'No evidence description provided')}

## Testing and Validation
{details.get('testing_notes', 'No testing notes provided')}

## Continuous Monitoring
{details.get('monitoring_notes', 'No monitoring notes provided')}

---
*Generated on {datetime.utcnow().isoformat()}*
"""
    
    def _generate_model_card(self, model_id: str, details: Dict) -> str:
        """Generate AI model card"""
        return f"""# Model Card: {model_id}

## Model Details
- **Model ID:** {model_id}
- **Model Type:** {details.get('model_type', 'Unknown')}
- **Version:** {details.get('version', 'Unknown')}
- **Created:** {details.get('created_date', 'Unknown')}
- **Owner:** {details.get('owner', 'Unknown')}

## Intended Use
- **Primary Use Cases:** {details.get('primary_use', 'Not specified')}
- **Users:** {details.get('target_users', 'Not specified')}
- **Out-of-Scope Uses:** {details.get('out_of_scope', 'Not specified')}

## Training Data
- **Dataset:** {details.get('training_dataset', 'Not specified')}
- **Data Size:** {details.get('data_size', 'Not specified')}
- **Data Preprocessing:** {details.get('preprocessing', 'Not specified')}

## Evaluation
- **Metrics:** {details.get('evaluation_metrics', 'Not specified')}
- **Performance:** {details.get('performance_scores', 'Not specified')}
- **Bias Testing:** {details.get('bias_testing_results', 'Not specified')}

## Ethical Considerations
- **Risks:** {details.get('ethical_risks', 'Not specified')}
- **Mitigation:** {details.get('risk_mitigation', 'Not specified')}
- **Fairness:** {details.get('fairness_assessment', 'Not specified')}

---
*Generated on {datetime.utcnow().isoformat()}*
"""
    
    def _generate_ai_risk_assessment(self, model_id: str, details: Dict) -> str:
        """Generate AI risk assessment"""
        return f"""# AI Risk Assessment: {model_id}

## Risk Overview
- **Model:** {model_id}
- **Risk Level:** {details.get('risk_level', 'Not assessed')}
- **Assessment Date:** {datetime.utcnow().isoformat()}

## Identified Risks
- **Bias Risks:** {details.get('bias_risks', 'Not assessed')}
- **Privacy Risks:** {details.get('privacy_risks', 'Not assessed')}
- **Security Risks:** {details.get('security_risks', 'Not assessed')}
- **Accuracy Risks:** {details.get('accuracy_risks', 'Not assessed')}

## Risk Mitigation
- **Controls Implemented:** {details.get('controls', 'None specified')}
- **Monitoring:** {details.get('monitoring', 'None specified')}
- **Response Plan:** {details.get('response_plan', 'None specified')}

## Compliance
- **ISO 42001 Requirements:** {details.get('iso42001_compliance', 'Not assessed')}
- **Regulatory Requirements:** {details.get('regulatory_compliance', 'Not assessed')}

---
*Generated on {datetime.utcnow().isoformat()}*
"""
    
    async def _collect_access_control_evidence(self, control_id: str, org_id: int, collected_by: str, audit_period: str) -> List[Dict]:
        """Collect access control specific evidence"""
        # This would integrate with actual access control systems
        # For now, return placeholder evidence structure
        return []
    
    async def _collect_vulnerability_evidence(self, control_id: str, org_id: int, collected_by: str, audit_period: str) -> List[Dict]:
        """Collect vulnerability management evidence"""
        # This would run actual vulnerability scans
        # For now, return placeholder evidence structure
        return []
    
    async def _collect_backup_evidence(self, control_id: str, org_id: int, collected_by: str, audit_period: str) -> List[Dict]:
        """Collect backup and recovery evidence"""
        # This would verify backup systems
        # For now, return placeholder evidence structure
        return []

# Factory function
def create_evidence_collector(evidence_manager: EvidenceManager) -> EvidenceCollector:
    """Create and configure evidence collector"""
    return EvidenceCollector(evidence_manager)