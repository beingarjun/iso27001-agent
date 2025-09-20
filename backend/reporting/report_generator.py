"""
Compliance Reporting and Deliverable Generation
Enterprise-grade report generation for ISO 27001/42001 compliance
"""

import json
import csv
import io
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import uuid
from jinja2 import Template
import markdown
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

class ComplianceReportGenerator:
    """Generate comprehensive compliance reports and deliverables"""
    
    def __init__(self):
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        
        # Create subdirectories for different report types
        (self.reports_dir / "statements").mkdir(exist_ok=True)
        (self.reports_dir / "risk_registers").mkdir(exist_ok=True)
        (self.reports_dir / "evidence").mkdir(exist_ok=True)
        (self.reports_dir / "model_cards").mkdir(exist_ok=True)
        (self.reports_dir / "management_reviews").mkdir(exist_ok=True)
        (self.reports_dir / "release_reports").mkdir(exist_ok=True)
    
    async def generate_statement_of_applicability(
        self,
        org_id: int,
        controls_data: List[Dict],
        org_info: Dict
    ) -> Dict[str, str]:
        """
        Generate Statement of Applicability (SoA) for ISO 27001
        
        Args:
            org_id: Organization ID
            controls_data: List of control implementation data
            org_info: Organization information
        
        Returns:
            Dict with file paths and metadata
        """
        
        timestamp = datetime.utcnow()
        report_id = f"SOA-{org_id}-{timestamp.strftime('%Y%m%d')}"
        
        # Prepare SoA data
        soa_data = {
            "report_id": report_id,
            "organization": org_info,
            "generated_date": timestamp.strftime("%Y-%m-%d"),
            "iso_version": "ISO/IEC 27001:2022",
            "controls": controls_data,
            "summary": {
                "total_controls": len(controls_data),
                "included": len([c for c in controls_data if c.get("status") == "INCLUDED"]),
                "excluded": len([c for c in controls_data if c.get("status") == "EXCLUDED"]),
                "not_applicable": len([c for c in controls_data if c.get("status") == "NOT_APPLICABLE"])
            }
        }
        
        # Generate Markdown version
        md_content = self._generate_soa_markdown(soa_data)
        md_file = self.reports_dir / "statements" / f"{report_id}.md"
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        # Generate PDF version
        pdf_file = self.reports_dir / "statements" / f"{report_id}.pdf"
        self._generate_soa_pdf(soa_data, pdf_file)
        
        # Generate JSON version for processing
        json_file = self.reports_dir / "statements" / f"{report_id}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(soa_data, f, indent=2, default=str)
        
        return {
            "report_id": report_id,
            "markdown_path": str(md_file),
            "pdf_path": str(pdf_file),
            "json_path": str(json_file),
            "generated_at": timestamp.isoformat()
        }
    
    def _generate_soa_markdown(self, soa_data: Dict) -> str:
        """Generate Statement of Applicability in Markdown format"""
        
        template = Template("""
# Statement of Applicability (SoA)
## ISO/IEC 27001:{{ iso_version }}

**Organization:** {{ organization.name }}  
**Report ID:** {{ report_id }}  
**Generated Date:** {{ generated_date }}  
**Scope:** {{ organization.scope_definition | default("Information security management system") }}

## Executive Summary

This Statement of Applicability documents the controls selected for implementation in our Information Security Management System (ISMS) based on {{ iso_version }}.

**Control Summary:**
- Total Controls: {{ summary.total_controls }}
- Included: {{ summary.included }}
- Excluded: {{ summary.excluded }}
- Not Applicable: {{ summary.not_applicable }}

## Control Implementation Status

{% for control in controls %}
### {{ control.control_id }}: {{ control.control_title }}

**Status:** {{ control.status }}  
**Implementation Status:** {{ control.implementation_status | default("NOT_STARTED") }}  
**Owner:** {{ control.owner | default("TBD") }}

**Description:** {{ control.control_description }}

{% if control.status == "INCLUDED" %}
**Implementation Approach:** {{ control.implementation_approach | default("To be defined") }}

**Evidence Location:** {{ control.evidence_location | default("To be documented") }}

**Testing Frequency:** {{ control.testing_frequency | default("Annual") }}
{% elif control.status == "EXCLUDED" %}
**Exclusion Reason:** {{ control.exclusion_reason | default("Not applicable to business operations") }}
{% elif control.status == "NOT_APPLICABLE" %}
**Justification:** {{ control.not_applicable_reason | default("Control not relevant to organization scope") }}
{% endif %}

---
{% endfor %}

## Approval and Sign-off

**Prepared by:** Information Security Team  
**Reviewed by:** CISO  
**Approved by:** CEO  

**Date:** {{ generated_date }}

**Signature:** ___________________

## Document Control

**Version:** 1.0  
**Next Review Date:** {{ (generated_date | strptime('%Y-%m-%d') + timedelta(days=365)).strftime('%Y-%m-%d') }}  
**Classification:** Internal
        """)
        
        return template.render(**soa_data)
    
    def _generate_soa_pdf(self, soa_data: Dict, output_path: Path):
        """Generate Statement of Applicability in PDF format"""
        
        doc = SimpleDocTemplate(str(output_path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=1  # Center
        )
        
        story.append(Paragraph("Statement of Applicability (SoA)", title_style))
        story.append(Paragraph(f"ISO/IEC 27001:{soa_data['iso_version']}", styles['Heading2']))
        story.append(Spacer(1, 20))
        
        # Organization info
        org_info = [
            ["Organization:", soa_data['organization']['name']],
            ["Report ID:", soa_data['report_id']],
            ["Generated Date:", soa_data['generated_date']],
            ["Scope:", soa_data['organization'].get('scope_definition', 'ISMS')]
        ]
        
        org_table = Table(org_info, colWidths=[2*inch, 4*inch])
        org_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(org_table)
        story.append(Spacer(1, 20))
        
        # Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        summary_text = f"""
        This Statement of Applicability documents the controls selected for implementation 
        in our Information Security Management System (ISMS) based on {soa_data['iso_version']}.
        
        Control Summary:
        • Total Controls: {soa_data['summary']['total_controls']}
        • Included: {soa_data['summary']['included']}
        • Excluded: {soa_data['summary']['excluded']}
        • Not Applicable: {soa_data['summary']['not_applicable']}
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(PageBreak())
        
        # Controls table
        story.append(Paragraph("Control Implementation Status", styles['Heading2']))
        
        control_data = [["Control ID", "Title", "Status", "Implementation", "Owner"]]
        
        for control in soa_data['controls']:
            control_data.append([
                control['control_id'],
                control['control_title'][:50] + "..." if len(control['control_title']) > 50 else control['control_title'],
                control['status'],
                control.get('implementation_status', 'TBD'),
                control.get('owner', 'TBD')
            ])
        
        control_table = Table(control_data, colWidths=[1*inch, 2.5*inch, 1*inch, 1*inch, 1*inch])
        control_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(control_table)
        
        doc.build(story)
    
    async def generate_risk_register(
        self,
        org_id: int,
        risks_data: List[Dict],
        org_info: Dict
    ) -> Dict[str, str]:
        """
        Generate Risk Register in CSV and PDF formats
        
        Args:
            org_id: Organization ID
            risks_data: List of risk data
            org_info: Organization information
        
        Returns:
            Dict with file paths and metadata
        """
        
        timestamp = datetime.utcnow()
        report_id = f"RISK-REGISTER-{org_id}-{timestamp.strftime('%Y%m%d')}"
        
        # Generate CSV version
        csv_file = self.reports_dir / "risk_registers" / f"{report_id}.csv"
        
        fieldnames = [
            'Risk ID', 'Title', 'Category', 'Description', 'Owner',
            'Inherent Likelihood', 'Inherent Impact', 'Inherent Risk Score',
            'Residual Likelihood', 'Residual Impact', 'Residual Risk Score',
            'Status', 'Mitigation Actions', 'Target Closure Date', 'Last Review'
        ]
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for risk in risks_data:
                writer.writerow({
                    'Risk ID': risk.get('risk_id', ''),
                    'Title': risk.get('title', ''),
                    'Category': risk.get('category', ''),
                    'Description': risk.get('description', ''),
                    'Owner': risk.get('owner', ''),
                    'Inherent Likelihood': risk.get('inherent_likelihood', ''),
                    'Inherent Impact': risk.get('inherent_impact', ''),
                    'Inherent Risk Score': risk.get('inherent_risk_score', ''),
                    'Residual Likelihood': risk.get('residual_likelihood', ''),
                    'Residual Impact': risk.get('residual_impact', ''),
                    'Residual Risk Score': risk.get('residual_risk_score', ''),
                    'Status': risk.get('status', ''),
                    'Mitigation Actions': '; '.join(risk.get('mitigation_actions', [])),
                    'Target Closure Date': risk.get('target_closure_date', ''),
                    'Last Review': risk.get('last_reviewed', '')
                })
        
        # Generate summary JSON
        json_file = self.reports_dir / "risk_registers" / f"{report_id}.json"
        
        risk_summary = {
            "report_id": report_id,
            "organization": org_info,
            "generated_date": timestamp.strftime("%Y-%m-%d"),
            "total_risks": len(risks_data),
            "by_status": {},
            "by_category": {},
            "by_risk_level": {
                "low": len([r for r in risks_data if r.get('residual_risk_score', 0) <= 4]),
                "medium": len([r for r in risks_data if 5 <= r.get('residual_risk_score', 0) <= 12]),
                "high": len([r for r in risks_data if 13 <= r.get('residual_risk_score', 0) <= 20]),
                "critical": len([r for r in risks_data if r.get('residual_risk_score', 0) >= 21])
            },
            "exceeding_appetite": len([r for r in risks_data if r.get('exceeds_appetite', False)]),
            "risks": risks_data
        }
        
        # Count by status and category
        for risk in risks_data:
            status = risk.get('status', 'UNKNOWN')
            category = risk.get('category', 'UNKNOWN')
            
            risk_summary["by_status"][status] = risk_summary["by_status"].get(status, 0) + 1
            risk_summary["by_category"][category] = risk_summary["by_category"].get(category, 0) + 1
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(risk_summary, f, indent=2, default=str)
        
        return {
            "report_id": report_id,
            "csv_path": str(csv_file),
            "json_path": str(json_file),
            "generated_at": timestamp.isoformat()
        }
    
    async def generate_model_card(
        self,
        model_id: str,
        model_data: Dict,
        bias_results: Dict = None,
        org_id: int = None
    ) -> Dict[str, str]:
        """
        Generate AI Model Card following Google Model Cards format
        
        Args:
            model_id: Model identifier
            model_data: Model information and metadata
            bias_results: Bias testing results
            org_id: Organization ID
        
        Returns:
            Dict with file paths and metadata
        """
        
        timestamp = datetime.utcnow()
        card_id = f"MODEL-CARD-{model_id}-{timestamp.strftime('%Y%m%d')}"
        
        # Prepare model card data
        card_data = {
            "model_id": model_id,
            "card_id": card_id,
            "generated_date": timestamp.strftime("%Y-%m-%d"),
            "model_details": model_data.get("model_details", {}),
            "intended_use": model_data.get("intended_use", {}),
            "factors": model_data.get("factors", {}),
            "metrics": model_data.get("metrics", {}),
            "evaluation_data": model_data.get("evaluation_data", {}),
            "training_data": model_data.get("training_data", {}),
            "quantitative_analyses": model_data.get("quantitative_analyses", {}),
            "ethical_considerations": model_data.get("ethical_considerations", {}),
            "caveats_recommendations": model_data.get("caveats_recommendations", {}),
            "bias_assessment": bias_results
        }
        
        # Generate Markdown model card
        md_content = self._generate_model_card_markdown(card_data)
        md_file = self.reports_dir / "model_cards" / f"{card_id}.md"
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        # Generate JSON version
        json_file = self.reports_dir / "model_cards" / f"{card_id}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(card_data, f, indent=2, default=str)
        
        return {
            "card_id": card_id,
            "model_id": model_id,
            "markdown_path": str(md_file),
            "json_path": str(json_file),
            "generated_at": timestamp.isoformat()
        }
    
    def _generate_model_card_markdown(self, card_data: Dict) -> str:
        """Generate Model Card in Markdown format"""
        
        template = Template("""
# Model Card: {{ model_id }}

**Generated Date:** {{ generated_date }}  
**Card ID:** {{ card_id }}

## Model Details

**Model Name:** {{ model_details.name | default("TBD") }}  
**Model Version:** {{ model_details.version | default("1.0") }}  
**Model Type:** {{ model_details.type | default("TBD") }}  
**Model Description:** {{ model_details.description | default("TBD") }}  
**Model Owner:** {{ model_details.owner | default("TBD") }}  
**Model License:** {{ model_details.license | default("Proprietary") }}

## Intended Use

**Primary Intended Uses:** {{ intended_use.primary_uses | default("TBD") }}

**Primary Intended Users:** {{ intended_use.primary_users | default("TBD") }}

**Out-of-Scope Use Cases:** {{ intended_use.out_of_scope | default("TBD") }}

## Factors

**Relevant Factors:** {{ factors.relevant_factors | default("TBD") }}

**Evaluation Factors:** {{ factors.evaluation_factors | default("TBD") }}

## Metrics

**Model Performance Measures:** {{ metrics.performance_measures | default("TBD") }}

**Decision Thresholds:** {{ metrics.decision_thresholds | default("TBD") }}

**Variation Approaches:** {{ metrics.variation_approaches | default("TBD") }}

## Evaluation Data

**Datasets:** {{ evaluation_data.datasets | default("TBD") }}

**Motivation:** {{ evaluation_data.motivation | default("TBD") }}

**Preprocessing:** {{ evaluation_data.preprocessing | default("TBD") }}

## Training Data

**Datasets:** {{ training_data.datasets | default("TBD") }}

**Motivation:** {{ training_data.motivation | default("TBD") }}

**Preprocessing:** {{ training_data.preprocessing | default("TBD") }}

## Quantitative Analyses

**Unitary Results:** {{ quantitative_analyses.unitary_results | default("TBD") }}

**Intersectional Results:** {{ quantitative_analyses.intersectional_results | default("TBD") }}

{% if bias_assessment %}
## Bias Assessment Results

**Test Date:** {{ bias_assessment.timestamp }}  
**Compliance Status:** {{ bias_assessment.compliance_status }}

### Bias Metrics
{% for metric, value in bias_assessment.metrics.items() %}
- **{{ metric }}:** {{ value }}
{% endfor %}

{% if bias_assessment.threshold_violations %}
### Threshold Violations
{% for violation in bias_assessment.threshold_violations %}
- **{{ violation.metric }}:** {{ violation.value }} (threshold: {{ violation.threshold }}, severity: {{ violation.severity }})
{% endfor %}
{% endif %}

### Recommendations
{% for rec in bias_assessment.recommendations %}
- {{ rec }}
{% endfor %}
{% endif %}

## Ethical Considerations

**Sensitive Use Cases:** {{ ethical_considerations.sensitive_uses | default("TBD") }}

**Risks and Harms:** {{ ethical_considerations.risks | default("TBD") }}

**Mitigation Strategies:** {{ ethical_considerations.mitigations | default("TBD") }}

## Caveats and Recommendations

**Known Limitations:** {{ caveats_recommendations.limitations | default("TBD") }}

**Recommendations:** {{ caveats_recommendations.recommendations | default("TBD") }}

---

**Document Version:** 1.0  
**Next Review Date:** {{ (generated_date | strptime('%Y-%m-%d') + timedelta(days=180)).strftime('%Y-%m-%d') }}
        """)
        
        return template.render(**card_data)
    
    async def generate_management_review_minutes(
        self,
        org_id: int,
        review_data: Dict,
        attendees: List[str],
        decisions: List[Dict]
    ) -> Dict[str, str]:
        """
        Generate Management Review Meeting Minutes
        
        Args:
            org_id: Organization ID
            review_data: Review data and metrics
            attendees: List of meeting attendees
            decisions: List of decisions made
        
        Returns:
            Dict with file paths and metadata
        """
        
        timestamp = datetime.utcnow()
        review_id = f"MGT-REVIEW-{org_id}-{timestamp.strftime('%Y%m%d')}"
        
        # Prepare review data
        minutes_data = {
            "review_id": review_id,
            "org_id": org_id,
            "review_date": timestamp.strftime("%Y-%m-%d"),
            "attendees": attendees,
            "review_period": review_data.get("review_period", "Q4 2024"),
            "isms_performance": review_data.get("isms_performance", {}),
            "risk_assessment_results": review_data.get("risk_assessment", {}),
            "incident_summary": review_data.get("incidents", {}),
            "audit_results": review_data.get("audit_results", {}),
            "improvement_opportunities": review_data.get("improvements", []),
            "decisions": decisions,
            "action_items": review_data.get("action_items", [])
        }
        
        # Generate PDF minutes
        pdf_file = self.reports_dir / "management_reviews" / f"{review_id}.pdf"
        self._generate_management_review_pdf(minutes_data, pdf_file)
        
        # Generate JSON version
        json_file = self.reports_dir / "management_reviews" / f"{review_id}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(minutes_data, f, indent=2, default=str)
        
        return {
            "review_id": review_id,
            "pdf_path": str(pdf_file),
            "json_path": str(json_file),
            "generated_at": timestamp.isoformat()
        }
    
    def _generate_management_review_pdf(self, minutes_data: Dict, output_path: Path):
        """Generate Management Review Minutes in PDF format"""
        
        doc = SimpleDocTemplate(str(output_path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        story.append(Paragraph("Management Review Meeting Minutes", styles['Title']))
        story.append(Paragraph(f"Review Period: {minutes_data['review_period']}", styles['Heading2']))
        story.append(Spacer(1, 20))
        
        # Meeting details
        meeting_info = [
            ["Review ID:", minutes_data['review_id']],
            ["Date:", minutes_data['review_date']],
            ["Attendees:", ", ".join(minutes_data['attendees'])]
        ]
        
        meeting_table = Table(meeting_info, colWidths=[2*inch, 4*inch])
        meeting_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(meeting_table)
        story.append(Spacer(1, 20))
        
        # ISMS Performance
        story.append(Paragraph("ISMS Performance Review", styles['Heading2']))
        performance = minutes_data['isms_performance']
        
        perf_text = f"""
        Security Incidents: {performance.get('incidents_count', 0)}
        Policy Compliance: {performance.get('compliance_rate', 0)}%
        Training Completion: {performance.get('training_completion', 0)}%
        Risk Appetite Breaches: {performance.get('risk_breaches', 0)}
        """
        story.append(Paragraph(perf_text, styles['Normal']))
        
        # Decisions
        story.append(Paragraph("Management Decisions", styles['Heading2']))
        for i, decision in enumerate(minutes_data['decisions'], 1):
            story.append(Paragraph(f"{i}. {decision.get('description', '')}", styles['Normal']))
            story.append(Paragraph(f"   Owner: {decision.get('owner', 'TBD')}", styles['Normal']))
            story.append(Paragraph(f"   Due Date: {decision.get('due_date', 'TBD')}", styles['Normal']))
            story.append(Spacer(1, 10))
        
        doc.build(story)
    
    async def generate_release_report(
        self,
        org_id: int,
        release_data: Dict,
        scan_results: Dict,
        approval_status: str
    ) -> Dict[str, str]:
        """
        Generate Release Security Report
        
        Args:
            org_id: Organization ID
            release_data: Release information
            scan_results: Security scan results
            approval_status: Release approval status
        
        Returns:
            Dict with file paths and metadata
        """
        
        timestamp = datetime.utcnow()
        report_id = f"RELEASE-{release_data.get('version', 'unknown')}-{timestamp.strftime('%Y%m%d')}"
        
        # Prepare release report data
        report_data = {
            "report_id": report_id,
            "org_id": org_id,
            "release_version": release_data.get("version", "unknown"),
            "release_date": timestamp.strftime("%Y-%m-%d"),
            "approval_status": approval_status,
            "scan_results": scan_results,
            "security_summary": {
                "total_findings": scan_results.get("summary", {}).get("total_findings", 0),
                "critical": scan_results.get("summary", {}).get("critical", 0),
                "high": scan_results.get("summary", {}).get("high", 0),
                "medium": scan_results.get("summary", {}).get("medium", 0),
                "low": scan_results.get("summary", {}).get("low", 0)
            },
            "blocking_issues": [f for f in scan_results.get("findings", []) if f.get("severity") in ["CRITICAL", "HIGH"]],
            "approved_exceptions": release_data.get("approved_exceptions", []),
            "compliance_status": "COMPLIANT" if approval_status == "APPROVED" else "NON_COMPLIANT"
        }
        
        # Generate Markdown report
        md_content = self._generate_release_report_markdown(report_data)
        md_file = self.reports_dir / "release_reports" / f"{report_id}.md"
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        # Generate JSON version
        json_file = self.reports_dir / "release_reports" / f"{report_id}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return {
            "report_id": report_id,
            "markdown_path": str(md_file),
            "json_path": str(json_file),
            "approval_status": approval_status,
            "generated_at": timestamp.isoformat()
        }
    
    def _generate_release_report_markdown(self, report_data: Dict) -> str:
        """Generate Release Report in Markdown format"""
        
        template = Template("""
# Release Security Report

**Release Version:** {{ release_version }}  
**Report ID:** {{ report_id }}  
**Release Date:** {{ release_date }}  
**Approval Status:** {{ approval_status }}  
**Compliance Status:** {{ compliance_status }}

## Security Scan Summary

**Total Findings:** {{ security_summary.total_findings }}

| Severity | Count |
|----------|-------|
| Critical | {{ security_summary.critical }} |
| High     | {{ security_summary.high }} |
| Medium   | {{ security_summary.medium }} |
| Low      | {{ security_summary.low }} |

## Release Approval Decision

{% if approval_status == "APPROVED" %}
✅ **RELEASE APPROVED**

This release has been approved for deployment based on security assessment results.
{% elif approval_status == "REJECTED" %}
❌ **RELEASE REJECTED**

This release has been rejected due to unresolved security issues.
{% else %}
⏳ **APPROVAL PENDING**

This release is pending security review and approval.
{% endif %}

{% if blocking_issues %}
## Blocking Security Issues

The following HIGH or CRITICAL severity issues were identified:

{% for issue in blocking_issues %}
### {{ issue.title }}
- **Severity:** {{ issue.severity }}
- **Category:** {{ issue.category }}
- **Description:** {{ issue.description }}
- **Recommendation:** {{ issue.recommendation | default("See detailed findings") }}

{% endfor %}
{% endif %}

{% if approved_exceptions %}
## Approved Security Exceptions

The following security exceptions have been approved for this release:

{% for exception in approved_exceptions %}
- **{{ exception.title }}** ({{ exception.severity }}) - Approved by {{ exception.approved_by }} on {{ exception.approval_date }}
  - Reason: {{ exception.reason }}
  - Mitigation: {{ exception.mitigation }}

{% endfor %}
{% endif %}

## Compliance Attestation

This release security report attests that:

1. Security scanning has been performed using enterprise-grade tools
2. All findings have been reviewed by the security team
3. HIGH and CRITICAL findings have been either resolved or have approved exceptions
4. The release meets organizational security standards

**Prepared by:** Security Team  
**Reviewed by:** CISO  
**Date:** {{ release_date }}

---

**Report Version:** 1.0  
**Classification:** Internal Use
        """)
        
        return template.render(**report_data)

# Factory function
def create_report_generator() -> ComplianceReportGenerator:
    """Create and configure compliance report generator"""
    return ComplianceReportGenerator()