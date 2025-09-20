"""
Tools for normalizing and summarizing security scan results
"""
from typing import Dict, Any, List
from datetime import datetime


def summarize_npm_audit(npm_result: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize npm audit results into standard format"""
    
    if not npm_result.get("success", False):
        return {
            "scanner": "npm_audit",
            "success": False,
            "error": npm_result.get("error", "Unknown error"),
            "total_vulns": 0,
            "severity_breakdown": {"low": 0, "moderate": 0, "high": 0, "critical": 0},
            "recommendations": []
        }
    
    vulnerabilities = npm_result.get("vulnerabilities", {})
    metadata = npm_result.get("metadata", {})
    
    # Count vulnerabilities by severity
    severity_counts = {"low": 0, "moderate": 0, "high": 0, "critical": 0}
    vulnerable_packages = []
    
    for pkg_name, vuln_info in vulnerabilities.items():
        if isinstance(vuln_info, dict):
            severity = vuln_info.get("severity", "low").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            vulnerable_packages.append({
                "package": pkg_name,
                "severity": severity,
                "title": vuln_info.get("title", ""),
                "url": vuln_info.get("url", ""),
                "vulnerable_versions": vuln_info.get("range", "")
            })
    
    total_vulns = sum(severity_counts.values())
    
    # Generate recommendations
    recommendations = []
    if total_vulns > 0:
        recommendations.append("Run 'npm audit fix' to automatically fix vulnerabilities")
        if severity_counts["high"] > 0 or severity_counts["critical"] > 0:
            recommendations.append("Review and manually fix high/critical vulnerabilities")
        recommendations.append("Consider using 'npm audit fix --force' for breaking changes")
        recommendations.append("Update package.json to pin secure versions")
    
    return {
        "scanner": "npm_audit",
        "success": True,
        "total_vulns": total_vulns,
        "severity_breakdown": severity_counts,
        "vulnerable_packages": vulnerable_packages,
        "recommendations": recommendations,
        "scan_summary": f"Found {total_vulns} vulnerabilities in npm dependencies",
        "metadata": metadata
    }


def summarize_safety(safety_result: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize safety check results into standard format"""
    
    if not safety_result.get("success", False):
        return {
            "scanner": "safety",
            "success": False,
            "error": safety_result.get("error", "Unknown error"),
            "total_vulns": 0,
            "severity_breakdown": {"low": 0, "medium": 0, "high": 0},
            "recommendations": []
        }
    
    vulnerabilities = safety_result.get("vulnerabilities", [])
    
    # Process vulnerabilities
    severity_counts = {"low": 0, "medium": 0, "high": 0}
    vulnerable_packages = []
    
    for vuln in vulnerabilities:
        # Safety doesn't provide severity, so we estimate based on advisory
        advisory = vuln.get("advisory", "").lower()
        if any(word in advisory for word in ["critical", "remote code execution", "sql injection"]):
            severity = "high"
        elif any(word in advisory for word in ["moderate", "denial of service", "information disclosure"]):
            severity = "medium"
        else:
            severity = "low"
        
        severity_counts[severity] += 1
        
        vulnerable_packages.append({
            "package": vuln.get("package_name", ""),
            "severity": severity,
            "installed_version": vuln.get("installed_version", ""),
            "vulnerable_spec": vuln.get("vulnerable_spec", ""),
            "advisory": vuln.get("advisory", ""),
            "vulnerability_id": vuln.get("vulnerability_id", "")
        })
    
    total_vulns = len(vulnerabilities)
    
    # Generate recommendations
    recommendations = []
    if total_vulns > 0:
        recommendations.append("Update vulnerable Python packages to secure versions")
        recommendations.append("Pin package versions in requirements.txt")
        recommendations.append("Consider using virtual environments for isolation")
        if severity_counts["high"] > 0:
            recommendations.append("Prioritize fixing high-severity Python vulnerabilities")
    
    return {
        "scanner": "safety",
        "success": True,
        "total_vulns": total_vulns,
        "severity_breakdown": severity_counts,
        "vulnerable_packages": vulnerable_packages,
        "recommendations": recommendations,
        "scan_summary": f"Found {total_vulns} vulnerabilities in Python dependencies"
    }


def summarize_bandit(bandit_result: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize bandit scan results into standard format"""
    
    if not bandit_result.get("success", False):
        return {
            "scanner": "bandit",
            "success": False,
            "error": bandit_result.get("error", "Unknown error"),
            "total_issues": 0,
            "severity_breakdown": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
            "recommendations": []
        }
    
    issues = bandit_result.get("issues", [])
    counts = bandit_result.get("counts", {"LOW": 0, "MEDIUM": 0, "HIGH": 0})
    
    # Process issues by category
    issue_categories = {}
    code_issues = []
    
    for issue in issues:
        test_id = issue.get("test_id", "")
        test_name = issue.get("test_name", "")
        severity = issue.get("issue_severity", "LOW")
        confidence = issue.get("issue_confidence", "LOW")
        
        category = issue_categories.get(test_name, {
            "test_name": test_name,
            "test_id": test_id,
            "count": 0,
            "max_severity": "LOW"
        })
        
        category["count"] += 1
        if severity == "HIGH" or category["max_severity"] != "HIGH":
            if severity == "MEDIUM" and category["max_severity"] == "LOW":
                category["max_severity"] = severity
            elif severity == "HIGH":
                category["max_severity"] = severity
        
        issue_categories[test_name] = category
        
        code_issues.append({
            "filename": issue.get("filename", ""),
            "line_number": issue.get("line_number", 0),
            "test_name": test_name,
            "test_id": test_id,
            "severity": severity,
            "confidence": confidence,
            "issue_text": issue.get("issue_text", ""),
            "code": issue.get("code", "")
        })
    
    total_issues = len(issues)
    
    # Generate recommendations
    recommendations = []
    if total_issues > 0:
        if counts.get("HIGH", 0) > 0:
            recommendations.append("Fix high-severity code security issues immediately")
        if counts.get("MEDIUM", 0) > 0:
            recommendations.append("Review and fix medium-severity security issues")
        recommendations.append("Implement secure coding practices")
        recommendations.append("Add Bandit to CI/CD pipeline for continuous scanning")
        
        # Specific recommendations based on common issues
        common_issues = [cat for cat in issue_categories.values() if cat["count"] >= 3]
        for issue_cat in common_issues:
            if "hardcoded_password" in issue_cat["test_id"]:
                recommendations.append("Use environment variables or key management for secrets")
            elif "sql_injection" in issue_cat["test_id"]:
                recommendations.append("Use parameterized queries to prevent SQL injection")
    
    return {
        "scanner": "bandit",
        "success": True,
        "total_issues": total_issues,
        "severity_breakdown": counts,
        "issue_categories": list(issue_categories.values()),
        "code_issues": code_issues,
        "recommendations": recommendations,
        "scan_summary": f"Found {total_issues} security issues in code analysis"
    }


def summarize_ssl(ssl_result: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize SSL/TLS check results into standard format"""
    
    if not ssl_result.get("success", False):
        return {
            "scanner": "ssl_check",
            "success": False,
            "error": ssl_result.get("error", "Unknown error"),
            "hostname": ssl_result.get("hostname", ""),
            "security_issues": [],
            "recommendations": []
        }
    
    hostname = ssl_result.get("hostname", "")
    certificate = ssl_result.get("certificate", {})
    connection = ssl_result.get("connection", {})
    security = ssl_result.get("security", {})
    
    issues = security.get("issues", [])
    days_until_expiry = security.get("days_until_expiry", 0)
    
    # Categorize issues by severity
    security_issues = []
    severity_counts = {"low": 0, "medium": 0, "high": 0}
    
    for issue in issues:
        if "expires" in issue.lower():
            if days_until_expiry <= 7:
                severity = "high"
            elif days_until_expiry <= 30:
                severity = "medium"
            else:
                severity = "low"
        elif "tls" in issue.lower() or "ssl" in issue.lower():
            severity = "high"
        else:
            severity = "medium"
        
        severity_counts[severity] += 1
        security_issues.append({
            "issue": issue,
            "severity": severity,
            "category": "certificate" if "expires" in issue.lower() else "protocol"
        })
    
    # Generate recommendations
    recommendations = []
    if len(issues) > 0:
        if days_until_expiry <= 30:
            recommendations.append("Renew SSL certificate before expiration")
        if any("tls" in issue.lower() for issue in issues):
            recommendations.append("Upgrade to TLS 1.2 or higher")
        recommendations.append("Implement certificate monitoring and alerts")
        recommendations.append("Consider using automated certificate management (Let's Encrypt)")
    
    return {
        "scanner": "ssl_check",
        "success": True,
        "hostname": hostname,
        "certificate_valid": len(issues) == 0,
        "days_until_expiry": days_until_expiry,
        "tls_version": connection.get("tls_version", ""),
        "cipher_suite": connection.get("cipher", ""),
        "security_issues": security_issues,
        "severity_breakdown": severity_counts,
        "recommendations": recommendations,
        "scan_summary": f"SSL/TLS check for {hostname}: {len(issues)} issues found",
        "certificate_info": {
            "subject": certificate.get("subject", {}),
            "issuer": certificate.get("issuer", {}),
            "not_after": certificate.get("not_after", "")
        }
    }


def summarize_http_headers(headers_result: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize HTTP security headers check results"""
    
    if not headers_result.get("success", False):
        return {
            "scanner": "http_headers",
            "success": False,
            "error": headers_result.get("error", "Unknown error"),
            "security_score": 0,
            "recommendations": []
        }
    
    missing_headers = headers_result.get("missing_headers", [])
    present_headers = headers_result.get("present_headers", {})
    security_score = headers_result.get("security_score", 0)
    
    # Categorize missing headers by importance
    critical_headers = ["Strict-Transport-Security", "Content-Security-Policy"]
    important_headers = ["X-Frame-Options", "X-Content-Type-Options"]
    
    critical_missing = [h for h in missing_headers if h["header"] in critical_headers]
    important_missing = [h for h in missing_headers if h["header"] in important_headers]
    
    recommendations = []
    if critical_missing:
        recommendations.append("Implement critical security headers (HSTS, CSP)")
    if important_missing:
        recommendations.append("Add important security headers (X-Frame-Options, etc.)")
    if security_score < 80:
        recommendations.append("Review and implement comprehensive security headers")
    
    return {
        "scanner": "http_headers",
        "success": True,
        "security_score": security_score,
        "present_headers": present_headers,
        "missing_headers": missing_headers,
        "critical_missing": len(critical_missing),
        "important_missing": len(important_missing),
        "recommendations": recommendations,
        "scan_summary": f"HTTP security headers: {security_score:.1f}% compliance"
    }


def create_unified_summary(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Create a unified summary of all scan results"""
    
    total_issues = 0
    high_severity_issues = 0
    all_recommendations = []
    scanner_summaries = []
    
    for scanner_name, result in scan_results.items():
        if not result.get("success", False):
            continue
        
        # Count issues
        if "total_vulns" in result:
            total_issues += result["total_vulns"]
            severity_breakdown = result.get("severity_breakdown", {})
            high_severity_issues += severity_breakdown.get("high", 0) + severity_breakdown.get("critical", 0)
        elif "total_issues" in result:
            total_issues += result["total_issues"]
            severity_breakdown = result.get("severity_breakdown", {})
            high_severity_issues += severity_breakdown.get("HIGH", 0)
        
        # Collect recommendations
        recommendations = result.get("recommendations", [])
        all_recommendations.extend(recommendations)
        
        # Add to summary
        scanner_summaries.append({
            "scanner": scanner_name,
            "summary": result.get("scan_summary", ""),
            "issues": result.get("total_vulns", result.get("total_issues", 0)),
            "success": result.get("success", False)
        })
    
    # Calculate overall risk score
    risk_score = min(100, (high_severity_issues * 20) + (total_issues * 5))
    
    return {
        "total_issues": total_issues,
        "high_severity_issues": high_severity_issues,
        "risk_score": risk_score,
        "risk_level": "HIGH" if risk_score >= 70 else "MEDIUM" if risk_score >= 30 else "LOW",
        "scanner_summaries": scanner_summaries,
        "recommendations": list(set(all_recommendations)),  # Remove duplicates
        "scan_timestamp": datetime.utcnow().isoformat(),
        "requires_immediate_attention": high_severity_issues > 0
    }