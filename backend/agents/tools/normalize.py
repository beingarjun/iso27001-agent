from typing import Dict, Any, List"""

Tools for normalizing and summarizing security scan results

def summarize_npm_audit(audit_data: Dict[str, Any]) -> Dict[str, Any]:"""

    """Normalize npm audit results"""from typing import Dict, Any, List

    if not audit_data or "vulnerabilities" not in audit_data:from datetime import datetime

        return {"total_vulns": 0, "by_severity": {}, "critical_packages": []}

    

    vulnerabilities = audit_data.get("vulnerabilities", {})def summarize_npm_audit(npm_result: Dict[str, Any]) -> Dict[str, Any]:

    by_severity = {"critical": 0, "high": 0, "moderate": 0, "low": 0, "info": 0}    """Normalize npm audit results into standard format"""

    critical_packages = []    

        if not npm_result.get("success", False):

    for package, vuln_info in vulnerabilities.items():        return {

        if isinstance(vuln_info, dict):            "scanner": "npm_audit",

            severity = vuln_info.get("severity", "info").lower()            "success": False,

            if severity in by_severity:            "error": npm_result.get("error", "Unknown error"),

                by_severity[severity] += 1            "total_vulns": 0,

                        "severity_breakdown": {"low": 0, "moderate": 0, "high": 0, "critical": 0},

            if severity in ["critical", "high"]:            "recommendations": []

                critical_packages.append({        }

                    "package": package,    

                    "severity": severity,    vulnerabilities = npm_result.get("vulnerabilities", {})

                    "title": vuln_info.get("title", ""),    metadata = npm_result.get("metadata", {})

                    "range": vuln_info.get("range", "")    

                })    # Count vulnerabilities by severity

        severity_counts = {"low": 0, "moderate": 0, "high": 0, "critical": 0}

    total_vulns = sum(by_severity.values())    vulnerable_packages = []

        

    return {    for pkg_name, vuln_info in vulnerabilities.items():

        "total_vulns": total_vulns,        if isinstance(vuln_info, dict):

        "by_severity": by_severity,            severity = vuln_info.get("severity", "low").lower()

        "critical_packages": critical_packages[:10],  # Limit to top 10            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        "summary": f"Found {total_vulns} vulnerabilities ({by_severity['critical']} critical, {by_severity['high']} high)"            

    }            vulnerable_packages.append({

                "package": pkg_name,

def summarize_safety(safety_data: List[Dict[str, Any]]) -> Dict[str, Any]:                "severity": severity,

    """Normalize safety check results"""                "title": vuln_info.get("title", ""),

    if not safety_data:                "url": vuln_info.get("url", ""),

        return {"total_vulns": 0, "vulnerable_packages": [], "summary": "No known vulnerabilities found"}                "vulnerable_versions": vuln_info.get("range", "")

                })

    vulnerable_packages = []    

    for vuln in safety_data:    total_vulns = sum(severity_counts.values())

        vulnerable_packages.append({    

            "package": vuln.get("package_name", "unknown"),    # Generate recommendations

            "version": vuln.get("installed_version", "unknown"),    recommendations = []

            "vulnerability": vuln.get("vulnerability_id", ""),    if total_vulns > 0:

            "advisory": vuln.get("advisory", "")[:200] + "..." if len(vuln.get("advisory", "")) > 200 else vuln.get("advisory", "")        recommendations.append("Run 'npm audit fix' to automatically fix vulnerabilities")

        })        if severity_counts["high"] > 0 or severity_counts["critical"] > 0:

                recommendations.append("Review and manually fix high/critical vulnerabilities")

    total_vulns = len(vulnerable_packages)        recommendations.append("Consider using 'npm audit fix --force' for breaking changes")

            recommendations.append("Update package.json to pin secure versions")

    return {    

        "total_vulns": total_vulns,    return {

        "vulnerable_packages": vulnerable_packages[:10],  # Limit to top 10        "scanner": "npm_audit",

        "summary": f"Found {total_vulns} vulnerable packages"        "success": True,

    }        "total_vulns": total_vulns,

        "severity_breakdown": severity_counts,

def summarize_bandit(bandit_data: Dict[str, Any]) -> Dict[str, Any]:        "vulnerable_packages": vulnerable_packages,

    """Normalize bandit scan results"""        "recommendations": recommendations,

    if not bandit_data or "results" not in bandit_data:        "scan_summary": f"Found {total_vulns} vulnerabilities in npm dependencies",

        return {"total_issues": 0, "counts": {}, "high_severity": [], "summary": "No security issues found"}        "metadata": metadata

        }

    results = bandit_data.get("results", [])

    metrics = bandit_data.get("metrics", {}).get("_totals", {})

    def summarize_safety(safety_result: Dict[str, Any]) -> Dict[str, Any]:

    counts = {    """Normalize safety check results into standard format"""

        "HIGH": metrics.get("SEVERITY.HIGH", 0),    

        "MEDIUM": metrics.get("SEVERITY.MEDIUM", 0),    if not safety_result.get("success", False):

        "LOW": metrics.get("SEVERITY.LOW", 0)        return {

    }            "scanner": "safety",

                "success": False,

    high_severity = []            "error": safety_result.get("error", "Unknown error"),

    for result in results:            "total_vulns": 0,

        if result.get("issue_severity") == "HIGH":            "severity_breakdown": {"low": 0, "medium": 0, "high": 0},

            high_severity.append({            "recommendations": []

                "filename": result.get("filename", ""),        }

                "line_number": result.get("line_number", 0),    

                "test_name": result.get("test_name", ""),    vulnerabilities = safety_result.get("vulnerabilities", [])

                "issue_text": result.get("issue_text", "")[:200] + "..." if len(result.get("issue_text", "")) > 200 else result.get("issue_text", "")    

            })    # Process vulnerabilities

        severity_counts = {"low": 0, "medium": 0, "high": 0}

    total_issues = sum(counts.values())    vulnerable_packages = []

        

    return {    for vuln in vulnerabilities:

        "total_issues": total_issues,        # Safety doesn't provide severity, so we estimate based on advisory

        "counts": counts,        advisory = vuln.get("advisory", "").lower()

        "high_severity": high_severity[:10],  # Limit to top 10        if any(word in advisory for word in ["critical", "remote code execution", "sql injection"]):

        "summary": f"Found {total_issues} security issues ({counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low)"            severity = "high"

    }        elif any(word in advisory for word in ["moderate", "denial of service", "information disclosure"]):

            severity = "medium"

def summarize_ssl(ssl_data: Dict[str, Any]) -> Dict[str, Any]:        else:

    """Normalize SSL certificate check results"""            severity = "low"

    if not ssl_data:        

        return {"valid": False, "issues": ["SSL check failed"], "summary": "SSL certificate validation failed"}        severity_counts[severity] += 1

            

    if not ssl_data.get("valid", False):        vulnerable_packages.append({

        return {            "package": vuln.get("package_name", ""),

            "valid": False,            "severity": severity,

            "error": ssl_data.get("error", "Unknown SSL error"),            "installed_version": vuln.get("installed_version", ""),

            "issues": [f"SSL connection failed: {ssl_data.get('error', 'Unknown error')}"],            "vulnerable_spec": vuln.get("vulnerable_spec", ""),

            "summary": "SSL certificate validation failed"            "advisory": vuln.get("advisory", ""),

        }            "vulnerability_id": vuln.get("vulnerability_id", "")

            })

    issues = []    

        total_vulns = len(vulnerabilities)

    # Check certificate expiry    

    not_after = ssl_data.get("not_after")    # Generate recommendations

    if not_after:    recommendations = []

        from datetime import datetime    if total_vulns > 0:

        try:        recommendations.append("Update vulnerable Python packages to secure versions")

            # Parse the certificate date format        recommendations.append("Pin package versions in requirements.txt")

            exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")        recommendations.append("Consider using virtual environments for isolation")

            days_until_expiry = (exp_date - datetime.now()).days        if severity_counts["high"] > 0:

                        recommendations.append("Prioritize fixing high-severity Python vulnerabilities")

            if days_until_expiry < 30:    

                issues.append(f"Certificate expires in {days_until_expiry} days")    return {

            elif days_until_expiry < 0:        "scanner": "safety",

                issues.append("Certificate has expired")        "success": True,

        except:        "total_vulns": total_vulns,

            issues.append("Could not parse certificate expiry date")        "severity_breakdown": severity_counts,

            "vulnerable_packages": vulnerable_packages,

    # Check subject        "recommendations": recommendations,

    subject = ssl_data.get("subject", {})        "scan_summary": f"Found {total_vulns} vulnerabilities in Python dependencies"

    hostname = ssl_data.get("hostname", "")    }

    if subject.get("commonName") != hostname:

        issues.append(f"Certificate CN '{subject.get('commonName')}' doesn't match hostname '{hostname}'")

    def summarize_bandit(bandit_result: Dict[str, Any]) -> Dict[str, Any]:

    return {    """Normalize bandit scan results into standard format"""

        "valid": ssl_data.get("valid", False),    

        "hostname": hostname,    if not bandit_result.get("success", False):

        "subject": subject,        return {

        "issuer": ssl_data.get("issuer", {}),            "scanner": "bandit",

        "not_after": not_after,            "success": False,

        "issues": issues,            "error": bandit_result.get("error", "Unknown error"),

        "summary": f"SSL certificate {'valid' if len(issues) == 0 else 'has issues'}: {', '.join(issues) if issues else 'No issues found'}"            "total_issues": 0,

    }            "severity_breakdown": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},

            "recommendations": []

def summarize_custom_checks(custom_data: Dict[str, Any]) -> Dict[str, Any]:        }

    """Normalize custom security check results"""    

    if not custom_data:    issues = bandit_result.get("issues", [])

        return {"total_issues": 0, "categories": {}, "summary": "No custom security issues found"}    counts = bandit_result.get("counts", {"LOW": 0, "MEDIUM": 0, "HIGH": 0})

        

    total_issues = 0    # Process issues by category

    categories = {}    issue_categories = {}

        code_issues = []

    for category, data in custom_data.items():    

        if isinstance(data, dict) and "total" in data:    for issue in issues:

            issue_count = data["total"]        test_id = issue.get("test_id", "")

            total_issues += issue_count        test_name = issue.get("test_name", "")

            categories[category] = {        severity = issue.get("issue_severity", "LOW")

                "count": issue_count,        confidence = issue.get("issue_confidence", "LOW")

                "issues": data.get("issues", [])[:5]  # Limit to top 5 per category        

            }        category = issue_categories.get(test_name, {

                "test_name": test_name,

    return {            "test_id": test_id,

        "total_issues": total_issues,            "count": 0,

        "categories": categories,            "max_severity": "LOW"

        "summary": f"Found {total_issues} custom security issues across {len(categories)} categories"        })

    }        
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