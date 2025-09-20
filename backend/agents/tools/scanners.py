"""
Security scanning tools for various vulnerability types
"""
import json
import subprocess
import ssl
import socket
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import tempfile
import os


def run_command(cmd: List[str], cwd: Optional[str] = None) -> Dict[str, Any]:
    """Run a shell command and return result"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=300  # 5 minute timeout
        )
        return {
            "success": True,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Command timed out after 300 seconds",
            "returncode": -1
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "returncode": -1
        }


def npm_audit_json(project_path: str = ".") -> Dict[str, Any]:
    """Run npm audit and return JSON results"""
    
    # Check if package.json exists
    package_json_path = Path(project_path) / "package.json"
    if not package_json_path.exists():
        return {
            "success": False,
            "error": "No package.json found",
            "vulnerabilities": {},
            "metadata": {"totalVulnerabilities": 0}
        }
    
    # Run npm audit
    result = run_command(["npm", "audit", "--json"], cwd=project_path)
    
    if not result["success"]:
        return {
            "success": False,
            "error": result.get("error", "npm audit failed"),
            "vulnerabilities": {},
            "metadata": {"totalVulnerabilities": 0}
        }
    
    try:
        audit_data = json.loads(result["stdout"])
        return {
            "success": True,
            "vulnerabilities": audit_data.get("vulnerabilities", {}),
            "metadata": audit_data.get("metadata", {}),
            "raw_output": audit_data
        }
    except json.JSONDecodeError:
        return {
            "success": False,
            "error": "Failed to parse npm audit JSON output",
            "vulnerabilities": {},
            "metadata": {"totalVulnerabilities": 0}
        }


def safety_check_json(requirements_file: str = "requirements.txt") -> Dict[str, Any]:
    """Run safety check and return structured results"""
    
    # Check if requirements file exists
    if not Path(requirements_file).exists():
        return {
            "success": False,
            "error": f"Requirements file {requirements_file} not found",
            "vulnerabilities": [],
            "summary": {"total_vulns": 0}
        }
    
    # Run safety check
    result = run_command([
        "safety", "check", 
        "--json", 
        "--file", requirements_file
    ])
    
    if not result["success"]:
        return {
            "success": False,
            "error": result.get("error", "safety check failed"),
            "vulnerabilities": [],
            "summary": {"total_vulns": 0}
        }
    
    try:
        # Safety outputs one JSON object per line
        vulnerabilities = []
        for line in result["stdout"].strip().split('\n'):
            if line.strip():
                vuln = json.loads(line)
                vulnerabilities.append(vuln)
        
        return {
            "success": True,
            "vulnerabilities": vulnerabilities,
            "summary": {"total_vulns": len(vulnerabilities)},
            "raw_output": result["stdout"]
        }
    except json.JSONDecodeError:
        return {
            "success": False,
            "error": "Failed to parse safety JSON output",
            "vulnerabilities": [],
            "summary": {"total_vulns": 0}
        }


def bandit_scan_json(project_path: str = ".") -> Dict[str, Any]:
    """Run bandit security scan and return JSON results"""
    
    # Create temporary output file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
        output_file = tmp_file.name
    
    try:
        # Run bandit scan
        result = run_command([
            "bandit", 
            "-r", project_path,
            "-f", "json",
            "-o", output_file,
            "--skip", "B101,B601"  # Skip common false positives
        ])
        
        # Read the output file
        if Path(output_file).exists():
            with open(output_file, 'r') as f:
                bandit_data = json.load(f)
        else:
            bandit_data = {"results": [], "metrics": {}}
        
        # Process results
        issues = bandit_data.get("results", [])
        metrics = bandit_data.get("metrics", {})
        
        # Count by severity
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        for issue in issues:
            severity = issue.get("issue_severity", "LOW")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "success": True,
            "issues": issues,
            "counts": severity_counts,
            "metrics": metrics,
            "summary": {
                "total_issues": len(issues),
                "high_severity": severity_counts.get("HIGH", 0)
            }
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Bandit scan failed: {str(e)}",
            "issues": [],
            "counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
            "summary": {"total_issues": 0, "high_severity": 0}
        }
    finally:
        # Cleanup temporary file
        if Path(output_file).exists():
            os.unlink(output_file)


def check_ssl_openssl(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Check SSL certificate using OpenSSL-style verification"""
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect and get certificate
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
        
        # Parse certificate dates
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        # Calculate days until expiry
        days_until_expiry = (not_after - datetime.now()).days
        
        # Check for issues
        issues = []
        if days_until_expiry < 30:
            issues.append(f"Certificate expires in {days_until_expiry} days")
        
        if version and version < 'TLSv1.2':
            issues.append(f"Outdated TLS version: {version}")
        
        return {
            "success": True,
            "hostname": hostname,
            "port": port,
            "certificate": {
                "subject": dict(x[0] for x in cert['subject']),
                "issuer": dict(x[0] for x in cert['issuer']),
                "not_before": cert['notBefore'],
                "not_after": cert['notAfter'],
                "serial_number": cert['serialNumber'],
                "version": cert['version']
            },
            "connection": {
                "cipher": cipher,
                "tls_version": version
            },
            "security": {
                "days_until_expiry": days_until_expiry,
                "issues": issues,
                "is_valid": len(issues) == 0
            }
        }
        
    except socket.gaierror:
        return {
            "success": False,
            "error": f"DNS resolution failed for {hostname}",
            "hostname": hostname,
            "port": port
        }
    except socket.timeout:
        return {
            "success": False,
            "error": f"Connection timeout to {hostname}:{port}",
            "hostname": hostname,
            "port": port
        }
    except ssl.SSLError as e:
        return {
            "success": False,
            "error": f"SSL error: {str(e)}",
            "hostname": hostname,
            "port": port
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
            "hostname": hostname,
            "port": port
        }


def check_http_headers(url: str) -> Dict[str, Any]:
    """Check HTTP security headers"""
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers
        
        # Security headers to check
        security_headers = {
            'Strict-Transport-Security': 'HSTS not implemented',
            'Content-Security-Policy': 'CSP not implemented', 
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME sniffing protection missing',
            'Referrer-Policy': 'Referrer policy not set',
            'Permissions-Policy': 'Permissions policy not set'
        }
        
        missing_headers = []
        present_headers = {}
        
        for header, description in security_headers.items():
            if header in headers:
                present_headers[header] = headers[header]
            else:
                missing_headers.append({
                    "header": header,
                    "description": description
                })
        
        return {
            "success": True,
            "url": url,
            "status_code": response.status_code,
            "present_headers": present_headers,
            "missing_headers": missing_headers,
            "security_score": len(present_headers) / len(security_headers) * 100,
            "issues": len(missing_headers)
        }
        
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "error": f"HTTP request failed: {str(e)}",
            "url": url
        }


def scan_open_ports(hostname: str, ports: List[int] = None) -> Dict[str, Any]:
    """Basic port scan for common services"""
    
    if ports is None:
        ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
    
    open_ports = []
    closed_ports = []
    
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
        except Exception:
            closed_ports.append(port)
    
    return {
        "success": True,
        "hostname": hostname,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "scan_summary": {
            "total_ports_scanned": len(ports),
            "open_count": len(open_ports),
            "closed_count": len(closed_ports)
        }
    }