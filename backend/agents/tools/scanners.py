import json"""

import subprocessSecurity scanning tools for various vulnerability types

import ssl"""

import socketimport json

from typing import Dict, Any, Listimport subprocess

import tempfileimport ssl

import osimport socket

import requests

def npm_audit_json() -> Dict[str, Any]:from pathlib import Path

    """Run npm audit and return JSON results"""from typing import Dict, List, Any, Optional

    try:from datetime import datetime

        # Check if package.json exists, if not create a minimal oneimport tempfile

        if not os.path.exists("package.json"):import os

            minimal_package = {

                "name": "security-scan",

                "version": "1.0.0",def run_command(cmd: List[str], cwd: Optional[str] = None) -> Dict[str, Any]:

                "dependencies": {    """Run a shell command and return result"""

                    "lodash": "4.17.20",  # Known vulnerable version for demo    try:

                    "express": "4.17.1"        result = subprocess.run(

                }            cmd,

            }            capture_output=True,

            with open("package.json", "w") as f:            text=True,

                json.dump(minimal_package, f, indent=2)            cwd=cwd,

                    timeout=300  # 5 minute timeout

        result = subprocess.run(        )

            ["npm", "audit", "--json"],         return {

            capture_output=True,             "success": True,

            text=True,             "stdout": result.stdout,

            timeout=30            "stderr": result.stderr,

        )            "returncode": result.returncode

                }

        if result.stdout:    except subprocess.TimeoutExpired:

            return json.loads(result.stdout)        return {

        else:            "success": False,

            return {"vulnerabilities": {}, "metadata": {"total": 0}}            "error": "Command timed out after 300 seconds",

                        "returncode": -1

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError):        }

        return {"vulnerabilities": {}, "metadata": {"total": 0}}    except Exception as e:

        return {

def safety_check_json() -> Dict[str, Any]:            "success": False,

    """Run safety check and return structured results"""            "error": str(e),

    try:            "returncode": -1

        result = subprocess.run(        }

            ["safety", "check", "--json"], 

            capture_output=True, 

            text=True, def npm_audit_json(project_path: str = ".") -> Dict[str, Any]:

            timeout=30    """Run npm audit and return JSON results"""

        )    

            # Check if package.json exists

        if result.stdout:    package_json_path = Path(project_path) / "package.json"

            return json.loads(result.stdout)    if not package_json_path.exists():

        else:        return {

            return []            "success": False,

                        "error": "No package.json found",

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError):            "vulnerabilities": {},

        return []            "metadata": {"totalVulnerabilities": 0}

        }

def bandit_scan_json(path: str = ".") -> Dict[str, Any]:    

    """Run bandit security scan and return JSON results"""    # Run npm audit

    try:    result = run_command(["npm", "audit", "--json"], cwd=project_path)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:    

            output_file = f.name    if not result["success"]:

                return {

        result = subprocess.run(            "success": False,

            ["bandit", "-r", path, "-f", "json", "-o", output_file],             "error": result.get("error", "npm audit failed"),

            capture_output=True,             "vulnerabilities": {},

            text=True,             "metadata": {"totalVulnerabilities": 0}

            timeout=60        }

        )    

            try:

        # Bandit writes to file regardless of exit code        audit_data = json.loads(result["stdout"])

        if os.path.exists(output_file):        return {

            with open(output_file, 'r') as f:            "success": True,

                data = json.load(f)            "vulnerabilities": audit_data.get("vulnerabilities", {}),

            os.unlink(output_file)            "metadata": audit_data.get("metadata", {}),

            return data            "raw_output": audit_data

        else:        }

            return {"results": [], "metrics": {"_totals": {"SEVERITY.HIGH": 0, "SEVERITY.MEDIUM": 0, "SEVERITY.LOW": 0}}}    except json.JSONDecodeError:

                    return {

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError):            "success": False,

        return {"results": [], "metrics": {"_totals": {"SEVERITY.HIGH": 0, "SEVERITY.MEDIUM": 0, "SEVERITY.LOW": 0}}}            "error": "Failed to parse npm audit JSON output",

            "vulnerabilities": {},

def check_ssl_openssl(hostname: str, port: int = 443) -> Dict[str, Any]:            "metadata": {"totalVulnerabilities": 0}

    """Check SSL certificate for a hostname"""        }

    try:

        # Create SSL context

        context = ssl.create_default_context()def safety_check_json(requirements_file: str = "requirements.txt") -> Dict[str, Any]:

            """Run safety check and return structured results"""

        # Connect and get certificate    

        with socket.create_connection((hostname, port), timeout=10) as sock:    # Check if requirements file exists

            with context.wrap_socket(sock, server_hostname=hostname) as ssock:    if not Path(requirements_file).exists():

                cert = ssock.getpeercert()        return {

                            "success": False,

                return {            "error": f"Requirements file {requirements_file} not found",

                    "hostname": hostname,            "vulnerabilities": [],

                    "port": port,            "summary": {"total_vulns": 0}

                    "subject": dict(x[0] for x in cert.get('subject', [])),        }

                    "issuer": dict(x[0] for x in cert.get('issuer', [])),    

                    "not_before": cert.get('notBefore'),    # Run safety check

                    "not_after": cert.get('notAfter'),    result = run_command([

                    "serial_number": cert.get('serialNumber'),        "safety", "check", 

                    "version": cert.get('version'),        "--json", 

                    "signature_algorithm": cert.get('signatureAlgorithm'),        "--file", requirements_file

                    "san": cert.get('subjectAltName', []),    ])

                    "valid": True    

                }    if not result["success"]:

                        return {

    except (socket.timeout, socket.gaierror, ssl.SSLError, ConnectionRefusedError, OSError) as e:            "success": False,

        return {            "error": result.get("error", "safety check failed"),

            "hostname": hostname,            "vulnerabilities": [],

            "port": port,            "summary": {"total_vulns": 0}

            "error": str(e),        }

            "valid": False    

        }    try:

        # Safety outputs one JSON object per line

def run_custom_security_checks() -> Dict[str, Any]:        vulnerabilities = []

    """Run custom security checks"""        for line in result["stdout"].strip().split('\n'):

    checks = {            if line.strip():

        "file_permissions": check_sensitive_file_permissions(),                vuln = json.loads(line)

        "environment_vars": check_environment_variables(),                vulnerabilities.append(vuln)

        "open_ports": check_open_ports()        

    }        return {

    return checks            "success": True,

            "vulnerabilities": vulnerabilities,

def check_sensitive_file_permissions() -> Dict[str, Any]:            "summary": {"total_vulns": len(vulnerabilities)},

    """Check permissions on sensitive files"""            "raw_output": result["stdout"]

    sensitive_files = [".env", "config.yaml", "secrets.txt", "private.key"]        }

    issues = []    except json.JSONDecodeError:

            return {

    for file_path in sensitive_files:            "success": False,

        if os.path.exists(file_path):            "error": "Failed to parse safety JSON output",

            stat_info = os.stat(file_path)            "vulnerabilities": [],

            mode = oct(stat_info.st_mode)[-3:]            "summary": {"total_vulns": 0}

            if mode != "600":  # Should be readable/writable by owner only        }

                issues.append({

                    "file": file_path,

                    "current_mode": mode,def bandit_scan_json(project_path: str = ".") -> Dict[str, Any]:

                    "recommended_mode": "600"    """Run bandit security scan and return JSON results"""

                })    

        # Create temporary output file

    return {"issues": issues, "total": len(issues)}    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:

        output_file = tmp_file.name

def check_environment_variables() -> Dict[str, Any]:    

    """Check for sensitive data in environment variables"""    try:

    sensitive_patterns = ["password", "secret", "key", "token", "api_key"]        # Run bandit scan

    exposed_vars = []        result = run_command([

                "bandit", 

    for var_name, var_value in os.environ.items():            "-r", project_path,

        for pattern in sensitive_patterns:            "-f", "json",

            if pattern.lower() in var_name.lower():            "-o", output_file,

                exposed_vars.append({            "--skip", "B101,B601"  # Skip common false positives

                    "variable": var_name,        ])

                    "pattern_matched": pattern,        

                    "value_length": len(var_value) if var_value else 0        # Read the output file

                })        if Path(output_file).exists():

                break            with open(output_file, 'r') as f:

                    bandit_data = json.load(f)

    return {"exposed_variables": exposed_vars, "total": len(exposed_vars)}        else:

            bandit_data = {"results": [], "metrics": {}}

def check_open_ports() -> Dict[str, Any]:        

    """Check for commonly open ports (simplified check)"""        # Process results

    common_ports = [22, 80, 443, 3306, 5432, 6379, 27017]        issues = bandit_data.get("results", [])

    open_ports = []        metrics = bandit_data.get("metrics", {})

            

    for port in common_ports:        # Count by severity

        try:        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:        for issue in issues:

                s.settimeout(1)            severity = issue.get("issue_severity", "LOW")

                result = s.connect_ex(('127.0.0.1', port))            severity_counts[severity] = severity_counts.get(severity, 0) + 1

                if result == 0:        

                    open_ports.append(port)        return {

        except:            "success": True,

            continue            "issues": issues,

                "counts": severity_counts,

    return {"open_ports": open_ports, "total": len(open_ports)}            "metrics": metrics,
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