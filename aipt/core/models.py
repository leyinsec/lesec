from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum
import hashlib
import json


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnType(Enum):
    SQL_INJECTION = "SQL Injection"
    SQL_BLIND = "Blind SQL Injection"
    XSS = "Cross-Site Scripting (XSS)"
    XSS_DOM = "DOM-based XSS"
    XSS_STORED = "Stored XSS"
    SSRF = "Server-Side Request Forgery"
    IDOR = "Insecure Direct Object Reference"
    PATH_TRAVERSAL = "Path Traversal"
    COMMAND_INJECTION = "Command Injection"
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    XXE = "XML External Entity"
    XPATH_INJECTION = "XPath Injection"
    LDAP_INJECTION = "LDAP Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    TEMPLATE_INJECTION = "Server-Side Template Injection"
    CSRF = "Cross-Site Request Forgery"
    MISSING_SECURITY_HEADERS = "Missing Security Headers"
    INSECURE_COOKIE = "Insecure Cookie Configuration"
    CORS_MISCONFIGURATION = "CORS Misconfiguration"
    OPEN_REDIRECT = "Open Redirect"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    WEAK_CRYPTO = "Weak Cryptography"
    INFO_DISCLOSURE = "Information Disclosure"
    JS_VULNERABILITY = "JavaScript Vulnerability"
    API_VULNERABILITY = "API Security Issue"
    GRAPHQL_VULNERABILITY = "GraphQL Security Issue"
    WAF_DETECTED = "Web Application Firewall Detected"
    BUSINESS_LOGIC = "Business Logic Flaw"


@dataclass
class Evidence:
    request: str = ""
    response: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    matched_pattern: str = ""
    context: str = ""
    screenshot_path: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request": self.request[:2000] if self.request else "",
            "response": self.response[:2000] if self.response else "",
            "response_headers": dict(self.response_headers),
            "matched_pattern": self.matched_pattern,
            "context": self.context,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class Vulnerability:
    id: str = field(default_factory=lambda: hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:12])
    type: VulnType = VulnType.INFO_DISCLOSURE
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: Evidence = field(default_factory=Evidence)
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    ai_detected: bool = False
    ai_confidence: float = 0.0
    verified: bool = False
    false_positive_probability: float = 0.0
    tags: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence.to_dict(),
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "references": self.references,
            "ai_detected": self.ai_detected,
            "ai_confidence": self.ai_confidence,
            "verified": self.verified,
            "false_positive_probability": self.false_positive_probability,
            "tags": self.tags,
            "discovered_at": self.discovered_at.isoformat()
        }

    @property
    def risk_score(self) -> float:
        severity_weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0
        }
        base_score = severity_weights.get(self.severity, 0)
        if self.cvss_score:
            base_score = max(base_score, self.cvss_score)
        if self.ai_detected:
            base_score *= 1.1
        return min(base_score, 10.0)


@dataclass
class Form:
    url: str = ""
    action: str = ""
    method: str = "GET"
    inputs: List[Dict[str, Any]] = field(default_factory=list)
    enctype: str = ""
    id: Optional[str] = None
    name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
            "enctype": self.enctype,
            "id": self.id,
            "name": self.name
        }


@dataclass
class Endpoint:
    url: str = ""
    method: str = "GET"
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    response_status: int = 0
    response_size: int = 0
    response_hash: str = ""
    is_api: bool = False
    is_graphql: bool = False
    discovered_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": dict(self.parameters),
            "headers": dict(self.headers),
            "content_type": self.content_type,
            "response_status": self.response_status,
            "response_size": self.response_size,
            "response_hash": self.response_hash,
            "is_api": self.is_api,
            "is_graphql": self.is_graphql,
            "discovered_at": self.discovered_at.isoformat()
        }


@dataclass
class JSFile:
    url: str = ""
    content: str = ""
    size: int = 0
    is_minified: bool = False
    has_sourcemap: bool = False
    sourcemap_url: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    findings: List[Vulnerability] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    duration: float = 0.0
    urls_discovered: int = 0
    forms_discovered: int = 0
    endpoints_discovered: int = 0
    js_files_analyzed: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    forms: List[Form] = field(default_factory=list)
    js_files: List[JSFile] = field(default_factory=list)
    waf_detected: Optional[str] = None
    scan_config: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "urls_discovered": self.urls_discovered,
            "forms_discovered": self.forms_discovered,
            "endpoints_discovered": self.endpoints_discovered,
            "js_files_analyzed": self.js_files_analyzed,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "endpoints": [e.to_dict() for e in self.endpoints],
            "forms": [f.to_dict() for f in self.forms],
            "js_files": [{"url": j.url, "size": j.size, "is_minified": j.is_minified} for j in self.js_files],
            "waf_detected": self.waf_detected,
            "scan_config": self.scan_config,
            "errors": self.errors,
            "severity_summary": self.severity_summary,
            "total_risk_score": self.total_risk_score
        }

    @property
    def severity_summary(self) -> Dict[str, int]:
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for vuln in self.vulnerabilities:
            summary[vuln.severity.value] = summary.get(vuln.severity.value, 0) + 1
        return summary

    @property
    def total_risk_score(self) -> float:
        return sum(v.risk_score for v in self.vulnerabilities)

    def get_vulnerabilities_by_severity(self, severity: Severity) -> List[Vulnerability]:
        return [v for v in self.vulnerabilities if v.severity == severity]

    def get_vulnerabilities_by_type(self, vuln_type: VulnType) -> List[Vulnerability]:
        return [v for v in self.vulnerabilities if v.type == vuln_type]
