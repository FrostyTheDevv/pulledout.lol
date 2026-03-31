"""
Encrypted Scan Results Data Structure - PULLEDOUT.LOL Security Scanner
No HTML allowed - all data stored as structured fields
"""

from typing import List, Dict, Optional, Literal
from datetime import datetime
from dataclasses import dataclass, asdict
import json

# Severity levels
SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Finding categories
CategoryType = Literal[
    "SSL/TLS Security",
    "HTTP Security Headers",
    "Session Management",
    "Authentication",
    "Input Validation",
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Remote Code Execution (RCE)",
    "Server-Side Template Injection (SSTI)",
    "NoSQL Injection",
    "API Security", 
    "Information Disclosure",
    "Database Exposure",
    "File Upload",
    "Directory Traversal",
    "CMS Vulnerabilities",
    "Cloud Storage Exposure",
    "Cookie Security",
    "CSRF Protection",
    "Client-Side Security",
    "Performance & Availability",
    "Technology Detection",
    "Network Reconnaissance",
    "Data Extraction",
    "Credential Harvesting",
    "Session Hijacking",
    "Database Penetration",
    "Resource Security",
    "Discovery & Hygiene"
]

@dataclass
class FindingDetail:
    """
    Individual security finding - NO HTML ALLOWED
    All content must be plain text or URL references
    """
    severity: SeverityLevel
    category: CategoryType
    title: str  # Brief, descriptive title
    description: str  # Plain text description
    affected_urls: List[str]  # List of URLs where issue was found
    evidence: Dict[str, any]  # Structured evidence (headers, cookies, etc.)
    remediation: str  # Plain text remediation steps
    cwe_id: Optional[str] = None  # CWE identifier
    owasp_category: Optional[str] = None  # OWASP Top 10 category
    cvss_score: Optional[float] = None  # CVSS score if applicable
    references: List[str] = None  # Reference URLs for more info
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)
    
@dataclass
class ModuleResult:
    """Result from a single security module"""
    module_name: str
    status: Literal["completed", "failed", "skipped"]
    findings_count: int
    execution_time: float  # seconds
    error_message: Optional[str] = None
    
@dataclass
class ScanMetadata:
    """Metadata about the scan execution"""
    scan_id: str
    target_url: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    pages_scanned: int
    total_requests: int
    scanner_version: str = "2.0.0"
    modules_executed: List[ModuleResult] = None
    
@dataclass
class ScanResults:
    """
    Complete scan results structure - ENCRYPTED when stored
    NO HTML - only plain text and structured data
    """
    metadata: ScanMetadata
    risk_score: int  # 0-100
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    findings: List[FindingDetail]
    findings_summary: Dict[str, int]  # {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 5, ...}
    technology_stack: Dict[str, List[str]]  # {"servers": ["nginx"], "frameworks": ["React"], ...}
    discovered_endpoints: List[str]  # All discovered URLs
    
    def to_json(self) -> str:
        """Serialize to JSON for encryption"""
        data = {
            "metadata": {
                "scan_id": self.metadata.scan_id,
                "target_url": self.metadata.target_url,
                "start_time": self.metadata.start_time.isoformat(),
                "end_time": self.metadata.end_time.isoformat(),
                "duration_seconds": self.metadata.duration_seconds,
                "pages_scanned": self.metadata.pages_scanned,
                "total_requests": self.metadata.total_requests,
                "scanner_version": self.metadata.scanner_version,
                "modules_executed": [asdict(m) for m in self.metadata.modules_executed] if self.metadata.modules_executed else []
            },
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "findings": [f.to_dict() for f in self.findings],
            "findings_summary": self.findings_summary,
            "technology_stack": self.technology_stack,
            "discovered_endpoints": self.discovered_endpoints
        }
        return json.dumps(data, indent=2, default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ScanResults':
        """Deserialize from JSON after decryption"""
        data = json.loads(json_str)
        
        # Reconstruct metadata
        metadata = ScanMetadata(
            scan_id=data["metadata"]["scan_id"],
            target_url=data["metadata"]["target_url"],
            start_time=datetime.fromisoformat(data["metadata"]["start_time"]),
            end_time=datetime.fromisoformat(data["metadata"]["end_time"]),
            duration_seconds=data["metadata"]["duration_seconds"],
            pages_scanned=data["metadata"]["pages_scanned"],
            total_requests=data["metadata"]["total_requests"],
            scanner_version=data["metadata"]["scanner_version"],
            modules_executed=[ModuleResult(**m) for m in data["metadata"].get("modules_executed", [])]
        )
        
        # Reconstruct findings
        findings = [FindingDetail(**f) for f in data["findings"]]
        
        return cls(
            metadata=metadata,
            risk_score=data["risk_score"],
            risk_level=data["risk_level"],
            findings=findings,
            findings_summary=data["findings_summary"],
            technology_stack=data["technology_stack"],
            discovered_endpoints=data["discovered_endpoints"]
        )


# Example usage:
"""
finding = FindingDetail(
    severity="HIGH",
    category="SQL Injection",
    title="SQL Injection in login form",
    description="Login form vulnerable to SQL injection via username parameter",
    affected_urls=["https://example.com/login"],
    evidence={
        "parameter": "username",
        "payload": "' OR '1'='1",
        "response_time": 2.5,
        "error_message": "MySQL syntax error"
    },
    remediation="Use parameterized queries instead of string concatenation",
    cwe_id="CWE-89",
    owasp_category="A03:2021 - Injection",
    cvss_score=8.6,
    references=["https://owasp.org/www-community/attacks/SQL_Injection"]
)
"""
