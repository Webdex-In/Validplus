from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class DNSSecurityChecks:
    has_spf: bool
    has_dmarc: bool
    has_dkim: bool
    spf_record: str
    dmarc_record: str
    dkim_record: str
    spf_valid: bool
    dmarc_valid: bool
    dkim_valid: bool

@dataclass
class SecurityChecks:
    blacklisted: bool
    blacklist_records: List[str]
    spam_score: int
    abuse_score: int
    domain_reputation: str

@dataclass
class MailServerChecks:
    has_valid_mx: bool
    mx_records: List[str]
    response_time: float
    accepts_all: bool
    has_catch_all: bool
    port_open: bool
    smtp_provider: str

@dataclass
class VerificationScore:
    score: int
    verdict: str
    details: List[str]
    confidence: str
    verification_time: float

@dataclass
class EmailVerificationResult:
    is_valid: bool
    format_valid: bool
    syntax_checks: Dict[str, bool]
    mx_check: MailServerChecks
    smtp_check: bool
    is_disposable: bool
    is_role_account: bool
    is_free_email: bool
    dns_security: DNSSecurityChecks
    security_checks: SecurityChecks
    suggestions: List[str]
    score: VerificationScore
    error_message: Optional[str] = None