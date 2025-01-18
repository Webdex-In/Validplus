from dataclasses import dataclass
from typing import List, Dict, Optional, Any, Tuple
import dns.resolver
import socket
import smtplib
import time
import re
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from email_validator import validate_email, EmailNotValidError
from dns_cache import cached_dns_lookup, dns_cache, DNSCache
from smtp_pool import verify_email_with_pool, smtp_pool
from error_handler import (
    handle_dns_error, handle_smtp_error, log_error,
    DNSError, SMTPError, ValidationError
)
import traceback
import random
from config import (
    DNS_CONFIG,
    SMTP_CONFIG,
    ROLE_ACCOUNTS,
    DISPOSABLE_DOMAINS,
    FREE_EMAIL_PROVIDERS,
    BLACKLISTS,
    VALIDATION_RULES,
    ERROR_MESSAGES
)

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
    mx_records: List[str]
    mx_valid: bool

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
    mx_record_details: List[Dict]
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
    catch_all_details: Optional[Dict[str, Any]] = None

class EmailVerifier:
    """Production-ready email verification with comprehensive checks"""

    def __init__(self):
        """Initialize verifier with configuration and caching"""
        self.logger = logging.getLogger('email_verifier')

        # Initialize DNS components
        self.dns_cache = DNSCache()
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = DNS_CONFIG['NAMESERVERS']
        self.resolver.timeout = DNS_CONFIG['TIMEOUT']
        self.resolver.lifetime = DNS_CONFIG['LIFETIME']

        # Initialize SMTP components
        self.timeout = SMTP_CONFIG['TIMEOUT']
        self.retry_count = SMTP_CONFIG['RETRY_COUNT']
        self.retry_delay = SMTP_CONFIG['RETRY_DELAY']

        # Load configurations
        self.role_accounts = ROLE_ACCOUNTS
        self.disposable_domains = DISPOSABLE_DOMAINS
        self.free_providers = FREE_EMAIL_PROVIDERS
        self.blacklists = BLACKLISTS

        # Initialize spam trap patterns
        self._init_spam_trap_patterns()

        self.logger.info("EmailVerifier initialized with production configuration")

    def _init_spam_trap_patterns(self):
        """Initialize spam trap detection patterns"""
        self.spam_trap_patterns = {
            'prefixes': [
                # Common trap indicators
                'spam', 'trap', 'honey', 'spamtrap', 'filter', 'block',
                'abuse', 'report', 'blackhole', 'honeypot', 'spampot',

                # Testing/Validation
                'test', 'validate', 'verify', 'check', 'probe',
                'scan', 'audit', 'monitor', 'dummy', 'sample',

                # System accounts
                'system', 'daemon', 'robot', 'auto', 'noreply',
                'no-reply', 'donotreply', 'bounce', 'mailer'
            ],
            'patterns': [
                # Basic trap patterns
                r'^spam\.', r'^trap\.', r'^honey\.', r'^filter\.',
                r'^block\.', r'^catch\.', r'^bounce\.',

                # Development patterns
                r'^dev(el)?\d*\.', r'^test\d*\.', r'^admin\d*\.',
                r'^staging\.', r'^uat\.', r'^qa\.',

                # Random/Hash patterns
                r'[0-9a-f]{8,}',           # Hex strings
                r'\d{10,}',                # Long numbers
                r'^[a-z0-9]{20,}@',        # Long random strings
                r'[a-f0-9]{32}',           # MD5-like
                r'[a-f0-9]{40}',           # SHA1-like

                # Suspicious combinations
                r'^(spam|trap|honey).*\d{4,}',
                r'^(test|dev).*[0-9a-f]{6,}',
                r'(spam|trap|honey).*\.(test|dev)',

                # Time-based patterns
                r'\d{8,}.*@',              # Date-like numbers
                r'\d{4}-\d{2}-\d{2}',      # ISO date format

                # Special formatting
                r'.*\.{2,}.*@',            # Multiple dots
                r'.*_{2,}.*@',             # Multiple underscores
                r'.*-{2,}.*@'              # Multiple hyphens
            ]
        }

    def verify_email(self, email: str) -> EmailVerificationResult:
        """
        Perform comprehensive email verification with production safeguards

        Args:
            email: Email address to verify

        Returns:
            EmailVerificationResult containing detailed verification results
        """
        start_time = time.time()
        suggestions = []

        try:
            # Basic format validation
            try:
                if not self._validate_format(email):
                    raise ValidationError(
                        'INVALID_FORMAT',
                        ERROR_MESSAGES['INVALID_EMAIL'],
                        'Email format validation failed'
                    )
            except ValidationError as e:
                log_error(e.error, self.logger)
                return self._create_error_result(str(e))

            local_part, domain = email.lower().split('@')

            # Enhanced MX check with detailed information
            try:
                mx_data = self._enhanced_mx_check(domain)
                mx_check = self._parse_mx_records(mx_data)

                if not mx_check.has_valid_mx:
                    raise DNSError(
                        'NO_MX_RECORDS',
                        ERROR_MESSAGES['NO_MX_RECORDS'],
                        f"Domain: {domain}"
                    )
            except Exception as e:
                error = handle_dns_error(e)
                log_error(error, self.logger)
                return self._create_error_result(error.message)

            # Enhanced validation checks
            is_role = self._is_role_account(local_part)
            is_disposable = domain in self.disposable_domains
            is_spam_trap = self._is_spam_trap(local_part, domain)
            is_free_email = domain in self.free_providers

            # Advanced catch-all detection - BEFORE SMTP check
            try:
                is_catch_all, catch_all_details = self._check_catch_all(domain, mx_check.mx_records)
                mx_check.has_catch_all = is_catch_all
                mx_check.accepts_all = is_catch_all

                if is_catch_all and catch_all_details:
                    self.logger.warning(
                        f"Catch-all detected for {domain} "
                        f"(Confidence: {catch_all_details['confidence']:.2f}, "
                        f"Method: {catch_all_details['detection_method']})"
                    )
                    suggestions.append(f"Domain accepts all emails ({catch_all_details['server_behavior']})")
            except Exception as e:
                self.logger.error(f"Catch-all detection error for {domain}: {str(e)}")
                is_catch_all = False
                catch_all_details = None
                mx_check.has_catch_all = False
                mx_check.accepts_all = False

            # SMTP verification with connection pooling
            try:
                smtp_check = self._verify_smtp_with_role_check(email, mx_check.mx_records, is_role)
            except Exception as e:
                error = handle_smtp_error(e)
                log_error(error, self.logger)
                smtp_check = False

            # Security checks with caching
            try:
                dns_security = self._check_dns_security(domain)
                security_checks = self._check_security(domain)
            except Exception as e:
                error = handle_dns_error(e)
                log_error(error, self.logger)
                dns_security = DNSSecurityChecks(
                    has_spf=False, spf_record="", spf_valid=False,
                    has_dmarc=False, dmarc_record="", dmarc_valid=False,
                    has_dkim=False, dkim_record="", dkim_valid=False,
                    mx_records=[], mx_valid=False
                )
                security_checks = SecurityChecks(
                    blacklisted=False,
                    blacklist_records=[],
                    spam_score=0,
                    abuse_score=0,
                    domain_reputation="Unknown"
                )

            # Calculate initial score
            score = self._calculate_score(
                mx_check=mx_check,
                dns_security=dns_security,
                security_checks=security_checks,
                smtp_valid=smtp_check,
                is_role=is_role,
                is_disposable=is_disposable,
                is_spam_trap=is_spam_trap,
                verification_time=time.time() - start_time
            )

            # Adjust score for catch-all status
            if is_catch_all:
                score = self._adjust_score_for_catch_all(score, is_catch_all)

            # Add remaining suggestions
            suggestions.extend(self._generate_suggestions(
                smtp_check, is_role, is_spam_trap,
                security_checks, dns_security, mx_check
            ))

            return EmailVerificationResult(
                is_valid=smtp_check and not is_spam_trap,
                format_valid=True,
                syntax_checks=self._get_syntax_checks(email),
                mx_check=mx_check,
                smtp_check=smtp_check,
                is_disposable=is_disposable,
                is_role_account=is_role,
                is_free_email=is_free_email,
                dns_security=dns_security,
                security_checks=security_checks,
                suggestions=suggestions,
                score=score,
                catch_all_details=catch_all_details
            )

        except Exception as e:
            self.logger.error(f"Unexpected error verifying {email}: {str(e)}", exc_info=True)
            return self._create_error_result(f"Verification error: {str(e)}")


    def _validate_format(self, email: str) -> bool:
        """
        Validate email format using strict rules

        Args:
            email: Email address to validate

        Returns:
            bool: Whether format is valid
        """
        try:
            validate_email(email)
            local_part, domain = email.split('@')

            # Additional validation rules from config
            if len(local_part) > VALIDATION_RULES['MAX_LOCAL_PART_LENGTH']:
                return False
            if len(email) > VALIDATION_RULES['MAX_EMAIL_LENGTH']:
                return False

            return True
        except EmailNotValidError:
            return False

    def _enhanced_mx_check(self, domain: str) -> Dict:
        """
        Perform enhanced MX record validation with connection testing

        Args:
            domain: Domain to check

        Returns:
            Dict containing MX validation results
        """
        try:
            mx_records = self.resolver.resolve(domain, 'MX')
            mx_info = []

            # Test each MX record
            for record in mx_records:
                mx_host = str(record.exchange).rstrip('.')
                priority = record.preference
                try:
                    # Get IP and test port
                    ip = socket.gethostbyname(mx_host)
                    port_open = self._check_port_open(ip)

                    # Additional server info
                    server_info = {
                        'host': mx_host,
                        'priority': priority,
                        'ip': ip,
                        'port_open': port_open,
                        'response_time': self._measure_response_time(mx_host)
                    }
                    mx_info.append(server_info)
                except Exception as e:
                    self.logger.warning(f"Error checking MX record {mx_host}: {str(e)}")
                    mx_info.append({
                        'host': mx_host,
                        'priority': priority,
                        'ip': None,
                        'port_open': False,
                        'response_time': None
                    })

            return {
                'has_mx': True,
                'records': sorted(mx_info, key=lambda x: x['priority']),
                'error': None
            }
        except Exception as e:
            self.logger.error(f"MX check error for {domain}: {str(e)}")
            return {
                'has_mx': False,
                'records': [],
                'error': str(e)
            }

    def _parse_mx_records(self, mx_data: Dict) -> MailServerChecks:
        """
        Parse MX record data into structured format

        Args:
            mx_data: Raw MX record data

        Returns:
            MailServerChecks containing parsed MX information
        """
        if not mx_data['has_mx']:
            return MailServerChecks(
                has_valid_mx=False,
                mx_records=[],
                mx_record_details=[],
                response_time=0.0,
                accepts_all=False,
                has_catch_all=False,
                port_open=False,
                smtp_provider="unknown"
            )

        # Extract basic record info
        records = [r['host'] for r in mx_data['records']]
        port_open = any(r['port_open'] for r in mx_data['records'])

        # Get average response time
        response_times = [r['response_time'] for r in mx_data['records'] 
                        if r['response_time'] is not None]
        avg_response = sum(response_times) / len(response_times) if response_times else 0.0

        # Detect provider
        provider = self._detect_smtp_provider(records)

        return MailServerChecks(
            has_valid_mx=True,
            mx_records=records,
            mx_record_details=mx_data['records'],
            response_time=avg_response,
            accepts_all=False,  # Will be set by catch-all check
            has_catch_all=False,  # Will be set by catch-all check
            port_open=port_open,
            smtp_provider=provider
        )

    def _measure_response_time(self, host: str) -> Optional[float]:
        """
        Measure SMTP server response time

        Args:
            host: SMTP host to test

        Returns:
            float: Response time in seconds, or None if failed
        """
        try:
            start_time = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, 25))
                return time.time() - start_time
        except:
            return None

    def _check_port_open(self, host: str) -> bool:
        """
        Check if SMTP port is open

        Args:
            host: Host to check

        Returns:
            bool: Whether port 25 is open
        """
        for attempt in range(self.retry_count):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout / self.retry_count)
                    s.connect((host, 25))
                    return True
            except:
                if attempt < self.retry_count - 1:
                    time.sleep(self.retry_delay)
                continue
        return False

    def _detect_smtp_provider(self, mx_records: List[str]) -> str:
        """
        Detect email service provider from MX records

        Args:
            mx_records: List of MX record hostnames

        Returns:
            str: Detected provider name or "unknown"
        """
        provider_patterns = {
            'google': ['google', 'gmail', 'googlemail'],
            'microsoft': ['outlook', 'hotmail', 'microsoft'],
            'amazon': ['amazonses', 'aws-smtp'],
            'proton': ['protonmail', 'proton.ch'],
            'yahoo': ['yahoo', 'yahoodns'],
            'zoho': ['zoho', 'zohomail'],
            'mailgun': ['mailgun', 'mg'],
            'sendgrid': ['sendgrid', 'smtp.sendgrid'],
            'office365': ['protection.outlook.com'],
            'ovh': ['ovh.net'],
            'ionos': ['ionos'],
            'godaddy': ['secureserver.net']
        }

        # Check each provider's patterns
        for provider, patterns in provider_patterns.items():
            if any(pattern in mx.lower() for mx in mx_records 
                  for pattern in patterns):
                return provider

        return "unknown"

    @cached_dns_lookup
    def _check_dns_security(self, domain: str) -> DNSSecurityChecks:
        """
        Check domain DNS security configuration

        Args:
            domain: Domain to check

        Returns:
            DNSSecurityChecks containing security validation results
        """
        try:
            # Get all security records
            spf = self._check_spf(domain)
            dmarc = self._check_dmarc(domain)
            dkim = self._check_dkim(domain)
            mx = self._check_mx(domain)

            return DNSSecurityChecks(
                has_spf=spf['exists'],
                has_dmarc=dmarc['exists'],
                has_dkim=dkim['exists'],
                spf_record=spf['record'],
                dmarc_record=dmarc['record'],
                dkim_record=dkim['record'],
                spf_valid=spf['valid'],
                dmarc_valid=dmarc['valid'],
                dkim_valid=dkim['valid'],
                mx_records=mx['records'],
                mx_valid=mx['valid']
            )
        except Exception as e:
            self.logger.error(f"DNS security check error: {str(e)}", exc_info=True)
            return DNSSecurityChecks(
                has_spf=False, spf_record="", spf_valid=False,
                has_dmarc=False, dmarc_record="", dmarc_valid=False,
                has_dkim=False, dkim_record="", dkim_valid=False,
                mx_records=[], mx_valid=False
            )

    @cached_dns_lookup
    def _check_mx(self, domain: str) -> Dict[str, Any]:
        """Check domain MX records"""
        try:
            lookup_result = self.dns_cache.lookup(domain, 'MX')

            if 'error' in lookup_result:
                return {'valid': False, 'records': []}

            records = []
            for record in lookup_result['records']:
                records.append({
                    'exchange': record['exchange'],
                    'preference': record['preference']
                })

            sorted_records = sorted(records, key=lambda x: x['preference'])
            return {
                'valid': True,
                'records': [f"{r['exchange']} (Priority: {r['preference']})" for r in sorted_records]
            }
        except Exception:
            return {'valid': False, 'records': []}

    def _check_security(self, domain: str) -> SecurityChecks:
        """Check domain security status"""
        blacklisted = False
        blacklist_records = []

        for bl in self.blacklists:
            try:
                test_domain = f"{domain}.{bl}"
                result = self.dns_cache.lookup(test_domain, 'A')
                if 'error' not in result:
                    blacklisted = True
                    blacklist_records.append(bl)
            except:
                continue

        abuse_score = 50 if blacklisted else 0
        reputation = "Poor" if blacklisted else "Good"

        return SecurityChecks(
            blacklisted=blacklisted,
            blacklist_records=blacklist_records,
            spam_score=50 if blacklisted else 0,
            abuse_score=abuse_score,
            domain_reputation=reputation
        )

    @cached_dns_lookup
    def _check_spf(self, domain: str) -> Dict[str, Any]:
        """
        Check domain SPF records with validation

        Args:
            domain: Domain to check

        Returns:
            Dict containing SPF check results
        """
        result = self.dns_cache.lookup(domain, 'TXT')
        if 'error' in result:
            return {'exists': False, 'record': '', 'valid': False}

        for record in result['records']:
            if record.startswith('v=spf1'):
                # Validate SPF syntax
                valid = self._validate_spf(record)
                return {
                    'exists': True,
                    'record': record,
                    'valid': valid
                }

        return {'exists': False, 'record': '', 'valid': False}

    def _validate_spf(self, record: str) -> bool:
        """
        Validate SPF record syntax

        Args:
            record: SPF record to validate

        Returns:
            bool: Whether syntax is valid
        """
        try:
            # Basic SPF syntax validation
            parts = record.split()
            if parts[0] != 'v=spf1':
                return False

            valid_mechanisms = {'all', 'include', 'a', 'mx', 'ip4', 'ip6', 
                              'exists', 'redirect', 'exp', 'ptr'}
            valid_qualifiers = {'+', '-', '~', '?'}

            for part in parts[1:]:
                # Check qualifiers
                if part[0] in valid_qualifiers:
                    part = part[1:]

                # Check mechanisms
                mechanism = part.split(':', 1)[0]
                if mechanism not in valid_mechanisms:
                    return False

            return True
        except:
            return False

    @cached_dns_lookup
    def _check_dmarc(self, domain: str) -> Dict[str, Any]:
        """
        Check domain DMARC records with policy validation

        Args:
            domain: Domain to check

        Returns:
            Dict containing DMARC check results
        """
        try:
            dmarc_domain = f'_dmarc.{domain}'
            result = self.dns_cache.lookup(dmarc_domain, 'TXT')

            if 'error' in result:
                return {'exists': False, 'record': '', 'valid': False}

            for record in result['records']:
                if record.startswith('v=DMARC1'):
                    # Validate DMARC policy
                    policy = re.search(r'p=(\w+)', record)
                    valid = bool(policy and policy.group(1) in ['reject', 'quarantine', 'none'])
                    return {
                        'exists': True,
                        'record': record,
                        'valid': valid,
                        'policy': policy.group(1) if policy else 'none'
                    }

            return {'exists': False, 'record': '', 'valid': False, 'policy': None}
        except Exception as e:
            self.logger.error(f"DMARC check error: {str(e)}", exc_info=True)
            return {'exists': False, 'record': '', 'valid': False, 'policy': None}

    @cached_dns_lookup
    def _check_dkim(self, domain: str) -> Dict[str, Any]:
        """
        Check domain DKIM records with comprehensive selector testing

        Args:
            domain: Domain to check

        Returns:
            Dict containing DKIM check results
        """
        selectors = ['default', 'google', 'k1', 'mail', 'dkim', 
                    'selector1', 'selector2', 'key1', 'key2']

        for selector in selectors:
            try:
                dkim_domain = f'{selector}._domainkey.{domain}'
                result = self.dns_cache.lookup(dkim_domain, 'TXT')

                if 'error' not in result:
                    for record in result['records']:
                        if 'v=DKIM1' in record:
                            # Validate DKIM record
                            valid = self._validate_dkim(record)
                            return {
                                'exists': True,
                                'record': record,
                                'valid': valid,
                                'selector': selector
                            }
            except Exception as e:
                self.logger.debug(f"DKIM check failed for selector {selector}: {str(e)}")
                continue

        return {'exists': False, 'record': '', 'valid': False, 'selector': None}

    def _validate_dkim(self, record: str) -> bool:
        """
        Validate DKIM record syntax

        Args:
            record: DKIM record to validate

        Returns:
            bool: Whether syntax is valid
        """
        try:
            # Required DKIM tags
            required_tags = ['v', 'k', 'p']

            # Parse tags
            tags = {}
            parts = record.split(';')
            for part in parts:
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    tags[key.strip()] = value.strip()

            # Check required tags
            for tag in required_tags:
                if tag not in tags:
                    return False

            # Validate version
            if tags['v'] != 'DKIM1':
                return False

            # Validate key type
            if tags['k'] not in ['rsa', 'ed25519']:
                return False

            # Validate public key presence
            if not tags['p']:
                return False

            return True
        except:
            return False

    def _check_catch_all(self, domain: str, mx_records: List[str]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Advanced catch-all detection with multiple testing strategies"""
        self.logger.info(f"Starting catch-all detection for {domain}")
        start_time = time.time()  # Added this line

        try:
            # Test patterns
            patterns = [
                f"nonexistent_{int(time.time())}_{random.randint(1000, 9999)}@{domain}",
                f"test.{time.time()}@{domain}",
                f"verify.{random.randint(1000, 9999)}@{domain}",
                f"thisisnotarealuser_{random.randint(100000, 999999)}@{domain}",
                f"catchalltest_{time.time()}@{domain}"
            ]

            results = []
            for pattern in patterns:
                self.logger.debug(f"Testing catch-all pattern: {pattern}")
                for attempt in range(self.retry_count):
                    try:
                        is_valid = self._verify_smtp_with_role_check(pattern, mx_records, False)
                        results.append(is_valid)
                        break
                    except Exception as e:
                        if attempt < self.retry_count - 1:
                            time.sleep(self.retry_delay)
                            continue
                        self.logger.warning(f"Catch-all test failed for {pattern}: {str(e)}")
                        results.append(False)
                        break

            valid_count = sum(1 for r in results if r)
            is_catch_all = valid_count >= 2

            if is_catch_all:
                confidence = min(0.95, 0.5 + (valid_count / len(patterns)) * 0.45)
                detection_method = 'multiple_pattern_test'
                server_behavior = 'accepts_all_standard_patterns'
            else:
                confidence = 0.9
                detection_method = 'standard_test'
                server_behavior = 'normal_validation'

            catch_all_details = {
                'is_catch_all': is_catch_all,
                'detection_method': detection_method,
                'confidence': confidence,
                'server_behavior': server_behavior,
                'response_patterns': {
                    'test_patterns': patterns,
                    'results': results,
                    'valid_count': valid_count
                },
                'verification_time': time.time() - start_time
            }

            self.logger.info(
                f"Catch-all detection completed for {domain}: "
                f"{'Detected' if is_catch_all else 'Not detected'} "
                f"(Confidence: {confidence:.2f})"
            )

            return is_catch_all, catch_all_details

        except Exception as e:
            self.logger.error(f"Catch-all detection error: {str(e)}", exc_info=True)
            return False, None

    def _verify_smtp_with_role_check(self, email: str, mx_records: List[str], is_role: bool) -> bool:
        """Verify email via SMTP with role account handling"""
        if not mx_records:
            return False

        for mx in mx_records[:2]:  # Try first two MX records
            try:
                with smtplib.SMTP(timeout=self.timeout) as smtp:
                    # Test connection
                    conn = smtp.connect(str(mx), 25)

                    # EHLO/HELO check
                    try:
                        ehlo_response = smtp.ehlo()
                        if ehlo_response[0] != 250:
                            smtp.helo()
                    except Exception as e:
                        self.logger.debug(f"EHLO failed for {mx}: {str(e)}")
                        continue

                    # Email verification
                    try:
                        smtp.mail('')
                        code, message = smtp.rcpt(email)

                        if code == 250:
                            return True
                        elif code == 550:
                            continue  # Try next MX
                        elif code in [421, 450, 451, 452]:
                            # Temporary failures
                            return True if is_role else False

                    except smtplib.SMTPServerDisconnected:
                        if is_role:
                            return True  # Accept disconnection for role accounts
                        continue

                    except smtplib.SMTPResponseException as e:
                        if is_role and e.smtp_code in [521, 421, 450, 451, 452]:
                            return True
                        continue

            except Exception as e:
                self.logger.warning(f"SMTP verification failed for {mx}: {str(e)}")
                continue

        return False

    def _calculate_score(self, **kwargs) -> VerificationScore:
        """
        Calculate comprehensive email verification score

        Args:
            **kwargs: Score calculation parameters

        Returns:
            VerificationScore containing detailed score information
        """
        score = 100
        details = []

        # Core verification check
        if not kwargs['smtp_valid']:
            if kwargs['is_role']:
                score -= 30
                details.append("Role account with restricted access")
            else:
                score = 0
                details.append("Email does not exist")
                return VerificationScore(
                    score=score,
                    verdict="Failed",
                    details=details,
                    confidence="Very High",
                    verification_time=kwargs['verification_time']
                )

        # MX checks
        mx = kwargs['mx_check']
        if not mx.has_valid_mx:
            score -= 50
            details.append("No valid MX records")
        if not mx.port_open:
            score -= 10
            details.append("SMTP ports not accessible")
        if mx.has_catch_all:
            score -= 25
            details.append("Catch-all domain detected")

        # Security checks
        if kwargs['is_spam_trap']:
            score -= 100
            details.append("Spam trap detected")
        if kwargs['is_disposable']:
            score -= 40
            details.append("Disposable email detected")
        if kwargs['security_checks'].blacklisted:
            score -= 50
            details.append("Domain is blacklisted")

        # DNS security
        dns_sec = kwargs['dns_security']
        if not dns_sec.has_spf:
            score -= 10
            details.append("Missing SPF record")
        if not dns_sec.has_dmarc:
            score -= 15
            details.append("Missing DMARC record")
        if not dns_sec.has_dkim:
            score -= 15
            details.append("Missing DKIM setup")

        score = max(0, min(100, score))

        # Determine verdict
        verdict = self._get_verdict_with_catch_all(score) if mx.has_catch_all else (
            "Excellent" if score >= 90 else
            "Good" if score >= 70 else
            "Fair" if score >= 50 else
            "Poor" if score >= 30 else "Failed"
        )

        # Determine confidence
        confidence = (
            "Very High" if score >= 90 or score == 0 else
            "High" if score >= 70 else
            "Medium" if score >= 50 else "Low"
        )

        if mx.has_catch_all:
            confidence = "Medium" if confidence in ["Very High", "High"] else confidence

        return VerificationScore(
            score=score,
            verdict=verdict,
            details=details,
            confidence=confidence,
            verification_time=kwargs['verification_time']
        )

    def _adjust_score_for_catch_all(self, score: VerificationScore, is_catch_all: bool) -> VerificationScore:
        """
        Adjust verification score for catch-all domains

        Args:
            score: Original verification score
            is_catch_all: Whether domain is catch-all

        Returns:
            VerificationScore: Adjusted score
        """
        if is_catch_all:
            new_score = max(0, score.score - 25)
            new_details = score.details + ["Score reduced: Catch-all domain detected"]

            return VerificationScore(
                score=new_score,
                verdict=self._get_verdict_with_catch_all(new_score),
                details=new_details,
                confidence="Medium" if score.confidence == "High" else score.confidence,
                verification_time=score.verification_time
            )
        return score

    def _get_verdict_with_catch_all(self, score: int) -> str:
        """
        Get verdict text for catch-all domains

        Args:
            score: Verification score

        Returns:
            str: Verdict text
        """
        if score >= 85:
            return "Excellent (But Catch-all)"
        elif score >= 70:
            return "Good (But Catch-all)"
        elif score >= 50:
            return "Fair (But Catch-all)"
        else:
            return "Poor"

    def _is_role_account(self, local_part: str) -> bool:
        """
        Check if email is a role account

        Args:
            local_part: Local part of email address

        Returns:
            bool: Whether it's a role account
        """
        return local_part.lower() in self.role_accounts

    def _is_spam_trap(self, local_part: str, domain: str) -> bool:
        """
        Check if email matches spam trap patterns

        Args:
            local_part: Local part of email
            domain: Domain part of email

        Returns:
            bool: Whether email matches spam trap patterns
        """
        local_part = local_part.lower()
        domain = domain.lower()

        # Check prefixes
        if any(local_part.startswith(prefix) 
               for prefix in self.spam_trap_patterns['prefixes']):
            return True

        # Check regex patterns
        if any(re.match(pattern, local_part) 
               for pattern in self.spam_trap_patterns['patterns']):
            return True

        # Check for suspicious combinations
        if re.match(r'^[0-9a-f]{8,}$', local_part):  # Hash-like
            return True
        if re.match(r'^\d{10,}$', local_part):  # Long numbers
            return True
        if len(local_part) > 40:  # Excessively long
            return True

        return False

    def _get_syntax_checks(self, email: str) -> Dict[str, bool]:
        """
        Perform detailed syntax validation

        Args:
            email: Email address to validate

        Returns:
            Dict: Detailed syntax check results
        """
        try:
            local_part, domain = email.split('@')

            return {
                'local_length': len(local_part) <= VALIDATION_RULES['MAX_LOCAL_PART_LENGTH'],
                'total_length': len(email) <= VALIDATION_RULES['MAX_EMAIL_LENGTH'],
                'valid_local_chars': bool(re.match(
                    r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+$', 
                    local_part
                )),
                'valid_domain': bool(re.match(
                    r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$',
                    domain
                )),
                'no_consecutive_dots': '..' not in local_part,
                'no_leading_dots': not local_part.startswith('.'),
                'no_trailing_dots': not local_part.endswith('.'),
                'valid_domain_length': len(domain) <= VALIDATION_RULES['MAX_DOMAIN_LENGTH'],
                'valid_label_length': all(
                    len(label) <= 63 for label in domain.split('.')
                ),
                'valid_special_chars': all(
                    char in VALIDATION_RULES['ALLOWED_SPECIAL_CHARS'] 
                    for char in local_part 
                    if not char.isalnum()
                )
            }
        except Exception as e:
            self.logger.error(f"Syntax check error: {str(e)}", exc_info=True)
            return {
                'local_length': False,
                'total_length': False,
                'valid_local_chars': False,
                'valid_domain': False,
                'no_consecutive_dots': False,
                'no_leading_dots': False,
                'no_trailing_dots': False,
                'valid_domain_length': False,
                'valid_label_length': False,
                'valid_special_chars': False
            }

    def _generate_suggestions(self, smtp_check: bool, is_role: bool, 
                            is_spam_trap: bool, security_checks: SecurityChecks,
                            dns_security: DNSSecurityChecks,
                            mx_check: MailServerChecks) -> List[str]:
        """
        Generate helpful suggestions based on verification results

        Args:
            smtp_check: SMTP verification result
            is_role: Whether email is role account
            is_spam_trap: Whether email matches spam trap patterns
            security_checks: Security check results
            dns_security: DNS security check results
            mx_check: MX check results

        Returns:
            List[str]: List of suggestions
        """
        suggestions = []

        # Core validation suggestions
        if not smtp_check:
            if is_role:
                suggestions.append("Role account with restricted SMTP verification")
            else:
                suggestions.append("Email address does not exist or is not accepting emails")

        # Account type suggestions
        if is_role:
            suggestions.append("This appears to be a role account rather than a personal email")
        if is_spam_trap:
            suggestions.append("This email matches patterns commonly used for spam traps")

        # Security suggestions
        if security_checks.blacklisted:
            suggestions.append(
                f"Domain is blacklisted in {len(security_checks.blacklist_records)} "
                "reputation systems"
            )
        if not dns_security.has_dmarc:
            suggestions.append("Domain lacks DMARC protection - susceptible to spoofing")
        if not dns_security.has_spf and not dns_security.has_dkim:
            suggestions.append("Domain lacks both SPF and DKIM - vulnerable to email forgery")
        elif not dns_security.has_spf:
            suggestions.append("Domain lacks SPF protection")
        elif not dns_security.has_dkim:
            suggestions.append("Domain lacks DKIM protection")

        # MX suggestions
        if mx_check.has_catch_all:
            suggestions.append("Domain accepts all email addresses - specific validation not possible")
        if not mx_check.port_open:
            suggestions.append("SMTP ports are not accessible - may affect email delivery")

        return suggestions

    def _create_error_result(self, error_message: str) -> EmailVerificationResult:
        """
        Create standardized error result

        Args:
            error_message: Error message to include

        Returns:
            EmailVerificationResult: Error result
        """
        return EmailVerificationResult(
            is_valid=False,
            format_valid=False,
            syntax_checks={},
            mx_check=MailServerChecks(
                has_valid_mx=False,
                mx_records=[],
                mx_record_details=[],
                response_time=0.0,
                accepts_all=False,
                has_catch_all=False,
                port_open=False,
                smtp_provider="unknown"
            ),
            smtp_check=False,
            is_disposable=False,
            is_role_account=False,
            is_free_email=False,
            dns_security=DNSSecurityChecks(
                has_spf=False, spf_record="", spf_valid=False,
                has_dmarc=False, dmarc_record="", dmarc_valid=False,
                has_dkim=False, dkim_record="", dkim_valid=False,
                mx_records=[], mx_valid=False
            ),
            security_checks=SecurityChecks(
                blacklisted=False,
                blacklist_records=[],
                spam_score=0,
                abuse_score=0,
                domain_reputation="Unknown"
            ),
            suggestions=[error_message],
            score=VerificationScore(
                score=0,
                verdict="Error",
                details=[error_message],
                confidence="Very Low",
                verification_time=0.0
            ),
            error_message=error_message
        )