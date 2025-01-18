from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple
import dns.resolver
import re
import socket
import smtplib
import time
import logging
import traceback
from dns_cache import cached_dns_lookup, DNSCache
from smtp_pool import verify_email_with_pool, smtp_pool
from error_handler import (
    handle_dns_error, handle_smtp_error, log_error,
    DNSError, SMTPError, ValidationError
)
from catch_all_detector import (
    AdvancedCatchAllDetector,
    CatchAllResult
)
from config import (
    SMTP_CONFIG,
    DNS_CONFIG,
    ROLE_ACCOUNTS,
    DISPOSABLE_DOMAINS,
    FREE_EMAIL_PROVIDERS,
    VALIDATION_RULES,
    ERROR_MESSAGES
)

@dataclass
class QuickVerificationResult:
    """Result of quick email verification"""
    is_valid: bool
    format_valid: bool
    domain_valid: bool
    mailbox_exists: bool
    is_role_account: bool
    is_disposable: bool
    is_catch_all: bool
    is_free_email: bool
    is_honeypot: bool
    has_valid_syntax: bool
    has_parked_mx: bool
    has_valid_smtp: bool
    verification_time: float
    status: str
    details: List[str]
    suggestions: List[str]
    mx_info: Optional[Dict[str, Any]] = None
    catch_all_details: Optional[Dict[str, Any]] = None

class QuickEmailVerifier:
    """Production-ready quick email verification with comprehensive checks"""

    def __init__(self):
        # Initialize logger with proper configuration
        self.logger = logging.getLogger('quick_email_verifier')
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        # Initialize DNS cache
        self.dns_cache = DNSCache()
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = DNS_CONFIG['NAMESERVERS']
        self.resolver.timeout = DNS_CONFIG['TIMEOUT']
        self.resolver.lifetime = DNS_CONFIG['LIFETIME']

        # Initialize SMTP configuration
        self.timeout = SMTP_CONFIG['TIMEOUT']
        self.retry_count = SMTP_CONFIG['RETRY_COUNT']
        self.retry_delay = SMTP_CONFIG['RETRY_DELAY']

        # Load configurations from config.py
        self.role_accounts = ROLE_ACCOUNTS
        self.disposable_domains = DISPOSABLE_DOMAINS
        self.free_email_providers = FREE_EMAIL_PROVIDERS

        # Initialize honeypot patterns
        self._init_honeypot_patterns()

        self.logger.info("QuickEmailVerifier initialized successfully with production configuration")

    def _init_honeypot_patterns(self):
        """Initialize comprehensive honeypot detection patterns"""
        self.honeypot_patterns = [
            # Common trap patterns
            r'^spam\.', r'^trap\.', r'^honey\.', r'^filter\.',
            r'^block\.', r'^catch\.', r'^bounce\.',

            # Role-based patterns
            r'^no-reply\.', r'^noreply\.', r'^postmaster\.',
            r'^admin\.', r'^administrator\.', r'^hostmaster\.',
            r'^webmaster\.', r'^abuse\.', r'^security\.',

            # Testing patterns
            r'^test\.', r'^verify\.', r'^validation\.',
            r'^temp\.', r'^temporary\.',

            # Numeric and hash patterns
            r'[0-9a-f]{8,}',           # Hex strings
            r'\d{10,}',                # Long numbers
            r'^[a-z0-9]{20,}@',        # Long random strings

            # Special patterns
            r'.*\.{2,}.*@',            # Multiple dots
            r'.*_{2,}.*@',             # Multiple underscores
            r'.*-{2,}.*@',             # Multiple hyphens

            # Additional suspicious patterns
            r'^delete\.', r'^removed\.',
            r'^defunct\.', r'^expired\.',
            r'^blacklist\.', r'^blocked\.',
            r'^[0-9a-f]{32}',          # MD5-like hashes
            r'^[0-9a-f]{40}',          # SHA1-like hashes
        ]

    def verify_email(self, email: str) -> QuickVerificationResult:
        """
        Perform quick but comprehensive email verification

        Args:
            email: Email address to verify

        Returns:
            QuickVerificationResult containing verification results
        """
        try:
            start_time = time.time()
            details = []
            suggestions = []

            # Enhanced format and syntax validation
            try:
                syntax_valid = self._validate_syntax(email)
                format_valid = syntax_valid['is_valid']

                if not format_valid:
                    raise ValidationError(
                        'INVALID_FORMAT',
                        ERROR_MESSAGES['INVALID_EMAIL'],
                        detail=str(syntax_valid['details'])
                    )
            except ValidationError as e:
                log_error(e.error, self.logger)
                return self._create_error_result(
                    [e.error.message],
                    [e.error.suggestion],
                    time.time() - start_time
                )

            try:
                local_part, domain = email.lower().split('@')
            except ValueError:
                error = ValidationError(
                    'INVALID_EMAIL',
                    ERROR_MESSAGES['INVALID_EMAIL'],
                    'Email must contain exactly one @ symbol'
                )
                log_error(error.error, self.logger)
                return self._create_error_result(
                    [error.error.message],
                    [error.error.suggestion],
                    time.time() - start_time
                )

            # Domain validation with DNS cache
            try:
                domain_check = self._validate_domain_enhanced(domain)
            except Exception as e:
                error = handle_dns_error(e)
                log_error(error, self.logger)
                return self._create_error_result(
                    [error.message],
                    [error.suggestion],
                    time.time() - start_time
                )

            if not domain_check['is_valid']:
                details.extend(domain_check['details'])
                suggestions.extend(domain_check['suggestions'])
                return self._create_error_result(
                    details,
                    suggestions,
                    time.time() - start_time
                )

            # SMTP verification using connection pool
            try:
                smtp_check = self._verify_smtp_enhanced(email, domain_check['mx_records'])
            except Exception as e:
                error = handle_smtp_error(e)
                log_error(error, self.logger)
                if error.error_code in ['RATE_LIMIT', 'SMTP_TIMEOUT']:
                    # For temporary errors, return a special result
                    return QuickVerificationResult(
                        is_valid=False,
                        format_valid=True,
                        domain_valid=True,
                        mailbox_exists=None,  # Unknown due to temporary error
                        is_role_account=local_part in self.role_accounts,
                        is_disposable=domain in self.disposable_domains,
                        is_catch_all=False,
                        is_free_email=domain in self.free_email_providers,
                        is_honeypot=self._check_honeypot(local_part, domain),
                        has_valid_syntax=True,
                        has_parked_mx=domain_check['is_parked'],
                        has_valid_smtp=None,  # Unknown due to temporary error
                        verification_time=time.time() - start_time,
                        status="Temporary Failure - Retry Later",
                        details=[error.message],
                        suggestions=[error.suggestion],
                        mx_info={
                            'has_mx': bool(domain_check['mx_records']),
                            'records': domain_check['mx_records'],
                            'is_parked': domain_check['is_parked']
                        },
                        catch_all_details=None
                    )

                return self._create_error_result(
                    [error.message],
                    [error.suggestion],
                    time.time() - start_time
                )

            if not smtp_check['is_valid']:
                details.extend(smtp_check['details'])
                suggestions.extend(smtp_check['suggestions'])

            # Advanced catch-all detection
            detector = AdvancedCatchAllDetector()
            try:
                detector_result = detector.detect_catch_all(
                    domain,
                    domain_check['mx_records'],
                    self._verify_smtp_enhanced
                )
                is_catch_all = detector_result.is_catch_all
                catch_all_details = {
                    'is_catch_all': detector_result.is_catch_all,
                    'confidence': detector_result.confidence,
                    'detection_method': detector_result.detection_method,
                    'server_behavior': detector_result.server_behavior,
                    'verification_time': detector_result.verification_time
                }
            except Exception as e:
                self.logger.error(f"Catch-all detection error: {str(e)}")
                is_catch_all = False
                catch_all_details = None

            # Additional checks
            is_role = local_part in self.role_accounts
            is_disposable = domain in self.disposable_domains
            is_free_email = domain in self.free_email_providers
            is_honeypot = self._check_honeypot(local_part, domain)

            # Prepare mx_info
            mx_info = {
                'has_mx': bool(domain_check['mx_records']),
                'records': domain_check['mx_records'],
                'is_parked': domain_check['is_parked'],
                'response_time': smtp_check.get('response_time', 0)
            }

            # Build final status and details
            status = self._determine_status(
                smtp_check['is_valid'],
                is_disposable,
                is_catch_all,
                is_honeypot,
                domain_check['is_parked']
            )

            return QuickVerificationResult(
                is_valid=smtp_check['is_valid'] and not is_honeypot and not domain_check['is_parked'],
                format_valid=format_valid,
                domain_valid=domain_check['is_valid'],
                mailbox_exists=smtp_check['is_valid'],
                is_role_account=is_role,
                is_disposable=is_disposable,
                is_catch_all=is_catch_all,
                is_free_email=is_free_email,
                is_honeypot=is_honeypot,
                has_valid_syntax=True,
                has_parked_mx=domain_check['is_parked'],
                has_valid_smtp=smtp_check['is_valid'],
                verification_time=time.time() - start_time,
                status=status,
                details=details,
                suggestions=suggestions,
                mx_info=mx_info,
                catch_all_details=catch_all_details
            )

        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}\n{traceback.format_exc()}")
            return self._create_error_result(
                ["An unexpected error occurred"],
                ["Please try again later or contact support"],
                time.time() - start_time
            )

    def _validate_syntax(self, email: str) -> dict:
        """
        Perform comprehensive syntax validation

        Args:
            email: Email address to validate

        Returns:
            Dict containing validation results and details
        """
        result = {'is_valid': True, 'details': [], 'suggestions': []}

        # Length checks
        if len(email) > VALIDATION_RULES['MAX_EMAIL_LENGTH']:
            result['is_valid'] = False
            result['details'].append(f"Email exceeds maximum length of {VALIDATION_RULES['MAX_EMAIL_LENGTH']} characters")
            result['suggestions'].append("Shorten the email address")

        try:
            local_part, domain = email.split('@')
        except ValueError:
            result['is_valid'] = False
            result['details'].append("Invalid email format")
            result['suggestions'].append("Email must contain exactly one @ symbol")
            return result

        # Local part checks
        if len(local_part) > VALIDATION_RULES['MAX_LOCAL_PART_LENGTH']:
            result['is_valid'] = False
            result['details'].append(f"Local part exceeds maximum length of {VALIDATION_RULES['MAX_LOCAL_PART_LENGTH']} characters")
            result['suggestions'].append("Shorten the local part of the email")

        if local_part.startswith('.') or local_part.endswith('.'):
            result['is_valid'] = False
            result['details'].append("Local part cannot start or end with a dot")
            result['suggestions'].append("Remove leading/trailing dots from local part")

        if '..' in local_part:
            result['is_valid'] = False
            result['details'].append("Local part contains consecutive dots")
            result['suggestions'].append("Remove consecutive dots from local part")

        # Check for restricted characters
        if any(char in VALIDATION_RULES['RESTRICTED_LOCAL_CHARS'] for char in local_part):
            result['is_valid'] = False
            result['details'].append("Local part contains restricted characters")
            result['suggestions'].append("Remove special characters from local part")

        # Domain checks
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9](\.[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])*\.[a-zA-Z]{2,}$', domain):
            result['is_valid'] = False
            result['details'].append("Invalid domain format")
            result['suggestions'].append("Check domain format and TLD")

        if len(domain) > VALIDATION_RULES['MAX_DOMAIN_LENGTH']:
            result['is_valid'] = False
            result['details'].append(f"Domain exceeds maximum length of {VALIDATION_RULES['MAX_DOMAIN_LENGTH']} characters")
            result['suggestions'].append("Domain name is too long")

        return result

    @cached_dns_lookup
    def _validate_domain_enhanced(self, domain: str) -> dict:
        """
        Perform enhanced domain validation with MX record checks

        Args:
            domain: Domain to validate

        Returns:
            Dict containing validation results
        """
        result = {
            'is_valid': False,
            'is_parked': False,
            'mx_records': [],
            'details': [],
            'suggestions': []
        }

        # Use DNS cache for lookup
        lookup_result = self.dns_cache.lookup(domain, 'MX')

        if 'error' in lookup_result:
            if lookup_result['error'] == 'NXDOMAIN':
                result['details'].append("Domain does not exist")
                result['suggestions'].append("Check if the domain name is correct")
                self.logger.warning(f"Domain does not exist: {domain}")
            elif lookup_result['error'] == 'NoAnswer':
                result['details'].append("Domain exists but has no MX records")
                result['suggestions'].append("Domain is not configured for email")
                self.logger.warning(f"No MX records for domain: {domain}")
            else:
                result['details'].append(f"DNS lookup error: {lookup_result['error']}")
                result['suggestions'].append("Unable to verify domain. Please try again later")
                self.logger.error(f"DNS lookup error for {domain}: {lookup_result['error']}")
            return result

        # Process MX records
        mx_list = [record['exchange'].lower() for record in lookup_result['records']]
        result['mx_records'] = mx_list

        # Check for parked MX records
        parked_patterns = [
            'parkingcrew.net',
            'sedoparking.com',
            'domainparking.com',
            'pending-setup.com',
            'hostinger.com',
            'parking-page.com',
            'domain-starter.com',
            'parked.namecheap.com'
        ]

        if any(pattern in mx for mx in mx_list for pattern in parked_patterns):
            result['is_parked'] = True
            result['details'].append("Domain has parked mail exchangers")
            result['suggestions'].append("This domain's email service is not properly configured")
            self.logger.info(f"Parked domain detected: {domain}")
        else:
            result['is_valid'] = True

        return result

    def _verify_smtp_enhanced(self, email: str, mx_records: List[str]) -> dict:
        """
        Verify email via SMTP using connection pool

        Args:
            email: Email address to verify
            mx_records: List of MX records to try

        Returns:
            Dict containing verification results
        """
        result = {
            'is_valid': False,
            'details': [],
            'suggestions': [],
            'response_time': 0,
            'mx_info': {
                'has_mx': bool(mx_records),
                'records': mx_records,
                'ports_open': [],
                'response_codes': []
            }
        }

        if not mx_records:
            result['details'].append("No MX records found")
            result['suggestions'].append("Verify domain DNS configuration")
            return result

        start_time = time.time()
        # Use SMTP pool for verification
        is_valid, message = verify_email_with_pool(email, mx_records)
        result['response_time'] = time.time() - start_time
        result['is_valid'] = is_valid

        if is_valid:
            if "temporarily" in message.lower():
                result['details'].append("Server responded with temporary error")
                result['suggestions'].append("The mail server is experiencing temporary issues")
            else:
                result['details'].append("Email address verified")
        else:
            result['details'].append(message)
            result['suggestions'].append("Check if the email address is correct")

        # For role accounts, treat certain responses as valid
        if not is_valid and email.split('@')[0] in self.role_accounts:
            result['is_valid'] = True
            result['details'].append("Common role account with valid mail servers")
            result['suggestions'].append("Role accounts often have restricted SMTP verification")

        return result

    def _check_honeypot(self, local_part: str, domain: str) -> bool:
        """
        Check if email matches known spam trap patterns

        Args:
            local_part: Local part of email
            domain: Domain part of email

        Returns:
            bool: Whether email matches honeypot patterns
        """
        # Check local part against patterns
        if any(re.match(pattern, local_part) for pattern in self.honeypot_patterns):
            return True

        # Check for suspicious number patterns
        if re.match(r'.*(\d{8,}|[a-f0-9]{8,}).*', local_part):
            return True

        # Check for random-looking strings
        if re.match(r'^[a-z0-9]{12,}$', local_part):
            return True

        # Check for suspicious combinations
        if any([
            re.match(r'^(test|verify|validate)\d+', local_part),
            re.match(r'^(spam|trap|honey).*\d{4,}', local_part),
            re.match(r'.*\.(test|spam|trap)\d*$', local_part),
            re.match(r'^[a-f0-9]{32}@', local_part),  # MD5-like hash
            re.match(r'^[a-f0-9]{40}@', local_part),  # SHA1-like hash
            re.match(r'.*\+(spam|test|trap)@', local_part),  # Plus addressing
        ]):
            return True

        return False

    def _determine_status(self, smtp_valid: bool, is_disposable: bool, 
                         is_catch_all: bool, is_honeypot: bool, is_parked: bool) -> str:
        """
        Determine final verification status

        Args:
            smtp_valid: Whether SMTP verification passed
            is_disposable: Whether domain is disposable
            is_catch_all: Whether domain is catch-all
            is_honeypot: Whether email matches honeypot patterns
            is_parked: Whether domain is parked

        Returns:
            str: Status message
        """
        if is_honeypot:
            return "Invalid - Potential Spam Trap"
        if is_parked:
            return "Invalid - Parked Domain"
        if not smtp_valid:
            return "Invalid - Do Not Send"
        if is_disposable:
            return "Valid - But Disposable"
        if is_catch_all:
            return "Valid - But Catch-all (Use Caution)"
        return "Valid - OK to Send"

    def _create_error_result(self, details: List[str], suggestions: List[str], 
                           verification_time: float) -> QuickVerificationResult:
        """
        Create standardized error result

        Args:
            details: List of error details
            suggestions: List of suggestions
            verification_time: Time taken for verification

        Returns:
            QuickVerificationResult: Error result
        """
        return QuickVerificationResult(
            is_valid=False,
            format_valid=False,
            domain_valid=False,
            mailbox_exists=False,
            is_role_account=False,
            is_disposable=False,
            is_catch_all=False,
            is_free_email=False,
            is_honeypot=False,
            has_valid_syntax=False,
            has_parked_mx=False,
            has_valid_smtp=False,
            verification_time=verification_time,
            status="Invalid - Error",
            details=details,
            suggestions=suggestions,
            mx_info=None,
            catch_all_details=None
        )

    def _check_catch_all(self, domain: str, mx_records: List[str]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Perform catch-all detection with caching

        Args:
            domain: Domain to check
            mx_records: List of MX records

        Returns:
            Tuple containing:
            - bool: Whether domain is catch-all
            - dict: Catch-all detection details
        """
        detector = AdvancedCatchAllDetector()
        try:
            result = detector.detect_catch_all(
                domain,
                mx_records,
                self._verify_smtp_enhanced
            )

            # Log detailed results for analysis
            self.logger.info(
                f"Catch-all detection for {domain}:\n"
                f"Result: {result.is_catch_all}\n"
                f"Confidence: {result.confidence}\n"
                f"Method: {result.detection_method}\n"
                f"Behavior: {result.server_behavior}\n"
                f"Time: {result.verification_time:.2f}s"
            )

            return result.is_catch_all, {
                'is_catch_all': result.is_catch_all,
                'confidence': result.confidence,
                'detection_method': result.detection_method,
                'server_behavior': result.server_behavior,
                'verification_time': result.verification_time,
                'response_patterns': result.response_patterns
            }
        except Exception as e:
            self.logger.error(f"Catch-all detection error: {str(e)}")
            return False, None

    def bulk_verify(self, emails: List[str], max_workers: int = 10) -> Dict[str, QuickVerificationResult]:
        """
        Perform bulk email verification

        Args:
            emails: List of email addresses to verify
            max_workers: Maximum number of concurrent workers

        Returns:
            Dict mapping emails to their verification results
        """
        from concurrent.futures import ThreadPoolExecutor
        results = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_email = {
                executor.submit(self.verify_email, email): email 
                for email in emails
            }

            for future in future_to_email:
                email = future_to_email[future]
                try:
                    results[email] = future.result()
                except Exception as e:
                    self.logger.error(f"Error verifying {email}: {str(e)}")
                    results[email] = self._create_error_result(
                        ["Verification failed"],
                        ["Please try again later"],
                        0.0
                    )

        return results