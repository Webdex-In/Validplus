from typing import Optional, Dict, Any
import logging
from dataclasses import dataclass
from datetime import datetime
import traceback
import dns.resolver
import smtplib
import socket

@dataclass
class VerificationError:
    """Structured error information for email verification"""
    error_code: str
    message: str
    detail: str
    timestamp: datetime
    retry_possible: bool
    error_type: str
    suggestion: str

class EmailVerificationError(Exception):
    """Base exception class for email verification errors"""
    def __init__(self, error_code: str, message: str, detail: str = "", retry_possible: bool = True):
        self.error = VerificationError(
            error_code=error_code,
            message=message,
            detail=detail,
            timestamp=datetime.now(),
            retry_possible=retry_possible,
            error_type=self.__class__.__name__,
            suggestion=self._get_suggestion(error_code)
        )
        super().__init__(message)

    def _get_suggestion(self, error_code: str) -> str:
        suggestions = {
            'DNS_LOOKUP_ERROR': 'Check domain DNS configuration or try again later',
            'SMTP_CONNECTION_ERROR': 'Mail server might be temporarily unavailable',
            'SMTP_TIMEOUT': 'Try again later or verify server connectivity',
            'INVALID_EMAIL': 'Please check the email format',
            'SERVER_REJECT': 'Verify email address exists',
            'RATE_LIMIT': 'Reduce verification frequency or wait before retrying',
            'BLOCKED': 'IP might be blocked, try later or use different IP',
            'MAILBOX_FULL': 'Target mailbox is full',
            'ROLE_ACCOUNT': 'Role account detected, verification might be restricted',
            'CATCH_ALL': 'Domain accepts all emails, specific verification not possible'
        }
        return suggestions.get(error_code, 'Please try again or contact support')

class DNSError(EmailVerificationError):
    """DNS related errors"""
    pass

class SMTPError(EmailVerificationError):
    """SMTP related errors"""
    pass

class ValidationError(EmailVerificationError):
    """Input validation errors"""
    pass

def handle_dns_error(e: Exception) -> VerificationError:
    """Handle DNS resolution errors"""
    if isinstance(e, dns.resolver.NXDOMAIN):
        return VerificationError(
            error_code='DNS_LOOKUP_ERROR',
            message='Domain does not exist',
            detail=str(e),
            timestamp=datetime.now(),
            retry_possible=False,
            error_type='DNSError',
            suggestion='Verify domain name is correct'
        )
    elif isinstance(e, dns.resolver.NoAnswer):
        return VerificationError(
            error_code='DNS_LOOKUP_ERROR',
            message='No MX records found',
            detail=str(e),
            timestamp=datetime.now(),
            retry_possible=False,
            error_type='DNSError',
            suggestion='Domain is not configured for email'
        )
    elif isinstance(e, dns.resolver.Timeout):
        return VerificationError(
            error_code='DNS_TIMEOUT',
            message='DNS lookup timeout',
            detail=str(e),
            timestamp=datetime.now(),
            retry_possible=True,
            error_type='DNSError',
            suggestion='Try again later'
        )
    else:
        return VerificationError(
            error_code='DNS_ERROR',
            message='DNS error occurred',
            detail=str(e),
            timestamp=datetime.now(),
            retry_possible=True,
            error_type='DNSError',
            suggestion='Check DNS configuration'
        )

def handle_smtp_error(e: Exception) -> VerificationError:
    """Handle SMTP connection and verification errors"""
    if isinstance(e, smtplib.SMTPServerDisconnected):
        return VerificationError(
            error_code='SMTP_CONNECTION_ERROR',
            message='Server disconnected',
            detail=str(e),
            timestamp=datetime.now(),
            retry_possible=True,
            error_type='SMTPError',
            suggestion='Server might be protecting against verification'
        )
    elif isinstance(e, smtplib.SMTPResponseException):
        error_info = {
            550: ('SERVER_REJECT', 'Mailbox does not exist', False),
            551: ('SERVER_REJECT', 'User not local', False),
            552: ('MAILBOX_FULL', 'Mailbox full', True),
            450: ('RATE_LIMIT', 'Too many requests', True),
            421: ('RATE_LIMIT', 'Service not available', True),
        }
        code_info = error_info.get(e.smtp_code, ('SMTP_ERROR', str(e.smtp_error), True))
        return VerificationError(
            error_code=code_info[0],
            message=code_info[1],
            detail=f"SMTP Code: {e.smtp_code}, Message: {e.smtp_error}",
            timestamp=datetime.now(),
            retry_possible=code_info[2],
            error_type='SMTPError',
            suggestion=code_info[1]
        )
    elif isinstance(e, socket.timeout):
        return VerificationError(
            error_code='SMTP_TIMEOUT',
            message='Connection timeout',
            detail=str(e),
            timestamp=datetime.now(),
            retry_possible=True,
            error_type='SMTPError',
            suggestion='Server might be slow or blocking verification'
        )
    else:
        return VerificationError(
            error_code='SMTP_ERROR',
            message='SMTP error occurred',
            detail=str(e),
            timestamp=datetime.now(),
            retry_possible=True,
            error_type='SMTPError',
            suggestion='Try again later'
        )

def log_error(error: VerificationError, logger: Optional[logging.Logger] = None) -> None:
    """Log error with appropriate severity"""
    if logger is None:
        logger = logging.getLogger('email_verifier')

    log_message = (
        f"Error: {error.error_code}\n"
        f"Message: {error.message}\n"
        f"Detail: {error.detail}\n"
        f"Timestamp: {error.timestamp}\n"
        f"Type: {error.error_type}\n"
        f"Retry Possible: {error.retry_possible}\n"
        f"Suggestion: {error.suggestion}"
    )

    if error.retry_possible:
        logger.warning(log_message)
    else:
        logger.error(log_message)

def format_error_response(error: VerificationError) -> Dict[str, Any]:
    """Format error for API response"""
    return {
        'error': {
            'code': error.error_code,
            'message': error.message,
            'type': error.error_type,
            'retry_possible': error.retry_possible,
            'suggestion': error.suggestion,
            'timestamp': error.timestamp.isoformat()
        }
    }