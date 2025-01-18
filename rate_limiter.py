from typing import Dict, Optional, Tuple
import time
from collections import defaultdict
from threading import Lock
import logging
from dataclasses import dataclass
from config import RATE_LIMITS

@dataclass
class RateLimit:
    """Rate limit configuration"""
    requests: int
    window: int

@dataclass
class RateLimitState:
    """Current state of rate limiting"""
    count: int
    window_start: float

class RateLimiter:
    """Thread-safe rate limiter with support for multiple limit types"""

    def __init__(self):
        # Initialize logger
        self.logger = logging.getLogger('rate_limiter')

        # Initialize rate limits from config
        self.default_limits = {
            'global': RateLimit(**RATE_LIMITS['GLOBAL']),
            'domain': RateLimit(**RATE_LIMITS['DOMAIN']),
            'ip': RateLimit(**RATE_LIMITS['IP']),
            'domain_ip': RateLimit(**RATE_LIMITS['DOMAIN_IP'])
        }

        # Rate limit states
        self._global_state = RateLimitState(0, time.time())
        self._domain_states: Dict[str, RateLimitState] = defaultdict(
            lambda: RateLimitState(0, time.time())
        )
        self._ip_states: Dict[str, RateLimitState] = defaultdict(
            lambda: RateLimitState(0, time.time())
        )
        self._domain_ip_states: Dict[str, RateLimitState] = defaultdict(
            lambda: RateLimitState(0, time.time())
        )

        # Thread safety
        self._lock = Lock()

        self.logger.info("Rate limiter initialized with configuration: %s", RATE_LIMITS)

    def _check_limit(self, state: RateLimitState, limit: RateLimit, now: float) -> Tuple[bool, float]:
        """
        Check if request is within rate limit

        Args:
            state: Current state of the rate limit
            limit: Rate limit configuration
            now: Current timestamp

        Returns:
            Tuple containing:
            - bool: Whether request is allowed
            - float: Seconds until rate limit resets
        """
        # Reset counter if window has expired
        if now - state.window_start >= limit.window:
            state.count = 0
            state.window_start = now

        # Check if limit is exceeded
        if state.count >= limit.requests:
            retry_after = state.window_start + limit.window - now
            return False, max(0, retry_after)

        return True, 0

    def check_rate_limit(self, domain: str, ip: str) -> Tuple[bool, str, float]:
        """
        Check if request is allowed under rate limits

        Args:
            domain: Domain being validated
            ip: IP address making request

        Returns:
            Tuple containing:
            - bool: Whether request is allowed
            - str: Type of limit exceeded (if any)
            - float: Seconds until rate limit resets
        """
        try:
            with self._lock:
                now = time.time()

                # Normalize inputs
                domain = domain.lower().strip()
                ip = ip.strip()

                # Check global limit
                allowed, retry_after = self._check_limit(
                    self._global_state,
                    self.default_limits['global'],
                    now
                )
                if not allowed:
                    return False, 'global', retry_after

                # Check domain limit
                allowed, retry_after = self._check_limit(
                    self._domain_states[domain],
                    self.default_limits['domain'],
                    now
                )
                if not allowed:
                    return False, 'domain', retry_after

                # Check IP limit
                allowed, retry_after = self._check_limit(
                    self._ip_states[ip],
                    self.default_limits['ip'],
                    now
                )
                if not allowed:
                    return False, 'ip', retry_after

                # Check domain+IP limit
                domain_ip_key = f"{domain}:{ip}"
                allowed, retry_after = self._check_limit(
                    self._domain_ip_states[domain_ip_key],
                    self.default_limits['domain_ip'],
                    now
                )
                if not allowed:
                    return False, 'domain_ip', retry_after

                # Increment counters if all checks pass
                self._global_state.count += 1
                self._domain_states[domain].count += 1
                self._ip_states[ip].count += 1
                self._domain_ip_states[domain_ip_key].count += 1

                return True, '', 0

        except Exception as e:
            self.logger.error(f"Error checking rate limit: {str(e)}", exc_info=True)
            # On error, allow the request but log the issue
            return True, '', 0

    def get_remaining_quota(self, domain: str, ip: str) -> Dict[str, Dict[str, int]]:
        """
        Get remaining quota for all limit types

        Args:
            domain: Domain to check
            ip: IP address to check

        Returns:
            Dict containing remaining quota information for each limit type
        """
        try:
            with self._lock:
                now = time.time()
                quotas = {}

                # Normalize inputs
                domain = domain.lower().strip()
                ip = ip.strip()
                domain_ip_key = f"{domain}:{ip}"

                # Check each limit type
                states = {
                    'global': self._global_state,
                    'domain': self._domain_states[domain],
                    'ip': self._ip_states[ip],
                    'domain_ip': self._domain_ip_states[domain_ip_key]
                }

                for limit_type, state in states.items():
                    limit = self.default_limits[limit_type]

                    # Reset if window expired
                    if now - state.window_start >= limit.window:
                        remaining = limit.requests
                        window_remaining = limit.window
                    else:
                        remaining = max(0, limit.requests - state.count)
                        window_remaining = max(0, state.window_start + limit.window - now)

                    quotas[limit_type] = {
                        'remaining_requests': remaining,
                        'window_remaining': int(window_remaining),
                        'limit': limit.requests,
                        'window': limit.window
                    }

                return quotas

        except Exception as e:
            self.logger.error(f"Error getting quota: {str(e)}", exc_info=True)
            # Return empty quotas on error
            return {}

    def clear_expired(self) -> None:
        """Clear expired rate limit states to prevent memory growth"""
        try:
            with self._lock:
                now = time.time()

                # Clear expired domain states
                for domain in list(self._domain_states.keys()):
                    state = self._domain_states[domain]
                    if now - state.window_start >= self.default_limits['domain'].window:
                        del self._domain_states[domain]

                # Clear expired IP states
                for ip in list(self._ip_states.keys()):
                    state = self._ip_states[ip]
                    if now - state.window_start >= self.default_limits['ip'].window:
                        del self._ip_states[ip]

                # Clear expired domain+IP states
                for key in list(self._domain_ip_states.keys()):
                    state = self._domain_ip_states[key]
                    if now - state.window_start >= self.default_limits['domain_ip'].window:
                        del self._domain_ip_states[key]

                self.logger.info("Cleared expired rate limit states")

        except Exception as e:
            self.logger.error(f"Error clearing expired states: {str(e)}", exc_info=True)

# Create global rate limiter instance
rate_limiter = RateLimiter()