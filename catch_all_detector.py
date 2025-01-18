from typing import List, Dict, Tuple, Optional
import random
import string
import time
from dataclasses import dataclass
import logging
import hashlib
from collections import defaultdict
import re

@dataclass
class CatchAllResult:
    """Detailed catch-all detection result"""
    is_catch_all: bool
    confidence: float  # 0-1
    detection_method: str
    response_patterns: Dict[str, bool]
    server_behavior: str
    verified_patterns: List[str]
    verification_time: float
    smtp_responses: Dict[str, List[int]]

class AdvancedCatchAllDetector:
    def __init__(self):
        self.logger = logging.getLogger('catch_all_detector')
        self._init_test_patterns()
        self._response_cache = defaultdict(dict)

    def _init_test_patterns(self):
        """Initialize sophisticated test patterns"""
        self.test_patterns = {
            'standard': [
                self._generate_standard_pattern,
                self._generate_uuid_pattern,
                self._generate_timestamp_pattern
            ],
            'format_specific': [
                self._generate_role_like_pattern,
                self._generate_service_like_pattern,
                self._generate_person_like_pattern
            ],
            'edge_cases': [
                self._generate_special_char_pattern,
                self._generate_long_pattern,
                self._generate_numeric_pattern
            ]
        }

        # Known patterns that often bypass catch-all detection
        self.bypass_patterns = [
            'postmaster', 'abuse', 'spam', 'admin', 'webmaster',
            'hostmaster', 'administrator', 'root', 'support', 'noreply'
        ]

        # Patterns that often indicate true catch-all
        self.indicator_patterns = [
            r'^test[\d]*@',
            r'^verify[\d]*@',
            r'^check[\d]*@',
            r'^invalid[\d]*@'
        ]

    def _generate_standard_pattern(self, domain: str) -> str:
        """Generate random but realistic-looking email pattern"""
        random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        hash_suffix = hashlib.md5(str(time.time()).encode()).hexdigest()[:6]
        return f"verify.{random_string}.{hash_suffix}@{domain}"

    def _generate_uuid_pattern(self, domain: str) -> str:
        """Generate UUID-based pattern"""
        import uuid
        return f"check.{str(uuid.uuid4())[:12]}@{domain}"

    def _generate_timestamp_pattern(self, domain: str) -> str:
        """Generate timestamp-based pattern with noise"""
        timestamp = int(time.time())
        noise = ''.join(random.choices(string.ascii_lowercase, k=4))
        return f"test.{timestamp}.{noise}@{domain}"

    def _generate_role_like_pattern(self, domain: str) -> str:
        """Generate patterns that look like role accounts"""
        roles = ['support', 'info', 'contact', 'sales', 'help']
        suffix = ''.join(random.choices(string.digits, k=4))
        role = random.choice(roles)
        return f"{role}.nonexistent.{suffix}@{domain}"

    def _generate_service_like_pattern(self, domain: str) -> str:
        """Generate patterns that look like service accounts"""
        services = ['newsletter', 'notification', 'alert', 'system', 'monitor']
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        service = random.choice(services)
        return f"{service}.{suffix}@{domain}"

    def _generate_person_like_pattern(self, domain: str) -> str:
        """Generate patterns that look like personal emails"""
        first_names = ['john', 'jane', 'bob', 'alice', 'david']
        last_names = ['smith', 'doe', 'jones', 'brown', 'wilson']
        first = random.choice(first_names)
        last = random.choice(last_names)
        suffix = ''.join(random.choices(string.digits, k=4))
        return f"{first}.{last}.{suffix}@{domain}"

    def _generate_special_char_pattern(self, domain: str) -> str:
        """Generate patterns with special characters"""
        chars = '.-_+'
        base = ''.join(random.choices(string.ascii_lowercase, k=8))
        special = random.choice(chars)
        return f"test{special}{base}@{domain}"

    def _generate_long_pattern(self, domain: str) -> str:
        """Generate very long local-part"""
        return f"{'x' * 50}@{domain}"

    def _generate_numeric_pattern(self, domain: str) -> str:
        """Generate numeric patterns"""
        nums = ''.join(random.choices(string.digits, k=10))
        return f"test.{nums}@{domain}"

    def detect_catch_all(self, domain: str, mx_records: List[str], smtp_verifier) -> CatchAllResult:
        """
        Advanced catch-all detection with multiple strategies

        Args:
            domain: Domain to test
            mx_records: List of MX records
            smtp_verifier: Function to verify email via SMTP
        """
        start_time = time.time()
        responses = defaultdict(list)
        verified_patterns = []

        # Test special patterns first
        bypass_results = self._test_bypass_patterns(domain, mx_records, smtp_verifier, responses)
        if bypass_results is not None:
            return bypass_results

        # Test patterns in stages
        test_results = {
            'standard': self._test_pattern_group('standard', domain, mx_records, smtp_verifier, responses),
            'format': self._test_pattern_group('format_specific', domain, mx_records, smtp_verifier, responses),
            'edge': self._test_pattern_group('edge_cases', domain, mx_records, smtp_verifier, responses)
        }

        # Analyze responses to determine catch-all status
        is_catch_all, confidence, method = self._analyze_results(test_results, responses)

        # Determine server behavior pattern
        server_behavior = self._determine_server_behavior(responses)

        verification_time = time.time() - start_time

        return CatchAllResult(
            is_catch_all=is_catch_all,
            confidence=confidence,
            detection_method=method,
            response_patterns=test_results,
            server_behavior=server_behavior,
            verified_patterns=verified_patterns,
            verification_time=verification_time,
            smtp_responses=dict(responses)
        )

    def _test_bypass_patterns(self, domain: str, mx_records: List[str], 
                            smtp_verifier, responses: Dict) -> Optional[CatchAllResult]:
        """Test for patterns that might bypass normal catch-all"""
        for pattern in self.bypass_patterns:
            email = f"{pattern}@{domain}"
            result = smtp_verifier(email, mx_records)
            is_valid = self._extract_validity(result)
            responses['bypass'].append(is_valid)

            # If all bypass patterns are accepted, likely a catch-all
            if all(responses['bypass']):
                return CatchAllResult(
                    is_catch_all=True,
                    confidence=0.95,
                    detection_method="bypass_pattern",
                    response_patterns={'bypass': True},
                    server_behavior="accepts_all_standard_patterns",
                    verified_patterns=self.bypass_patterns,
                    verification_time=0.0,
                    smtp_responses=dict(responses)
                )
        return None

    def _test_pattern_group(self, group: str, domain: str, mx_records: List[str],
                           smtp_verifier, responses: Dict) -> bool:
        """Test a group of patterns"""
        results = []
        for pattern_generator in self.test_patterns[group]:
            email = pattern_generator(domain)
            result = smtp_verifier(email, mx_records)
            is_valid = self._extract_validity(result)
            responses[group].append(is_valid)
            results.append(is_valid)
        return any(results)

    def _analyze_results(self, test_results: Dict, responses: Dict) -> Tuple[bool, float, str]:
        """Analyze test results to determine catch-all status"""
        # Count positive responses
        standard_positives = sum(1 for x in responses['standard'] if x)
        format_positives = sum(1 for x in responses['format_specific'] if x)
        edge_positives = sum(1 for x in responses['edge_cases'] if x)

        total_tests = len(responses['standard']) + len(responses['format_specific']) + len(responses['edge_cases'])
        positive_ratio = (standard_positives + format_positives + edge_positives) / total_tests

        # Determine catch-all status and confidence
        if positive_ratio > 0.8:
            return True, 0.95, "high_acceptance"
        elif positive_ratio > 0.6:
            return True, 0.8, "moderate_acceptance"
        elif positive_ratio > 0.4:
            return True, 0.6, "potential_catch_all"
        elif standard_positives > 0:
            return True, 0.4, "selective_catch_all"
        else:
            return False, 0.9, "standard_rejection"

    def _determine_server_behavior(self, responses: Dict) -> str:
        """Analyze server behavior patterns"""
        if all(responses.get('bypass', [])):
            return "accepts_standard_patterns"
        elif all(responses.get('standard', [])):
            return "accepts_all_random"
        elif any(responses.get('edge_cases', [])):
            return "accepts_edge_cases"
        elif any(responses.get('format_specific', [])):
            return "selective_acceptance"
        else:
            return "strict_rejection"

    def _extract_validity(self, result) -> bool:
        """Extract validity from SMTP verification result"""
        if isinstance(result, dict):
            return result.get('is_valid', False)
        return bool(result)