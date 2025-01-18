from dataclasses import dataclass
from typing import List, Dict
from models import MailServerChecks, DNSSecurityChecks, SecurityChecks, VerificationScore

@dataclass
class ScoreWeights:
    """Defines the maximum points deductible for each category"""
    SMTP_VERIFICATION = 100  # Complete failure if email doesn't exist
    MAIL_SERVER = 35        # Essential infrastructure checks
    DNS_SECURITY = 30       # Security configuration
    SECURITY_CHECKS = 25    # Blacklist and spam checks
    ACCOUNT_TYPE = 20       # Disposable and role account penalties
    PERFORMANCE = 5         # Response time penalties
    BONUS = 15             # Bonus for excellent configuration

class EmailScoreCalculator:
    def __init__(self):
        self.weights = ScoreWeights()

    def calculate_score(self,
                       mail_server: MailServerChecks,
                       dns_security: DNSSecurityChecks,
                       security: SecurityChecks,
                       is_disposable: bool,
                       is_role: bool,
                       smtp_check: bool,
                       verification_time: float) -> VerificationScore:
        """
        Calculate email verification score with detailed breakdown
        """
        score = 100
        details = []
        category_scores = {
            'Infrastructure': 0,
            'Security': 0,
            'Risk Factors': 0,
            'Performance': 0
        }

        # SMTP Verification (Critical Check)
        if not smtp_check:
            score = 0
            details.append("Email address doesn't exist (-100)")
            return VerificationScore(
                score=0,
                verdict="Failed",
                details=details,
                confidence="Very High",
                verification_time=verification_time
            )

        # Mail Server Checks
        server_deductions = 0
        if not mail_server.has_valid_mx:
            server_deductions += 10
            details.append("Missing valid MX records (-10)")
        if not mail_server.port_open:
            server_deductions += 5
            details.append("SMTP port closed (-5)")
        if mail_server.has_catch_all:
            server_deductions += 15
            details.append("Catch-all domain detected (-15)")

        score -= server_deductions
        category_scores['Infrastructure'] = self.weights.MAIL_SERVER - server_deductions

        # Provider Bonus
        if mail_server.smtp_provider.lower() in ['google', 'microsoft', 'yahoo', 'protonmail']:
            score += 10
            details.append("Reputable email provider (+10)")

        # DNS Security Checks
        security_deductions = self._calculate_dns_security_deductions(dns_security, details)
        score -= security_deductions
        category_scores['Security'] = (self.weights.DNS_SECURITY - security_deductions)

        # Security Risk Checks
        risk_deductions = self._calculate_security_deductions(security, details)
        score -= risk_deductions
        category_scores['Security'] += (self.weights.SECURITY_CHECKS - risk_deductions)

        # Account Type Penalties
        type_deductions = 0
        if is_disposable:
            type_deductions += 15
            details.append("Disposable email detected (-15)")
        if is_role:
            type_deductions += 5
            details.append("Role account detected (-5)")

        score -= type_deductions
        category_scores['Risk Factors'] = self.weights.ACCOUNT_TYPE - type_deductions

        # Performance Score
        perf_deductions = 0
        if verification_time > 5:
            perf_deductions = min(5, int((verification_time - 4) / 2))
            if perf_deductions > 0:
                details.append(f"Slow response time (-{perf_deductions})")

        score -= perf_deductions
        category_scores['Performance'] = self.weights.PERFORMANCE - perf_deductions

        # Bonus Points
        if self._qualifies_for_bonus(dns_security):
            score += self.weights.BONUS
            details.append(f"Complete and strong email security configuration (+{self.weights.BONUS})")

        # Ensure score stays within bounds
        score = max(0, min(100, score))

        verdict = self._get_enhanced_verdict(score, category_scores)
        confidence = self._get_enhanced_confidence(score, smtp_check, mail_server.has_valid_mx)

        return VerificationScore(
            score=score,
            verdict=verdict,
            details=details,
            confidence=confidence,
            verification_time=verification_time
        )

    def _calculate_dns_security_deductions(self, dns_security: DNSSecurityChecks, details: List[str]) -> int:
        deductions = 0

        # SPF Checks
        if not dns_security.has_spf:
            deductions += 10
            details.append("Missing SPF record (-10)")
        elif not dns_security.spf_valid:
            deductions += 5
            details.append("Invalid SPF record (-5)")

        # DMARC Checks
        if not dns_security.has_dmarc:
            deductions += 10
            details.append("Missing DMARC record (-10)")
        else:
            dmarc_record = dns_security.dmarc_record.lower()
            if 'p=none' in dmarc_record:
                deductions += 5
                details.append("Weak DMARC policy (p=none) (-5)")
            elif 'p=quarantine' in dmarc_record:
                deductions += 2
                details.append("Moderate DMARC policy (p=quarantine) (-2)")

        # DKIM Checks
        if not dns_security.has_dkim:
            deductions += 8
            details.append("Missing DKIM setup (-8)")
        elif not dns_security.dkim_valid:
            deductions += 4
            details.append("Invalid DKIM configuration (-4)")

        return deductions

    def _calculate_security_deductions(self, security: SecurityChecks, details: List[str]) -> int:
        deductions = 0

        if security.blacklisted:
            deductions += 20
            details.append("Domain blacklisted (-20)")
        if security.spam_score >= 50:
            deductions += 5
            details.append("High spam score (-5)")

        return deductions

    def _qualifies_for_bonus(self, dns_security: DNSSecurityChecks) -> bool:
        return (dns_security.has_spf and dns_security.spf_valid and 
                dns_security.has_dmarc and 'p=reject' in dns_security.dmarc_record.lower() and 
                dns_security.has_dkim and dns_security.dkim_valid)

    def _get_enhanced_verdict(self, score: int, category_scores: Dict[str, int]) -> str:
        if score >= 85:  # Reduced from 90
            return "Excellent"
        elif score >= 75:  # Reduced from 80
            lowest_category = min(category_scores.values())
            return "Very Good" if lowest_category >= 50 else f"Very Good (Needs attention in {self._get_lowest_category(category_scores)})"
        elif score >= 65:  # Reduced from 70
            return "Good"
        elif score >= 55:  # Reduced from 60
            return "Fair"
        elif score >= 45:  # Reduced from 50
            return "Needs Improvement"
        elif score >= 25:  # Reduced from 30
            return "Poor"
        else:
            return "Critical Issues"

    def _get_enhanced_confidence(self, score: int, smtp_check: bool, has_mx: bool) -> str:
        if not smtp_check or not has_mx:
            return "Very Low"
        if score >= 85:  # Updated thresholds to match new scoring
            return "Very High"
        elif score >= 70:
            return "High"
        elif score >= 55:
            return "Medium"
        elif score >= 35:
            return "Low"
        else:
            return "Very Low"

    def _get_lowest_category(self, category_scores: Dict[str, int]) -> str:
        return min(category_scores.items(), key=lambda x: x[1])[0]