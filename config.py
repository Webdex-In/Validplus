import os
from typing import Set, Dict, Any, Union
import requests


class Config:
    SQLALCHEMY_DATABASE_URI = 'postgresql:// postgres:tE8ri2hEd1ruxus8_Br2@139.84.132.236:5432/dataforge'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


# Function to fetch and parse the disposable domains list from the URL
def fetch_disposable_domains(urls: list) -> Set[str]:
    """Fetch disposable email domains from multiple URLs and return as a set."""
    all_domains = set()
    for url in urls:
        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise an exception for any HTTP errors
            domains = set(response.text.strip().splitlines())  # Split by line breaks and remove extra spaces
            all_domains.update(domains)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching disposable email domains from {url}: {e}")
    return all_domains

# URLs of the raw domain lists
DISPOSABLE_EMAIL_DOMAINS_URLS = [
    "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt",
    "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains_strict.txt"
]

# Hardcoded disposable email domains
STATIC_DISPOSABLE_DOMAINS: Set[str] = {
    'tempmail.com', '10minutemail.com', 'throwawaymail.com',
    'mailinator.com', 'guerrillamail.com', 'yopmail.com',
    'temp-mail.org', 'trashmail.com', 'sharklasers.com',
    'tempmail.net', 'disposablemail.com', 'wegwerfemail.de',
    'throwawaymail.net', 'minutemail.com', 'tempmailaddress.com',
    'fakeinbox.com', 'mailnesia.com', 'tempr.email',
    'guerrillamail.net', 'guerrillamail.org', 'guerrillamailblock.com',
    'mailinator.net', 'mailinator.org', 'mailinator.info',
    'yopmail.fr', 'yopmail.net', 'cool.fr.nf', 'jetable.org'
}

# Fetch disposable email domains and merge with the static list
DISPOSABLE_DOMAINS: Set[str] = STATIC_DISPOSABLE_DOMAINS.union(fetch_disposable_domains(DISPOSABLE_EMAIL_DOMAINS_URLS))

# Flask Configuration
FLASK_CONFIG = {
    'HOST': os.getenv('HOST', '0.0.0.0'),
    'PORT': int(os.getenv('PORT', 8080)),
    'DEBUG': False,  # Always False in production
    'TESTING': False,
    'JSONIFY_PRETTYPRINT_REGULAR': False,  # Better performance in production
    'MAX_CONTENT_LENGTH': 1 * 1024 * 1024,  # 1MB max-limit
    'PREFERRED_URL_SCHEME': 'https'
}

# Logging Configuration
LOG_CONFIG = {
    'FILENAME': 'email_validator.log',
    'MAX_BYTES': 10 * 1024 * 1024,  # 10MB
    'BACKUP_COUNT': 5,
    'LOG_FORMAT': '%(asctime)s - %(name)s - %(levelname)s - %(message)s - [%(filename)s:%(lineno)d]',
    'LOG_LEVEL': 'INFO'
}

# Rate Limiting Configuration
RATE_LIMITS = {
    'GLOBAL': {
        'requests': 100000,  # Increased for production
        'window': 3600
    },
    'DOMAIN': {
        'requests': 5000,  
        'window': 3600
    },
    'IP': {
        'requests': 10000,  
        'window': 3600
    },
    'DOMAIN_IP': {
        'requests': 2000,
        'window': 3600
    }
}

# DNS Configuration
DNS_CONFIG = {
    'NAMESERVERS': [
        '8.8.8.8',    # Google DNS
        '1.1.1.1',    # Cloudflare DNS
        '9.9.9.9',    # Quad9
        '208.67.222.222'  # OpenDNS
    ],
    'TIMEOUT': 5,
    'LIFETIME': 10,
    'CACHE_TTL': 300,      # 5 minutes
    'CACHE_MAXSIZE': 10000,  # Increased for production
    'RETRY_COUNT': 3,
    'RETRY_TIMEOUT': 1    # 1 second between retries
}

# SMTP Configuration
SMTP_CONFIG = {
    'TIMEOUT': 7,
    'MAX_CONNECTIONS': 50,  # Increased for production
    'CONNECTION_TIMEOUT': 5,
    'MAX_AGE': 300,  # 5 minutes
    'RETRY_COUNT': 2,
    'RETRY_DELAY': 1,
    'DEFAULT_PORTS': [25, 587, 465]
}

ROLE_ACCOUNTS: Set[str] = {
    # Administrative and System
    'admin', 'administrator', 'hostmaster', 'postmaster', 'webmaster', 'root', 'sysadmin',
    'system', 'security', 'ssl', 'certificates', 'dns', 'domain', 'hosting', 'cpanel',
    'whm', 'plesk', 'server', 'gateway', 'mx', 'smtp', 'imap', 'pop3',

    # Support and Service
    'support', 'help', 'helpdesk', 'service', 'customercare', 'care', 'customersupport',
    'technical', 'tech', 'support-team', 'bugs', 'issues', 'complaints', 'returns',
    'warranty', 'refunds', 'feedback-support', 'emergency', 'oncall', 'escalations',
    'support1', 'support2', 'level1', 'level2', 'level3', 'tier1', 'tier2', 'tier3',
    'servicedesk', 'desk', 'ticket', 'tickets', 'case', 'cases', 'dispute', 'disputes',

    # Information and Contact
    'info', 'information', 'contact', 'enquiries', 'inquiries', 'feedback', 'reception',
    'general', 'hello', 'questions', 'ask', 'faq', 'query', 'queries', 'contactus',
    'about', 'welcome', 'front', 'frontdesk', 'lobby', 'main', 'primary', 'central',

    # Business Functions
    'sales', 'marketing', 'billing', 'finance', 'accounts', 'accounting', 'payroll',
    'invoice', 'orders', 'shipping', 'legal', 'compliance', 'procurement', 'purchasing',
    'vendors', 'suppliers', 'partnerships', 'affiliates', 'resellers', 'wholesale',
    'retail', 'quotes', 'tenders', 'contracts', 'payments', 'collections', 'revenue',
    'expense', 'reimbursement', 'tax', 'audit', 'booking', 'reservation', 'register',
    'registration', 'subscribe', 'subscription', 'checkout', 'merchant', 'payment',
    'billing-support', 'sales1', 'sales2', 'quote', 'estimates', 'business', 'commerce',
    'commercial', 'trade', 'trading', 'export', 'import', 'customs', 'duty', 'logistics',
    'supply', 'chain', 'inventory', 'stock', 'warehouse', 'fulfillment', 'delivery',

    # Human Resources
    'hr', 'recruitment', 'careers', 'jobs', 'hiring', 'personnel', 'benefits',
    'payroll-hr', 'training', 'talent', 'employees', 'staff-hr', 'onboarding',
    'offboarding', 'compensation', 'leave', 'attendance', 'timesheet', 'vacation',
    'absence', 'sick', 'resume', 'cv', 'interview', 'candidate', 'candidates',
    'people', 'culture', 'diversity', 'inclusion', 'dei', 'wellness', 'benefits',

    # No-Reply and Automated
    'noreply', 'no-reply', 'no.reply', 'donotreply', 'do-not-reply', 'do.not.reply',
    'automated', 'auto', 'daemon', 'mailer', 'mailerdaemon', 'bounce', 'alerts',
    'notifications', 'reports', 'system-alerts', 'monitoring', 'status', 'updates',
    'autoresponder', 'automatic', 'robot', 'bot', 'notify', 'notification', 'alert',
    'scheduler', 'scheduled', 'cron', 'digest', 'summary', 'report', 'reporter',

    # Communications and Marketing
    'press', 'media', 'communications', 'pr', 'newsletter', 'news', 'editorial',
    'blog', 'social', 'social-media', 'community', 'events', 'webinar', 'broadcast',
    'announcements', 'publicity', 'outreach', 'campaign', 'campaigns', 'marketing',
    'advertise', 'advertising', 'ads', 'adwords', 'seo', 'digital', 'branding',
    'brand', 'design', 'graphics', 'creative', 'content', 'copywriting', 'copy',
    'maillist', 'mailing', 'list', 'unsubscribe', 'subscribe', 'subscription',

    # Development and Technical
    'developer', 'dev', 'api', 'development', 'engineering', 'devops', 'testing',
    'qa', 'quality', 'staging', 'production', 'deploy', 'release', 'git', 'svn',
    'repository', 'builds', 'ci', 'cd', 'integration', 'architecture', 'test',
    'beta', 'alpha', 'preview', 'demo', 'sandbox', 'development', 'prod', 'uat',
    'technical', 'engineer', 'engineering', 'coder', 'coding', 'programmer',
    'programming', 'software', 'hardware', 'network', 'networking', 'cloud',
    'infrastructure', 'platform', 'mobile', 'web', 'frontend', 'backend', 'fullstack',

    # Office and Management
    'office', 'team', 'staff', 'management', 'operations', 'facilities', 'logistics',
    'maintenance', 'reception', 'secretary', 'executive', 'admin-team', 'coordination',
    'director', 'ceo', 'cfo', 'cto', 'coo', 'president', 'vice-president', 'vp',
    'head', 'supervisor', 'manager', 'board', 'chairman', 'chairwoman', 'chair',

    # Security and Compliance
    'security', 'privacy', 'gdpr', 'dpo', 'compliance-team', 'audit-team',
    'infosec', 'abuse', 'fraud', 'phishing', 'incident', 'vulnerabilities',
    'pentest', 'penetration', 'testing', 'cybersecurity', 'encryption', 'firewall',
    'access', 'authentication', 'authorization', 'identity', 'credentials',
    'password', 'passwords', 'reset', 'recovery', 'breach', 'disclosure',

    # Project Management
    'project', 'projects', 'program', 'portfolio', 'pmo', 'scrum', 'agile',
    'delivery', 'implementation', 'consulting', 'consultant', 'consultants',
    'advisor', 'advisory', 'strategy', 'strategic', 'transformation', 'change',
    'improvement', 'optimization', 'analysis', 'analyst', 'analytics',

    # Regional and Language
    'international', 'global', 'regional', 'local', 'export', 'import',
    'translations', 'localization', 'america', 'europe', 'asia', 'africa',
    'pacific', 'north', 'south', 'east', 'west', 'central', 'latin', 'nordic',
    'info-fr', 'info-de', 'info-es', 'info-it', 'info-pt', 'info-ru', 'info-cn',
    'info-jp', 'info-kr', 'support-fr', 'support-de', 'support-es', 'support-it',
    'support-pt', 'support-ru', 'support-cn', 'support-jp', 'support-kr',

    # Industry Specific
    'academic', 'faculty', 'student', 'campus', 'admissions', 'alumni',
    'education', 'learning', 'library', 'resources', 'research', 'rd',
    'innovation', 'labs', 'experiments', 'testing-team', 'prototype', 'pilot',
    'medical', 'health', 'healthcare', 'doctor', 'patient', 'clinic', 'hospital',
    'pharmacy', 'dental', 'emergency', 'billing-medical', 'insurance', 'claims',
    'policy', 'underwriting', 'financial', 'bank', 'banking', 'mortgage',
    'loan', 'loans', 'credit', 'investment', 'investments', 'wealth', 'account',
    'broker', 'trading', 'hospitality', 'hotel', 'restaurant', 'booking',
    'reservations', 'concierge', 'travel', 'tourism', 'flights', 'tickets',

    # Common Formats and Patterns
    'info1', 'info2', 'info3', 'contact1', 'contact2', 'contact3',
    'dept', 'department', 'group', 'division', 'unit', 'branch', 'sector',
    'zone', 'region', 'area', 'district', 'box', 'mailbox', 'inbox',
    'primary', 'secondary', 'alternate', 'backup', 'temp', 'temporary',
    'old', 'new', 'archive', 'archived', 'inactive', 'active'
}

# Disposable Email Domains
DISPOSABLE_DOMAINS: Set[str] = {
    # Major Disposable Services
    'tempmail.com', '10minutemail.com', 'throwawaymail.com',
    'mailinator.com', 'guerrillamail.com', 'yopmail.com',
    'temp-mail.org', 'trashmail.com', 'sharklasers.com',

    # Additional Services
    'tempmail.net', 'disposablemail.com', 'wegwerfemail.de',
    'throwawaymail.net', 'minutemail.com', 'tempmailaddress.com',
    'fakeinbox.com', 'mailnesia.com', 'tempr.email',

    # Variants
    'guerrillamail.net', 'guerrillamail.org', 'guerrillamailblock.com',
    'mailinator.net', 'mailinator.org', 'mailinator.info',
    'yopmail.fr', 'yopmail.net', 'cool.fr.nf', 'jetable.org'
}

FREE_EMAIL_PROVIDERS: Set[str] = {
    # Global Providers
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 
    'protonmail.com', 'icloud.com', 'zoho.com', 'mail.com', 'yandex.com',
    'gmx.com', 'tutanota.com', 'fastmail.com', 'me.com', 'pm.me',
    'mailbox.org', 'hey.com', 'duck.com', 'skiff.com',

    # Microsoft Services
    'hotmail.co.uk', 'hotmail.fr', 'hotmail.de', 'hotmail.it', 'hotmail.es',
    'hotmail.com.br', 'hotmail.com.ar', 'live.com', 'live.co.uk', 'live.fr',
    'live.nl', 'msn.com', 'passport.com', 'outlook.fr', 'outlook.de', 
    'outlook.jp', 'outlook.it', 'outlook.es', 'outlook.com.br',

    # Yahoo Variants
    'yahoo.co.uk', 'yahoo.co.in', 'yahoo.co.jp', 'yahoo.fr', 'yahoo.de',
    'yahoo.it', 'yahoo.es', 'yahoo.com.br', 'yahoo.com.ar', 'yahoo.com.mx',
    'yahoo.com.au', 'yahoo.com.sg', 'yahoo.com.ph', 'yahoo.com.tw',
    'yahoo.com.hk', 'yahoo.com.vn', 'yahoo.co.kr', 'yahoo.co.id',
    'yahoo.com.my', 'yahoo.co.th', 'ymail.com', 'rocketmail.com',

    # Asian Providers
    'qq.com', '163.com', '126.com', 'yeah.net', 'sina.com', 'sohu.com',
    'aliyun.com', '139.com', 'wo.cn', '188.com', 'foxmail.com', 
    'naver.com', 'daum.net', 'hanmail.net', 'nate.com',

    # European Providers
    'web.de', 'gmx.de', 'gmx.at', 'gmx.ch', 'gmx.net', 'freenet.de',
    't-online.de', 'libero.it', 'tiscali.it', 'laposte.net', 'orange.fr',
    'wanadoo.fr', 'free.fr', 'sfr.fr', 'btinternet.com', 'virginmedia.com',
    'blueyonder.co.uk', 'sky.com', 'mail.ru', 'rambler.ru', 'yandex.ru',
    'list.ru', 'bk.ru', 'inbox.ru', 'internet.ru', 'myrambler.ru',

    # India and South Asia
    'rediffmail.com', 'indiatimes.com', 'sify.com', 'indianmail.com',
    'india.com', 'sancharnet.in', 'bol.net.in',

    # Latin America
    'bol.com.br', 'uol.com.br', 'terra.com.br', 'ig.com.br',
    'terra.com.ar', 'uol.com.ar', 'terra.com.mx', 'prodigy.net.mx',

    # Middle East and Africa
    'walla.co.il', 'mail.co.za', 'webmail.co.za', 'mweb.co.za',

    # Disposable/Temporary Providers
    'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 
    'sharklasers.com', 'spam4.me', 'yopmail.com',

    # Legacy and Discontinued (still in use)
    'aim.com', 'excite.com', 'juno.com', 'lycos.com', 'netscape.net',
    'att.net', 'verizon.net', 'sbcglobal.net', 'comcast.net', 'cox.net',
    'earthlink.net', 'mac.com', 'compuserve.com'
}

BLACKLISTS: list[str] = [
    # Spamhaus
    'zen.spamhaus.org',
    'sbl.spamhaus.org',
    'xbl.spamhaus.org',
    'pbl.spamhaus.org',
    'dbl.spamhaus.org',
    'sbl-xbl.spamhaus.org',

    # SpamCop
    'bl.spamcop.net',

    # SORBS
    'dnsbl.sorbs.net',
    'spam.dnsbl.sorbs.net',
    'recent.spam.dnsbl.sorbs.net',
    'new.spam.dnsbl.sorbs.net',
    'old.spam.dnsbl.sorbs.net',
    'problems.dnsbl.sorbs.net',
    'safe.dnsbl.sorbs.net',

    # Barracuda
    'b.barracudacentral.org',

    # Other Major DNSBLs
    'dnsbl.dronebl.org',
    'dnsbl.inps.de',
    'ix.dnsbl.manitu.net',
    'psbl.surriel.com',
    'ubl.unsubscore.com',
    'dnsbl.spfbl.net',
    'spam.spamrats.com',

    # Specialized Lists
    'truncate.gbudb.net',
    'dnsbl.justspam.org',
    'bad.psky.me',
    'bl.spamcannibal.org',
    'bl.worst.nosolicitado.org',
    'bogons.cymru.com',
    'cbl.abuseat.org',
    'combined.rbl.msrbl.net',

    # Multi-Criteria Lists
    'multi.surbl.org',
    'multi.uribl.com',
    'dnsbl.openresolvers.org',
    'access.redhawk.org',

    # Regional Lists
    'spamsources.fabel.dk',
    'wormrbl.imp.ch',
    'rbl.interserver.net',
    'db.wpbl.info',
    'korean.services.net',
    'virus.rbl.jp',

    # Additional Protection
    'dnsbl.cobion.com',
    'forbidden.icm.edu.pl',
    'proxy.bl.gweep.ca',
    'relays.nether.net',
    'singular.ttk.pte.hu',
    'spam.rbl.msrbl.net',
    'spamlist.or.kr',
    'spamrbl.imp.ch',
    't3direct.dnsbl.net.au'
]

# Error Messages
ERROR_MESSAGES = {
    'INVALID_EMAIL': 'Invalid email format',
    'DOMAIN_NOT_FOUND': 'Domain does not exist',
    'NO_MX_RECORDS': 'No valid MX records found for domain',
    'DISPOSABLE_EMAIL': 'Disposable email addresses are not allowed',
    'ROLE_ACCOUNT': 'Role-based email accounts are not allowed',
    'SMTP_ERROR': 'Unable to verify email existence',
    'RATE_LIMIT': 'Rate limit exceeded. Please try again later.',
    'SERVER_ERROR': 'An unexpected error occurred'
}

# Validation Rules
VALIDATION_RULES = {
    'MAX_EMAIL_LENGTH': 254,
    'MAX_LOCAL_PART_LENGTH': 64,
    'MAX_DOMAIN_LENGTH': 255,
    'MIN_DOMAIN_SEGMENTS': 2,
    'ALLOWED_SPECIAL_CHARS': '.-_+',
    'RESTRICTED_LOCAL_CHARS': '<>()[]\\,;:@ '
}