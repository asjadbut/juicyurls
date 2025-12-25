"""
URL Analyzer - Core logic for parsing and categorizing URLs.

Features:
- Context-aware matching (checks parameter VALUES, not just names)
- Confidence scoring to reduce false positives
- Smart deduplication (groups similar URLs)
- URL Intelligence: Analyzes entire URL structure to determine value
- Secret Detection: Finds leaked API keys, tokens, and credentials
"""

import re
import math
from urllib.parse import urlparse, parse_qs, unquote
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict, Counter
import hashlib

from .patterns import PatternManager, VulnPattern, Severity


# =============================================================================
# SECRET DETECTION SYSTEM
# Detects leaked API keys, tokens, and credentials in URLs using:
# 1. Known patterns (JWT, AWS, Stripe, etc.)
# 2. Entropy analysis (high-randomness strings)
# =============================================================================

@dataclass
class SecretMatch:
    """Represents a detected secret in a URL."""
    secret_type: str
    param_name: str
    value: str
    confidence: float  # 0.0 to 1.0
    description: str
    severity: str  # critical, high, medium

class SecretDetector:
    """
    Detects potential secrets, API keys, and tokens in URL parameters.
    
    Uses two approaches:
    1. Pattern matching for known secret formats
    2. Entropy analysis for high-randomness strings
    """
    
    # Known secret patterns with regex and metadata
    # Format: 'name': (pattern, description, severity, min_length)
    SECRET_PATTERNS = {
        # JWT Tokens
        'jwt': {
            'pattern': r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$',
            'description': 'JSON Web Token (JWT)',
            'severity': 'critical',
            'min_length': 20,
        },
        
        # AWS
        'aws_access_key': {
            'pattern': r'^AKIA[0-9A-Z]{16}$',
            'description': 'AWS Access Key ID',
            'severity': 'critical',
            'min_length': 20,
        },
        'aws_secret_key': {
            'pattern': r'^[A-Za-z0-9/+=]{40}$',
            'description': 'Possible AWS Secret Key',
            'severity': 'critical',
            'min_length': 40,
            'requires_context': True,  # Only flag if param name suggests secret
        },
        
        # Stripe
        'stripe_secret': {
            'pattern': r'^sk_live_[0-9a-zA-Z]{24,}$',
            'description': 'Stripe Secret Key (LIVE)',
            'severity': 'critical',
            'min_length': 30,
        },
        'stripe_publishable': {
            'pattern': r'^pk_live_[0-9a-zA-Z]{24,}$',
            'description': 'Stripe Publishable Key (live)',
            'severity': 'medium',
            'min_length': 30,
        },
        'stripe_test': {
            'pattern': r'^[sr]k_test_[0-9a-zA-Z]{24,}$',
            'description': 'Stripe Test Key',
            'severity': 'low',
            'min_length': 30,
        },
        
        # GitHub
        'github_token': {
            'pattern': r'^ghp_[0-9a-zA-Z]{36}$',
            'description': 'GitHub Personal Access Token',
            'severity': 'critical',
            'min_length': 40,
        },
        'github_oauth': {
            'pattern': r'^gho_[0-9a-zA-Z]{36}$',
            'description': 'GitHub OAuth Access Token',
            'severity': 'critical',
            'min_length': 40,
        },
        'github_app': {
            'pattern': r'^ghu_[0-9a-zA-Z]{36}$',
            'description': 'GitHub User-to-Server Token',
            'severity': 'critical',
            'min_length': 40,
        },
        'github_refresh': {
            'pattern': r'^ghr_[0-9a-zA-Z]{36}$',
            'description': 'GitHub Refresh Token',
            'severity': 'critical',
            'min_length': 40,
        },
        
        # Google
        'google_api_key': {
            'pattern': r'^AIza[0-9A-Za-z_-]{35}$',
            'description': 'Google API Key',
            'severity': 'high',
            'min_length': 39,
        },
        'google_oauth': {
            'pattern': r'^ya29\.[0-9A-Za-z_-]+$',
            'description': 'Google OAuth Access Token',
            'severity': 'critical',
            'min_length': 50,
        },
        
        # Slack
        'slack_token': {
            'pattern': r'^xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}$',
            'description': 'Slack Token',
            'severity': 'critical',
            'min_length': 50,
        },
        'slack_webhook': {
            'pattern': r'^https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+$',
            'description': 'Slack Webhook URL',
            'severity': 'high',
            'min_length': 50,
        },
        
        # Discord
        'discord_token': {
            'pattern': r'^[MN][A-Za-z0-9]{23,}\.[\w-]{6}\.[\w-]{27}$',
            'description': 'Discord Bot Token',
            'severity': 'critical',
            'min_length': 50,
        },
        'discord_webhook': {
            'pattern': r'^https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+$',
            'description': 'Discord Webhook URL',
            'severity': 'high',
            'min_length': 50,
        },
        
        # Twilio
        'twilio_api_key': {
            'pattern': r'^SK[0-9a-fA-F]{32}$',
            'description': 'Twilio API Key',
            'severity': 'critical',
            'min_length': 34,
        },
        'twilio_account_sid': {
            'pattern': r'^AC[0-9a-fA-F]{32}$',
            'description': 'Twilio Account SID',
            'severity': 'high',
            'min_length': 34,
        },
        
        # SendGrid
        'sendgrid_api_key': {
            'pattern': r'^SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}$',
            'description': 'SendGrid API Key',
            'severity': 'critical',
            'min_length': 69,
        },
        
        # Mailchimp
        'mailchimp_api_key': {
            'pattern': r'^[0-9a-f]{32}-us\d{1,2}$',
            'description': 'Mailchimp API Key',
            'severity': 'high',
            'min_length': 30,
        },
        
        # Square
        'square_access_token': {
            'pattern': r'^sq0atp-[0-9A-Za-z_-]{22}$',
            'description': 'Square Access Token',
            'severity': 'critical',
            'min_length': 30,
        },
        'square_oauth': {
            'pattern': r'^sq0csp-[0-9A-Za-z_-]{43}$',
            'description': 'Square OAuth Secret',
            'severity': 'critical',
            'min_length': 50,
        },
        
        # PayPal
        'paypal_braintree': {
            'pattern': r'^access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}$',
            'description': 'PayPal Braintree Access Token',
            'severity': 'critical',
            'min_length': 50,
        },
        
        # Shopify
        'shopify_private_token': {
            'pattern': r'^shppa_[0-9a-fA-F]{32}$',
            'description': 'Shopify Private App Token',
            'severity': 'critical',
            'min_length': 38,
        },
        'shopify_access_token': {
            'pattern': r'^shpat_[0-9a-fA-F]{32}$',
            'description': 'Shopify Access Token',
            'severity': 'critical',
            'min_length': 38,
        },
        
        # Heroku
        'heroku_api_key': {
            'pattern': r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
            'description': 'Heroku API Key (UUID format)',
            'severity': 'high',
            'min_length': 36,
            'requires_context': True,
        },
        
        # Firebase
        'firebase_key': {
            'pattern': r'^AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}$',
            'description': 'Firebase Cloud Messaging Key',
            'severity': 'high',
            'min_length': 150,
        },
        
        # NPM
        'npm_token': {
            'pattern': r'^npm_[A-Za-z0-9]{36}$',
            'description': 'NPM Access Token',
            'severity': 'critical',
            'min_length': 40,
        },
        
        # Generic high-value patterns
        'bearer_token': {
            'pattern': r'^Bearer\s+[A-Za-z0-9_-]{20,}$',
            'description': 'Bearer Token',
            'severity': 'critical',
            'min_length': 27,
        },
        'basic_auth': {
            'pattern': r'^Basic\s+[A-Za-z0-9+/]+=*$',
            'description': 'Basic Auth Credentials (Base64)',
            'severity': 'critical',
            'min_length': 10,
        },
        'private_key': {
            'pattern': r'^-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'description': 'Private Key',
            'severity': 'critical',
            'min_length': 50,
        },
        
        # Database connection strings
        'mongodb_uri': {
            'pattern': r'^mongodb(\+srv)?://[^:]+:[^@]+@',
            'description': 'MongoDB Connection URI with Credentials',
            'severity': 'critical',
            'min_length': 20,
        },
        'postgres_uri': {
            'pattern': r'^postgres(ql)?://[^:]+:[^@]+@',
            'description': 'PostgreSQL Connection URI with Credentials',
            'severity': 'critical',
            'min_length': 20,
        },
        'mysql_uri': {
            'pattern': r'^mysql://[^:]+:[^@]+@',
            'description': 'MySQL Connection URI with Credentials',
            'severity': 'critical',
            'min_length': 15,
        },
    }
    
    # Parameter names that suggest the value might be a secret
    SECRET_PARAM_NAMES = {
        'token', 'key', 'apikey', 'api_key', 'apiKey', 'api-key',
        'secret', 'password', 'passwd', 'pwd', 'pass',
        'auth', 'authorization', 'bearer',
        'access_token', 'accessToken', 'access-token',
        'refresh_token', 'refreshToken', 'refresh-token',
        'private_key', 'privateKey', 'private-key',
        'client_secret', 'clientSecret', 'client-secret',
        'app_secret', 'appSecret', 'app-secret',
        'api_secret', 'apiSecret', 'api-secret',
        'jwt', 'session', 'sessionid', 'session_id',
        'credential', 'credentials', 'cred',
        'webhook', 'hook',
    }
    
    @classmethod
    def calculate_entropy(cls, string: str) -> float:
        """
        Calculate Shannon entropy of a string.
        
        Higher entropy = more random = more likely to be a secret
        - English words: ~2.5 bits
        - Random alphanumeric: ~4.0+ bits
        - Base64/hex: ~4.5+ bits
        """
        if not string or len(string) < 8:
            return 0.0
        
        # Count frequency of each character
        freq = Counter(string)
        length = len(string)
        
        # Calculate entropy: -Σ(p * log2(p))
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @classmethod
    def detect_secrets(cls, params: Dict[str, List[str]], url: str = "") -> List[SecretMatch]:
        """
        Detect potential secrets in URL parameters.
        
        Args:
            params: Dictionary of parameter names to values
            url: Full URL (for checking patterns in the URL itself)
        
        Returns:
            List of SecretMatch objects for detected secrets
        """
        secrets = []
        
        # Check each parameter
        for param_name, values in params.items():
            param_is_secret_like = param_name.lower() in cls.SECRET_PARAM_NAMES or \
                                   any(s in param_name.lower() for s in ['key', 'token', 'secret', 'pass', 'auth'])
            
            for value in values:
                if not value or len(value) < 8:
                    continue
                
                # Check against known patterns
                for secret_name, config in cls.SECRET_PATTERNS.items():
                    # Skip patterns requiring context if param name doesn't suggest secret
                    if config.get('requires_context') and not param_is_secret_like:
                        continue
                    
                    if len(value) >= config['min_length']:
                        if re.match(config['pattern'], value, re.IGNORECASE):
                            secrets.append(SecretMatch(
                                secret_type=secret_name,
                                param_name=param_name,
                                value=cls._mask_secret(value),
                                confidence=0.95,
                                description=config['description'],
                                severity=config['severity'],
                            ))
                            break  # Found a match, no need to check other patterns
                
                # If no pattern matched, check entropy for potential unknown secrets
                if not any(s.param_name == param_name and s.value == cls._mask_secret(value) for s in secrets):
                    entropy = cls.calculate_entropy(value)
                    
                    # High entropy + secret-like param name = likely a secret
                    if entropy >= 4.0 and param_is_secret_like:
                        secrets.append(SecretMatch(
                            secret_type='high_entropy_secret',
                            param_name=param_name,
                            value=cls._mask_secret(value),
                            confidence=0.8,
                            description=f'High entropy value ({entropy:.2f} bits) in secret-like parameter',
                            severity='high',
                        ))
                    # Very high entropy even without secret-like name
                    elif entropy >= 4.5 and len(value) >= 20:
                        secrets.append(SecretMatch(
                            secret_type='high_entropy_value',
                            param_name=param_name,
                            value=cls._mask_secret(value),
                            confidence=0.6,
                            description=f'Very high entropy value ({entropy:.2f} bits)',
                            severity='medium',
                        ))
        
        # Also check the URL path for secrets (sometimes tokens are in the path)
        if url:
            parsed = urlparse(url)
            path_parts = parsed.path.split('/')
            for part in path_parts:
                if len(part) >= 20:
                    for secret_name, config in cls.SECRET_PATTERNS.items():
                        if config.get('requires_context'):
                            continue
                        if len(part) >= config['min_length']:
                            if re.match(config['pattern'], part, re.IGNORECASE):
                                secrets.append(SecretMatch(
                                    secret_type=secret_name,
                                    param_name='[URL_PATH]',
                                    value=cls._mask_secret(part),
                                    confidence=0.9,
                                    description=f"{config['description']} (in URL path)",
                                    severity=config['severity'],
                                ))
                                break
        
        return secrets
    
    @classmethod
    def _mask_secret(cls, value: str, visible_chars: int = 8) -> str:
        """Mask a secret value for safe display."""
        if len(value) <= visible_chars * 2:
            return value[:4] + '*' * (len(value) - 4)
        return value[:visible_chars] + '*' * (len(value) - visible_chars * 2) + value[-visible_chars:]
    
    @classmethod
    def get_severity_score(cls, secrets: List[SecretMatch]) -> float:
        """Calculate a score boost based on detected secrets."""
        if not secrets:
            return 0.0
        
        # Use the highest severity secret
        severity_scores = {
            'critical': 1.0,
            'high': 0.7,
            'medium': 0.4,
            'low': 0.2,
        }
        
        max_score = max(severity_scores.get(s.severity, 0) for s in secrets)
        return max_score


# =============================================================================
# URL INTELLIGENCE SYSTEM
# Analyzes the entire URL to determine if it's "juicy" (worth testing) or
# "boring" (static, marketing, tracking - likely useless for bug bounty)
# =============================================================================

class URLIntelligence:
    """
    Analyzes URL structure and context to determine its potential value.
    
    This goes beyond pattern matching - it understands:
    - What type of endpoint this likely is (API, static, admin, etc.)
    - Whether the URL structure suggests dynamic functionality
    - Common "boring" URL patterns that rarely yield bugs
    - Technology/framework fingerprints
    """
    
    # ========== BORING URL SIGNALS (reduce score) ==========
    
    # Static asset paths - almost never vulnerable
    STATIC_PATHS = re.compile(
        r'^/(static|assets|dist|build|public|media|images?|img|'
        r'css|js|fonts?|icons?|uploads?/images?|cdn|resources?|'
        r'libs?|vendor|node_modules|bower_components|'
        r'wp-content/(themes|plugins)/[^/]+/(css|js|images?|fonts?)|'
        r'wp-includes/(css|js|images?))/', re.IGNORECASE
    )
    
    # Static file extensions - not interesting
    STATIC_EXTENSIONS = re.compile(
        r'\.(css|js|jsx|ts|tsx|less|scss|sass|'
        r'jpg|jpeg|png|gif|svg|ico|webp|avif|bmp|tiff?|'
        r'woff2?|ttf|eot|otf|'
        r'mp3|mp4|webm|ogg|wav|avi|mov|mkv|flv|'
        r'pdf|doc|docx|xls|xlsx|ppt|pptx|'
        r'zip|rar|7z|tar|gz|bz2|'
        r'map|min\.js|bundle\.js|chunk\.js)(\?|$)', re.IGNORECASE
    )
    
    # CDN and third-party domains - not in scope usually
    CDN_DOMAINS = re.compile(
        r'(cdn|static|assets|images?|media|fonts?)\d*\.|'
        r'cloudfront\.net|cloudflare|akamai|fastly|'
        r'googleapis\.com|gstatic\.com|'
        r'bootstrapcdn|cdnjs|unpkg|jsdelivr|'
        r'facebook\.com|facebook\.net|fbcdn\.net|'
        r'twitter\.com|twimg\.com|'
        r'google\.com/recaptcha|googletagmanager|'
        r'google-analytics|doubleclick|googlesyndication|'
        r'youtube\.com|ytimg\.com|'
        r'linkedin\.com|licdn\.com|'
        r'pinterest\.com|pinimg\.com|'
        r'instagram\.com|cdninstagram\.com|'
        r'tiktok\.com|tiktokcdn\.com|'
        r'hotjar\.com|segment\.io|mixpanel\.com|'
        r'intercom\.io|zendesk\.com|crisp\.chat|'
        r'stripe\.com|paypal\.com|braintree|'
        r'newrelic\.com|datadoghq\.com|sentry\.io', re.IGNORECASE
    )
    
    # Marketing/tracking/analytics - boring
    TRACKING_PARAMS = re.compile(
        r'^(utm_|gclid|fbclid|msclkid|dclid|twclid|ttclid|'
        r'_ga|_gid|_gat|__utm|mc_|mailchimp|'
        r'ref|referrer|source|medium|campaign|'
        r'irclickid|irgwc|affiliate|partner|'
        r'clickid|click_id|session_id|visitor_id|'
        r'_hsenc|_hsmi|hubspot|hs_|'
        r'wickedid|wicked_id|_mkto|mkt_tok|'
        r'trk|track|tracking|'
        r'li_fat_id|igshid|'
        r'__cf_|cf_|_cf_)$', re.IGNORECASE
    )
    
    # Boring path segments - pagination, sorting, filtering of public content
    BORING_PATHS = re.compile(
        r'/(page|paged|p)/\d+/?$|'  # Simple pagination
        r'/feed/?$|/rss/?$|/atom/?$|'  # Feeds
        r'/sitemap|/robots\.txt|/favicon|'
        r'/share/?$|/print/?$|'
        r'/tag/|/tags/|/category/|/categories/|'  # Taxonomy pages
        r'/author/|/archive/|/archives/|'
        r'/(terms|privacy|about|contact|faq|help|support|legal|tos|policy)/?$|'
        r'/blog/?$|/news/?$|/press/?$|/careers/?$', re.IGNORECASE
    )
    
    # Widget/embed URLs
    WIDGET_PATHS = re.compile(
        r'/embed/|/widget/|/share-button|/like-button|'
        r'/social-|/follow-|/subscribe-widget', re.IGNORECASE
    )
    
    # ========== JUICY URL SIGNALS (increase score) ==========
    
    # Admin/internal paths - high value targets
    ADMIN_PATHS = re.compile(
        r'/(admin|administrator|adm|manage|manager|management|'
        r'dashboard|control[-_]?panel|cpanel|portal|backend|'
        r'internal|intranet|staff|employee|'
        r'moderator|mod[-_]?panel|superuser|'
        r'sysadmin|system[-_]?admin|'
        r'root|sudo|privilege)', re.IGNORECASE
    )
    
    # API endpoints - often juicy
    API_PATHS = re.compile(
        r'^/(api|apis|rest|graphql|gql|v\d+|'
        r'webservice|ws|endpoint|service|services|'
        r'ajax|async|xhr|rpc|json[-_]?rpc|'
        r'_next/data|__api)/', re.IGNORECASE
    )
    
    # Authentication/authorization - high value
    AUTH_PATHS = re.compile(
        r'/(auth|oauth|oauth2|sso|saml|login|signin|sign[-_]?in|'
        r'logout|signout|sign[-_]?out|logoff|'
        r'register|signup|sign[-_]?up|'
        r'password|passwd|forgot|reset[-_]?password|'
        r'verify|verification|confirm|activate|'
        r'token|refresh[-_]?token|access[-_]?token|'
        r'session|jwt|2fa|mfa|otp|totp|'
        r'impersonate|switch[-_]?user|'
        r'permission|permissions|role|roles|acl)', re.IGNORECASE
    )
    
    # File operations - LFI/upload targets
    FILE_PATHS = re.compile(
        r'/(upload|uploads|file|files|attachment|attachments|'
        r'download|downloads|export|exports|'
        r'import|imports|backup|backups|'
        r'document|documents|doc|docs|'
        r'media[-_]?upload|image[-_]?upload|'
        r'asset[-_]?upload)', re.IGNORECASE
    )
    
    # Data operations - IDOR/info disclosure
    DATA_PATHS = re.compile(
        r'/(user|users|account|accounts|profile|profiles|'
        r'customer|customers|member|members|'
        r'order|orders|invoice|invoices|'
        r'payment|payments|transaction|transactions|'
        r'message|messages|notification|notifications|'
        r'settings|preferences|config|configuration|'
        r'report|reports|analytics|stats|statistics|'
        r'history|logs?|audit)', re.IGNORECASE
    )
    
    # Debug/development - jackpot if found in production
    DEBUG_PATHS = re.compile(
        r'/(debug|debugging|test|testing|dev|development|'
        r'staging|stage|uat|qa|sandbox|'
        r'console|terminal|shell|'
        r'phpinfo|info\.php|server[-_]?info|'
        r'status|health|healthcheck|health[-_]?check|'
        r'metrics|prometheus|actuator|'
        r'swagger|api[-_]?doc|apidoc|redoc|'
        r'graphiql|playground|explorer|'
        r'trace|dump|error[-_]?log)', re.IGNORECASE
    )
    
    # Dangerous operations
    DANGEROUS_PATHS = re.compile(
        r'/(exec|execute|run|eval|process|'
        r'cmd|command|shell|system|'
        r'query|sql|database|db|'
        r'include|require|template|render|'
        r'proxy|forward|fetch|request|curl|'
        r'redirect|redir|goto|return[-_]?to|'
        r'callback|webhook|hook|'
        r'delete|remove|destroy|drop|truncate|'
        r'edit|modify|update|patch|'
        r'create|insert|add|new|'
        r'grant|revoke|sudo)', re.IGNORECASE
    )
    
    # Juicy parameters that suggest dynamic functionality
    JUICY_PARAMS = re.compile(
        r'^(id|user_?id|account_?id|order_?id|'
        r'file|path|url|uri|link|src|dest|target|'
        r'redirect|return|next|goto|callback|'
        r'cmd|command|exec|query|search|'
        r'template|view|page|action|'
        r'token|key|secret|password|'
        r'email|phone|ssn|credit|'
        r'admin|debug|test|internal)$', re.IGNORECASE
    )
    
    # Interesting file extensions
    INTERESTING_EXTENSIONS = re.compile(
        r'\.(php|asp|aspx|jsp|jspx|do|action|'
        r'cgi|pl|py|rb|'
        r'xml|json|yaml|yml|'
        r'conf|config|ini|env|'
        r'sql|db|sqlite|'
        r'bak|backup|old|orig|'
        r'log|txt|csv|'
        r'key|pem|crt|cert)(\?|$)', re.IGNORECASE
    )
    
    # Technology fingerprints that indicate interesting targets
    TECH_FINGERPRINTS = {
        'wordpress': (re.compile(r'/wp-admin|/wp-json|/wp-content|/xmlrpc\.php', re.I), 0.1),
        'drupal': (re.compile(r'/node/\d+|/admin/content|/user/\d+', re.I), 0.15),
        'joomla': (re.compile(r'/administrator|/components/|option=com_', re.I), 0.15),
        'magento': (re.compile(r'/admin|/checkout|/customer/account', re.I), 0.1),
        'laravel': (re.compile(r'/_debugbar|/telescope|/horizon', re.I), 0.3),
        'django': (re.compile(r'/admin/|/__debug__/', re.I), 0.2),
        'rails': (re.compile(r'/rails/|\.json$.*_method=', re.I), 0.15),
        'spring': (re.compile(r'/actuator|/swagger|/api-docs', re.I), 0.25),
        'nodejs': (re.compile(r'/_next/|/graphql|/__graphql', re.I), 0.15),
        'jenkins': (re.compile(r'/jenkins|/job/|/script|/manage', re.I), 0.3),
        'gitlab': (re.compile(r'/api/v\d+/|/-/graphql', re.I), 0.2),
    }
    
    @classmethod
    def analyze(cls, url: str, domain: str, path: str, params: Dict[str, List[str]]) -> Tuple[float, List[str], str]:
        """
        Analyze a URL and return an intelligence score.
        
        Returns:
            Tuple of (score_adjustment, reasons, classification)
            - score_adjustment: -1.0 to +1.0 (negative = boring, positive = interesting)
            - reasons: List of why the score was adjusted
            - classification: 'boring', 'neutral', 'interesting', or 'juicy'
        """
        score = 0.0
        reasons = []
        
        # ========== NEGATIVE SIGNALS ==========
        
        # Check for CDN/third-party domains
        if cls.CDN_DOMAINS.search(domain):
            score -= 0.8
            reasons.append("third-party/CDN domain")
        
        # Check for static paths
        if cls.STATIC_PATHS.search(path):
            score -= 0.6
            reasons.append("static asset path")
        
        # Check for static file extensions
        if cls.STATIC_EXTENSIONS.search(path):
            score -= 0.7
            reasons.append("static file extension")
        
        # Check for boring paths
        if cls.BORING_PATHS.search(path):
            score -= 0.4
            reasons.append("low-value path pattern")
        
        # Check for widget/embed URLs
        if cls.WIDGET_PATHS.search(path):
            score -= 0.5
            reasons.append("widget/embed URL")
        
        # Check for tracking parameters (count them)
        tracking_count = sum(1 for p in params.keys() if cls.TRACKING_PARAMS.match(p))
        if tracking_count > 0:
            total_params = len(params)
            tracking_ratio = tracking_count / total_params if total_params > 0 else 0
            if tracking_ratio > 0.5:
                score -= 0.4
                reasons.append(f"mostly tracking params ({tracking_count}/{total_params})")
        
        # Extremely long URLs with random strings often indicate tracking/session
        if len(url) > 500:
            score -= 0.2
            reasons.append("very long URL (likely tracking)")
        
        # ========== POSITIVE SIGNALS ==========
        
        # Admin paths - high value
        if cls.ADMIN_PATHS.search(path):
            score += 0.5
            reasons.append("🎯 admin/management path")
        
        # API endpoints
        if cls.API_PATHS.search(path):
            score += 0.3
            reasons.append("🔌 API endpoint")
        
        # Auth paths
        if cls.AUTH_PATHS.search(path):
            score += 0.4
            reasons.append("🔐 auth/session path")
        
        # File operations
        if cls.FILE_PATHS.search(path):
            score += 0.35
            reasons.append("📁 file operation path")
        
        # Data paths
        if cls.DATA_PATHS.search(path):
            score += 0.25
            reasons.append("📊 data access path")
        
        # Debug/dev paths - jackpot!
        if cls.DEBUG_PATHS.search(path):
            score += 0.6
            reasons.append("🐛 debug/dev endpoint")
        
        # Dangerous operation paths
        if cls.DANGEROUS_PATHS.search(path):
            score += 0.4
            reasons.append("⚠️ dangerous operation path")
        
        # Interesting file extensions
        if cls.INTERESTING_EXTENSIONS.search(path):
            score += 0.2
            reasons.append("interesting file extension")
        
        # Count juicy parameters
        juicy_param_count = sum(1 for p in params.keys() if cls.JUICY_PARAMS.match(p))
        if juicy_param_count > 0:
            score += 0.15 * min(juicy_param_count, 3)  # Cap at 3
            reasons.append(f"{juicy_param_count} interesting param(s)")
        
        # Check parameter values for interesting content
        for param, values in params.items():
            for val in values:
                if not val:
                    continue
                # URL in parameter value - SSRF potential
                if re.match(r'^https?://', val, re.I):
                    score += 0.4
                    reasons.append(f"URL in param '{param}'")
                    break
                # Path traversal in value
                if '..' in val or val.startswith('/'):
                    score += 0.3
                    reasons.append(f"path-like value in '{param}'")
                    break
                # Numeric ID (IDOR potential)
                if re.match(r'^\d+$', val) and len(val) < 10:
                    score += 0.15
                    reasons.append(f"numeric ID in '{param}'")
                    break
        
        # Technology fingerprints
        for tech, (pattern, boost) in cls.TECH_FINGERPRINTS.items():
            if pattern.search(url):
                score += boost
                reasons.append(f"tech: {tech}")
                break  # Only count one tech
        
        # Path depth analysis - deeper paths often more interesting
        path_depth = path.count('/') - 1
        if path_depth >= 4:
            score += 0.1
            reasons.append("deep path structure")
        
        # Has query params with actual values (dynamic page)
        non_empty_params = sum(1 for v in params.values() if any(v))
        if non_empty_params >= 2:
            score += 0.1
            reasons.append("multiple dynamic params")
        
        # ========== CLASSIFY ==========
        score = max(-1.0, min(1.0, score))  # Clamp to [-1, 1]
        
        if score <= -0.4:
            classification = "boring"
        elif score <= 0.1:
            classification = "neutral"
        elif score <= 0.4:
            classification = "interesting"
        else:
            classification = "juicy"
        
        return score, reasons, classification


# Value patterns that indicate high-confidence matches
VALUE_PATTERNS = {
    # URL/SSRF indicators - value looks like a URL
    "url_value": re.compile(r'^https?://|^//|^\.\./', re.IGNORECASE),
    # File path indicators - value looks like a file path
    "file_path": re.compile(r'\.\.[\\/]|^[\\/]|\.php$|\.asp$|\.jsp$|\.txt$|\.xml$|\.ini$|\.conf$|\.log$|/etc/|/var/|c:\\\\|\.\.%2f', re.IGNORECASE),
    # Numeric ID - just a number (potential IDOR/SQLi)
    "numeric_id": re.compile(r'^\d+$'),
    # Command indicators
    "command_like": re.compile(r'^[\w\-]+\s|;|\||`|\$\(|&&', re.IGNORECASE),
    # Template/code injection indicators
    "template_like": re.compile(r'\{\{|\$\{|\%\{|<%|<\?', re.IGNORECASE),    # API key patterns - looks like an API key/token
    "api_key_value": re.compile(r'^[a-zA-Z0-9_\-]{20,}$|^sk_|^pk_|^api_|^key_|^token_', re.IGNORECASE),
    # Suspicious keywords in values - debug/internal/test credentials
    "suspicious_value": re.compile(r'internal|admin|test|debug|dev|staging|secret|private|root|super|master|default|sample|example|demo|temp|tmp|backup', re.IGNORECASE),
    # Email in value (potential user enumeration)
    "email_value": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),}

# Low-value parameter values that should reduce confidence
LOW_VALUE_PATTERNS = [
    re.compile(r'^(true|false|yes|no|on|off|0|1)$', re.IGNORECASE),
    re.compile(r'^(asc|desc|ascending|descending)$', re.IGNORECASE),
    re.compile(r'^(collapsed|expanded|grid|list|table|card)$', re.IGNORECASE),
    re.compile(r'^(en|es|fr|de|zh|ja|ru|pt|it|nl|ko|ar|default)$', re.IGNORECASE),  # Languages
    re.compile(r'^[\w\-]+\.(jpg|jpeg|png|gif|svg|css|js|ico|woff|woff2)$', re.IGNORECASE),  # Static files
]


def get_url_signature(url: str, path: str, params: Dict[str, List[str]]) -> str:
    """
    Generate a signature for a URL by normalizing parameter values.
    
    This groups URLs that differ only in numeric ID values, like:
    - /product?id=123 and /product?id=456 -> same signature
    - /user?id=1&name=john and /user?id=2&name=jane -> same signature
    
    Returns a string signature for grouping similar URLs.
    """
    # Normalize parameter values
    normalized_params = []
    for key in sorted(params.keys()):
        values = params[key]
        # Normalize numeric values to placeholder
        normalized_values = []
        for v in values:
            if VALUE_PATTERNS["numeric_id"].match(v):
                normalized_values.append("<NUM>")
            elif VALUE_PATTERNS["url_value"].search(v):
                normalized_values.append("<URL>")
            else:
                # Keep first 20 chars of non-numeric values for grouping
                normalized_values.append(v[:20] if len(v) > 20 else v)
        normalized_params.append(f"{key}={'|'.join(sorted(set(normalized_values)))}")
    
    # Extract domain from URL
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
    except:
        domain = ""
    
    # Signature = domain + path + normalized params
    return f"{domain}{path}?{'&'.join(normalized_params)}"


@dataclass
class MatchedURL:
    """Represents a URL that matched one or more vulnerability patterns."""
    url: str
    domain: str
    path: str
    params: Dict[str, List[str]]
    categories: List[str] = field(default_factory=list)
    severities: List[Severity] = field(default_factory=list)
    matched_patterns: Dict[str, List[str]] = field(default_factory=dict)
    highest_severity: Severity = Severity.LOW
    confidence: float = 0.0  # 0.0 to 1.0 confidence score
    confidence_reasons: List[str] = field(default_factory=list)
    # URL Intelligence fields
    intelligence_score: float = 0.0  # -1.0 (boring) to +1.0 (juicy)
    intelligence_reasons: List[str] = field(default_factory=list)
    classification: str = "neutral"  # boring, neutral, interesting, juicy
    # Secret Detection fields
    detected_secrets: List[SecretMatch] = field(default_factory=list)
    has_secrets: bool = False
    
    def __post_init__(self):
        if self.severities:
            severity_order = [Severity.HIGH, Severity.MEDIUM, Severity.LOW]
            for sev in severity_order:
                if sev in self.severities:
                    self.highest_severity = sev
                    break
        # Check if we have secrets
        if self.detected_secrets:
            self.has_secrets = True
            # Secrets always bump to HIGH severity
            self.highest_severity = Severity.HIGH
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON output."""
        return {
            "url": self.url,
            "domain": self.domain,
            "path": self.path,
            "params": self.params,
            "categories": self.categories,
            "severity": self.highest_severity.value,
            "matched_patterns": self.matched_patterns,
            "confidence": self.confidence,
            "confidence_reasons": self.confidence_reasons,
            "intelligence_score": self.intelligence_score,
            "intelligence_reasons": self.intelligence_reasons,
            "classification": self.classification,
            "has_secrets": self.has_secrets,
            "detected_secrets": [
                {"type": s.secret_type, "param": s.param_name, "value": s.value, 
                 "severity": s.severity, "description": s.description}
                for s in self.detected_secrets
            ] if self.detected_secrets else [],
        }


@dataclass
class AnalysisResult:
    """Contains the complete analysis results."""
    total_urls: int = 0
    unique_urls: int = 0
    matched_urls: int = 0
    dedupe_removed: int = 0  # URLs removed by smart deduplication
    boring_filtered: int = 0  # URLs filtered by intelligence (boring)
    secrets_found: int = 0  # URLs with potential secrets
    categorized: Dict[str, List[MatchedURL]] = field(default_factory=lambda: defaultdict(list))
    by_severity: Dict[Severity, List[MatchedURL]] = field(default_factory=lambda: defaultdict(list))
    by_domain: Dict[str, List[MatchedURL]] = field(default_factory=lambda: defaultdict(list))
    by_classification: Dict[str, List[MatchedURL]] = field(default_factory=lambda: defaultdict(list))
    urls_with_secrets: List[MatchedURL] = field(default_factory=list)
    all_matches: List[MatchedURL] = field(default_factory=list)
    
    def get_stats(self) -> Dict:
        """Get analysis statistics."""
        stats = {
            "total_urls_processed": self.total_urls,
            "unique_urls": self.unique_urls,
            "matched_urls": self.matched_urls,
            "by_severity": {
                sev.value: len(urls) for sev, urls in self.by_severity.items()
            },
            "by_category": {
                cat: len(urls) for cat, urls in self.categorized.items()
            },
            "by_classification": {
                cls: len(urls) for cls, urls in self.by_classification.items()
            },
            "domains_found": len(self.by_domain),
        }
        if self.dedupe_removed > 0:
            stats["similar_urls_removed"] = self.dedupe_removed
        if self.boring_filtered > 0:
            stats["boring_urls_filtered"] = self.boring_filtered
        if self.secrets_found > 0:
            stats["potential_secrets_found"] = self.secrets_found
        return stats


class URLAnalyzer:
    """Analyzes URLs and categorizes them by potential vulnerability type."""
    
    def __init__(self, pattern_manager: Optional[PatternManager] = None):
        self.pattern_manager = pattern_manager or PatternManager()
        self.seen_urls: Set[str] = set()
        
    def normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        url = url.strip()
        # Remove trailing slashes for consistency
        if url.endswith('/') and url.count('/') > 3:
            url = url.rstrip('/')
        return url
    
    def parse_url(self, url: str) -> Tuple[str, str, str, Dict[str, List[str]]]:
        """Parse URL into components."""
        try:
            # Handle URLs without scheme
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            domain = parsed.netloc
            path = unquote(parsed.path)
            query = parsed.query
            
            # Parse query parameters
            params = parse_qs(query, keep_blank_values=True)
            
            # Also check for path-based parameters (e.g., /page/1, /user/123)
            # These are handled in pattern matching
            
            return url, domain, path, params
            
        except Exception:
            return url, "", "", {}
    
    def _calculate_param_confidence(self, param_name: str, param_values: List[str], category: str) -> Tuple[float, List[str]]:
        """
        Calculate confidence score for a parameter match based on its value.
        
        Returns:
            Tuple of (confidence_boost, list of reasons)
        """
        confidence = 0.0
        reasons = []
        
        for value in param_values:
            if not value:
                continue
            
            # Check if value looks low-quality (common boring values)
            is_low_value = False
            for low_pattern in LOW_VALUE_PATTERNS:
                if low_pattern.match(value):
                    is_low_value = True
                    break
            
            if is_low_value:
                confidence -= 0.2
                continue
            
            # Check for high-value patterns based on category
            if category in ['ssrf', 'redirect']:
                if VALUE_PATTERNS['url_value'].search(value):
                    confidence += 0.5
                    reasons.append(f"value looks like URL: {param_name}={value[:50]}")
            
            if category in ['lfi_rfi']:
                if VALUE_PATTERNS['file_path'].search(value):
                    confidence += 0.5
                    reasons.append(f"value looks like file path: {param_name}={value[:50]}")
            
            if category in ['sqli', 'idor']:
                if VALUE_PATTERNS['numeric_id'].match(value):
                    confidence += 0.3
                    reasons.append(f"numeric ID: {param_name}={value}")
            
            if category in ['rce']:
                if VALUE_PATTERNS['command_like'].search(value):
                    confidence += 0.5
                    reasons.append(f"command-like value: {param_name}")
            
            if category in ['ssti']:
                if VALUE_PATTERNS['template_like'].search(value):
                    confidence += 0.5
                    reasons.append(f"template syntax in value: {param_name}")
            
            # Check for suspicious values in ANY category
            if VALUE_PATTERNS['suspicious_value'].search(value):
                confidence += 0.4
                reasons.append(f"suspicious value '{value[:30]}' in {param_name}")
            
            # Check for API key-like values
            if VALUE_PATTERNS['api_key_value'].match(value):
                confidence += 0.3
                reasons.append(f"API key-like value in {param_name}")
        
        return confidence, reasons
    
    def match_url(self, url: str, categories: Optional[List[str]] = None, min_confidence: float = 0.0, use_intelligence: bool = True, detect_secrets: bool = True) -> Optional[MatchedURL]:
        """
        Check if URL matches any vulnerability patterns with confidence scoring.
        
        Args:
            url: The URL to analyze
            categories: Optional list of categories to filter by
            min_confidence: Minimum confidence score to return match (0.0-1.0)
            use_intelligence: Whether to apply URL intelligence scoring
            detect_secrets: Whether to scan for leaked secrets/API keys
        
        Returns:
            MatchedURL if matches found, None otherwise
        """
        url, domain, path, params = self.parse_url(url)
        
        if not domain and not path:
            return None
        
        # Run URL intelligence analysis first
        intel_score, intel_reasons, classification = URLIntelligence.analyze(url, domain, path, params)
        
        # Detect secrets in parameters
        detected_secrets = []
        if detect_secrets and params:
            detected_secrets = SecretDetector.detect_secrets(params, url)
            if detected_secrets:
                # Boost intelligence score for URLs with secrets
                secret_boost = SecretDetector.get_severity_score(detected_secrets)
                intel_score = min(1.0, intel_score + secret_boost)
                intel_reasons.append(f"🔑 {len(detected_secrets)} potential secret(s) detected!")
                classification = "juicy"  # URLs with secrets are always juicy
        
        # Full URL for pattern matching (includes query string)
        full_url = url
        
        matched_categories = []
        matched_severities = []
        matched_patterns_detail = defaultdict(list)
        category_confidence = {}
        all_confidence_reasons = []
        
        patterns = self.pattern_manager.get_all_patterns()
        
        # Filter by categories if specified
        if categories:
            patterns = {k: v for k, v in patterns.items() if k in categories}
        
        for cat_name, pattern in patterns.items():
            path_matched = False
            param_matched = False
            param_name_matched = None
            ext_matched = False
            base_confidence = 0.3  # Start with base confidence
            confidence_reasons = []
            
            # First check exclusions - if any exclude pattern matches, skip this category
            excluded = False
            for compiled in pattern.compiled_exclude:
                if compiled.search(full_url) or compiled.search(path):
                    excluded = True
                    break
            
            if excluded:
                continue
            
            # Check path patterns
            for compiled in pattern.compiled_path:
                if compiled.search(path) or compiled.search(full_url):
                    path_matched = True
                    matched_patterns_detail[cat_name].append(f"path:{compiled.pattern}")
                    base_confidence += 0.2  # Path match adds confidence
                    confidence_reasons.append(f"path matches {compiled.pattern}")
                    break
            
            # Check parameter patterns AND their values
            for param_name, param_values in params.items():
                for compiled in pattern.compiled_param:
                    if compiled.match(param_name):
                        param_matched = True
                        param_name_matched = param_name
                        matched_patterns_detail[cat_name].append(f"param:{param_name}")
                        
                        # Calculate confidence based on parameter value
                        value_confidence, value_reasons = self._calculate_param_confidence(
                            param_name, param_values, cat_name
                        )
                        base_confidence += value_confidence
                        confidence_reasons.extend(value_reasons)
                        break
                if param_matched:
                    break
            
            # Check extension patterns
            for compiled in pattern.compiled_ext:
                if compiled.search(path):
                    ext_matched = True
                    matched_patterns_detail[cat_name].append(f"ext:{compiled.pattern}")
                    base_confidence += 0.1
                    break
            
            # Determine if this is a valid match
            if pattern.require_params:
                matched = param_matched
            else:
                matched = path_matched or param_matched or ext_matched
            
            if matched:
                # Clamp confidence to 0.0-1.0
                final_confidence = max(0.0, min(1.0, base_confidence))
                
                # Only include if meets minimum confidence
                if final_confidence >= min_confidence:
                    matched_categories.append(cat_name)
                    matched_severities.append(pattern.severity)
                    category_confidence[cat_name] = final_confidence
                    all_confidence_reasons.extend(confidence_reasons)
        
        if matched_categories:
            # Calculate overall confidence as weighted average
            overall_confidence = sum(category_confidence.values()) / len(category_confidence)
            
            # Apply intelligence score adjustment to confidence
            if use_intelligence:
                # Intel score ranges from -1 to +1, scale it to affect confidence
                # Boring URLs (-1) reduce confidence, juicy URLs (+1) increase it
                intel_adjustment = intel_score * 0.3  # Max ±0.3 adjustment
                overall_confidence = max(0.0, min(1.0, overall_confidence + intel_adjustment))
            
            # Boost confidence significantly if secrets detected
            if detected_secrets:
                overall_confidence = min(1.0, overall_confidence + 0.4)
                for secret in detected_secrets:
                    all_confidence_reasons.append(f"🔑 {secret.description}")
                # Add leaked_secrets to categories if not already there
                if 'leaked_secrets' not in matched_categories:
                    matched_categories.append('leaked_secrets')
                    matched_severities.append(Severity.HIGH)
            
            return MatchedURL(
                url=url,
                domain=domain,
                path=path,
                params=params,
                categories=matched_categories,
                severities=matched_severities,
                matched_patterns=dict(matched_patterns_detail),
                confidence=round(overall_confidence, 2),
                confidence_reasons=list(set(all_confidence_reasons)),  # Dedupe reasons
                intelligence_score=round(intel_score, 2),
                intelligence_reasons=intel_reasons,
                classification=classification,
                detected_secrets=detected_secrets,
            )
        
        # Even if no pattern matched, return if secrets were found
        if detected_secrets:
            return MatchedURL(
                url=url,
                domain=domain,
                path=path,
                params=params,
                categories=['leaked_secrets'],
                severities=[Severity.HIGH],
                matched_patterns={'leaked_secrets': [f"secret:{s.secret_type}" for s in detected_secrets]},
                confidence=0.9,  # High confidence for secrets
                confidence_reasons=[f"🔑 {s.description}" for s in detected_secrets],
                intelligence_score=round(intel_score, 2),
                intelligence_reasons=intel_reasons,
                classification="juicy",
                detected_secrets=detected_secrets,
            )
        
        return None
    
    def analyze_urls(
        self,
        urls: List[str],
        categories: Optional[List[str]] = None,
        deduplicate: bool = True,
        min_severity: Optional[Severity] = None,
        min_confidence: float = 0.0,
        smart_dedupe: bool = True,
        max_per_pattern: int = 5,
        smart_filter: bool = True,
        hide_boring: bool = True,
        detect_secrets: bool = True,
    ) -> AnalysisResult:
        """
        Analyze a list of URLs.
        
        Args:
            urls: List of URLs to analyze
            categories: Optional list of categories to filter by
            deduplicate: Whether to remove duplicate URLs
            min_severity: Minimum severity level to include
            min_confidence: Minimum confidence score (0.0-1.0)
            smart_dedupe: Group similar URLs (differ only in param values) and keep max N
            max_per_pattern: Maximum URLs to keep per similar pattern (default 5)
            smart_filter: Use URL intelligence to boost/reduce confidence
            hide_boring: Filter out URLs classified as 'boring' by intelligence
            detect_secrets: Scan for leaked API keys, tokens, and secrets
        
        Returns:
            AnalysisResult containing categorized matches
        """
        result = AnalysisResult()
        result.total_urls = len(urls)
        
        severity_order = {
            Severity.HIGH: 0,
            Severity.MEDIUM: 1,
            Severity.LOW: 2,
        }
        
        # Track URL signatures for smart deduplication
        signature_counts: Dict[str, int] = defaultdict(int)
        
        for url in urls:
            url = self.normalize_url(url)
            
            if not url:
                continue
            
            # Deduplication
            if deduplicate:
                if url in self.seen_urls:
                    continue
                self.seen_urls.add(url)
            
            result.unique_urls += 1
            
            # Analyze URL with confidence filtering, intelligence, and secret detection
            match = self.match_url(url, categories, min_confidence, use_intelligence=smart_filter, detect_secrets=detect_secrets)
            
            if match:
                # NEVER filter URLs with secrets, even if boring
                if hide_boring and match.classification == "boring" and not match.has_secrets:
                    result.boring_filtered += 1
                    continue
                
                # Filter by minimum severity if specified (but not if has secrets)
                if min_severity and not match.has_secrets:
                    if severity_order[match.highest_severity] > severity_order[min_severity]:
                        continue
                
                # Smart deduplication: limit similar URLs
                if smart_dedupe and match.params:
                    signature = get_url_signature(match.url, match.path, match.params)
                    signature_counts[signature] += 1
                    
                    if signature_counts[signature] > max_per_pattern:
                        result.dedupe_removed += 1
                        continue
                
                result.matched_urls += 1
                result.all_matches.append(match)
                
                # Track URLs with secrets
                if match.has_secrets:
                    result.secrets_found += 1
                    result.urls_with_secrets.append(match)
                
                # Categorize by vulnerability type
                for cat in match.categories:
                    result.categorized[cat].append(match)
                
                # Categorize by severity
                result.by_severity[match.highest_severity].append(match)
                
                # Categorize by domain
                result.by_domain[match.domain].append(match)
                
                # Categorize by classification
                result.by_classification[match.classification].append(match)
        
        # Sort all matches by: secrets first, then confidence, then intelligence score
        result.all_matches.sort(key=lambda x: (x.has_secrets, x.confidence, x.intelligence_score), reverse=True)
        
        return result
    
    def analyze_from_file(
        self,
        filepath: str,
        categories: Optional[List[str]] = None,
        deduplicate: bool = True,
        min_severity: Optional[Severity] = None,
    ) -> AnalysisResult:
        """Analyze URLs from a file."""
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip()]
        return self.analyze_urls(urls, categories, deduplicate, min_severity)
    
    def reset(self):
        """Reset the analyzer state."""
        self.seen_urls.clear()


class CustomPatternMatcher:
    """Allows users to define custom regex patterns for matching."""
    
    def __init__(self):
        self.custom_patterns: List[Tuple[str, re.Pattern]] = []
    
    def add_pattern(self, name: str, pattern: str):
        """Add a custom regex pattern."""
        compiled = re.compile(pattern, re.IGNORECASE)
        self.custom_patterns.append((name, compiled))
    
    def match(self, url: str) -> List[Tuple[str, str]]:
        """Match URL against custom patterns."""
        matches = []
        for name, pattern in self.custom_patterns:
            if pattern.search(url):
                matches.append((name, pattern.pattern))
        return matches
    
    def load_from_file(self, filepath: str):
        """Load custom patterns from a file (format: name:regex per line)."""
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if ':' in line:
                        name, pattern = line.split(':', 1)
                        self.add_pattern(name.strip(), pattern.strip())
