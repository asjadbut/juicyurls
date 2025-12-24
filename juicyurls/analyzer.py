"""
URL Analyzer - Core logic for parsing and categorizing URLs.

Features:
- Context-aware matching (checks parameter VALUES, not just names)
- Confidence scoring to reduce false positives
- Smart deduplication (groups similar URLs)
"""

import re
from urllib.parse import urlparse, parse_qs, unquote
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict

from .patterns import PatternManager, VulnPattern, Severity


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
    
    def __post_init__(self):
        if self.severities:
            severity_order = [Severity.HIGH, Severity.MEDIUM, Severity.LOW]
            for sev in severity_order:
                if sev in self.severities:
                    self.highest_severity = sev
                    break
    
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
        }


@dataclass
class AnalysisResult:
    """Contains the complete analysis results."""
    total_urls: int = 0
    unique_urls: int = 0
    matched_urls: int = 0
    dedupe_removed: int = 0  # URLs removed by smart deduplication
    categorized: Dict[str, List[MatchedURL]] = field(default_factory=lambda: defaultdict(list))
    by_severity: Dict[Severity, List[MatchedURL]] = field(default_factory=lambda: defaultdict(list))
    by_domain: Dict[str, List[MatchedURL]] = field(default_factory=lambda: defaultdict(list))
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
            "domains_found": len(self.by_domain),
        }
        if self.dedupe_removed > 0:
            stats["similar_urls_removed"] = self.dedupe_removed
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
    
    def match_url(self, url: str, categories: Optional[List[str]] = None, min_confidence: float = 0.0) -> Optional[MatchedURL]:
        """
        Check if URL matches any vulnerability patterns with confidence scoring.
        
        Args:
            url: The URL to analyze
            categories: Optional list of categories to filter by
            min_confidence: Minimum confidence score to return match (0.0-1.0)
        
        Returns:
            MatchedURL if matches found, None otherwise
        """
        url, domain, path, params = self.parse_url(url)
        
        if not domain and not path:
            return None
        
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
            
            # Analyze URL with confidence filtering
            match = self.match_url(url, categories, min_confidence)
            
            if match:
                # Filter by minimum severity if specified
                if min_severity:
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
                
                # Categorize by vulnerability type
                for cat in match.categories:
                    result.categorized[cat].append(match)
                
                # Categorize by severity
                result.by_severity[match.highest_severity].append(match)
                
                # Categorize by domain
                result.by_domain[match.domain].append(match)
        
        # Sort all matches by confidence (highest first)
        result.all_matches.sort(key=lambda x: x.confidence, reverse=True)
        
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
