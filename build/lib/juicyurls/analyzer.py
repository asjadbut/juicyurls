"""
URL Analyzer - Core logic for parsing and categorizing URLs.
"""

import re
from urllib.parse import urlparse, parse_qs, unquote
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict

from .patterns import PatternManager, VulnPattern, Severity


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
    highest_severity: Severity = Severity.INFO
    
    def __post_init__(self):
        if self.severities:
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
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
        }


@dataclass
class AnalysisResult:
    """Contains the complete analysis results."""
    total_urls: int = 0
    unique_urls: int = 0
    matched_urls: int = 0
    categorized: Dict[str, List[MatchedURL]] = field(default_factory=lambda: defaultdict(list))
    by_severity: Dict[Severity, List[MatchedURL]] = field(default_factory=lambda: defaultdict(list))
    by_domain: Dict[str, List[MatchedURL]] = field(default_factory=lambda: defaultdict(list))
    all_matches: List[MatchedURL] = field(default_factory=list)
    
    def get_stats(self) -> Dict:
        """Get analysis statistics."""
        return {
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
    
    def match_url(self, url: str, categories: Optional[List[str]] = None) -> Optional[MatchedURL]:
        """
        Check if URL matches any vulnerability patterns.
        
        Args:
            url: The URL to analyze
            categories: Optional list of categories to filter by
        
        Returns:
            MatchedURL if matches found, None otherwise
        """
        url, domain, path, params = self.parse_url(url)
        
        if not domain and not path:
            return None
        
        matched_categories = []
        matched_severities = []
        matched_patterns_detail = defaultdict(list)
        
        patterns = self.pattern_manager.get_all_patterns()
        
        # Filter by categories if specified
        if categories:
            patterns = {k: v for k, v in patterns.items() if k in categories}
        
        for cat_name, pattern in patterns.items():
            matched = False
            
            # Check path patterns
            for compiled in pattern.compiled_path:
                if compiled.search(path):
                    matched = True
                    matched_patterns_detail[cat_name].append(f"path:{compiled.pattern}")
                    break
            
            # Check parameter patterns
            for param_name in params.keys():
                for compiled in pattern.compiled_param:
                    if compiled.match(param_name):
                        matched = True
                        matched_patterns_detail[cat_name].append(f"param:{param_name}")
                        break
                if matched and cat_name in matched_patterns_detail:
                    break
            
            # Check extension patterns
            for compiled in pattern.compiled_ext:
                if compiled.search(path):
                    matched = True
                    matched_patterns_detail[cat_name].append(f"ext:{compiled.pattern}")
                    break
            
            if matched:
                matched_categories.append(cat_name)
                matched_severities.append(pattern.severity)
        
        if matched_categories:
            return MatchedURL(
                url=url,
                domain=domain,
                path=path,
                params=params,
                categories=matched_categories,
                severities=matched_severities,
                matched_patterns=dict(matched_patterns_detail),
            )
        
        return None
    
    def analyze_urls(
        self,
        urls: List[str],
        categories: Optional[List[str]] = None,
        deduplicate: bool = True,
        min_severity: Optional[Severity] = None,
    ) -> AnalysisResult:
        """
        Analyze a list of URLs.
        
        Args:
            urls: List of URLs to analyze
            categories: Optional list of categories to filter by
            deduplicate: Whether to remove duplicate URLs
            min_severity: Minimum severity level to include
        
        Returns:
            AnalysisResult containing categorized matches
        """
        result = AnalysisResult()
        result.total_urls = len(urls)
        
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        
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
            
            # Analyze URL
            match = self.match_url(url, categories)
            
            if match:
                # Filter by minimum severity if specified
                if min_severity:
                    if severity_order[match.highest_severity] > severity_order[min_severity]:
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
