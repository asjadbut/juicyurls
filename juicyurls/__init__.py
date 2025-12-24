"""
JuicyURLs - A powerful URL filtering tool for security researchers and bug bounty hunters.

Filters URLs from waybackurls/gau output to identify potentially vulnerable endpoints.
"""

__version__ = "1.0.0"
__author__ = "Security Researcher"
__description__ = "Find juicy URLs for bug bounty hunting"

from .analyzer import URLAnalyzer
from .patterns import PatternManager
from .output import OutputFormatter

__all__ = ["URLAnalyzer", "PatternManager", "OutputFormatter"]
