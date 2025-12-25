"""
Output formatters for displaying analysis results.
"""

import io
import sys
from typing import List, Dict, Optional, TextIO
from dataclasses import dataclass
from enum import Enum

from .analyzer import AnalysisResult, MatchedURL
from .patterns import Severity


class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    
    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Bright foreground colors
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


class OutputFormat(Enum):
    PLAIN = "plain"
    URLS_ONLY = "urls"


@dataclass
class OutputConfig:
    """Configuration for output formatting."""
    format: OutputFormat = OutputFormat.PLAIN
    color: bool = True
    show_stats: bool = True
    verbose: bool = False
    output_file: Optional[str] = None
    show_intel: bool = False  # Show URL intelligence info


class OutputFormatter:
    """Handles formatting and output of analysis results."""
    
    SEVERITY_COLORS = {
        Severity.HIGH: Colors.RED + Colors.BOLD,
        Severity.MEDIUM: Colors.YELLOW,
        Severity.LOW: Colors.CYAN,
    }
    
    SEVERITY_ICONS = {
        Severity.HIGH: "🔴",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
    }
    
    # Classification icons and colors
    CLASSIFICATION_ICONS = {
        "juicy": "🧃",
        "interesting": "✨",
        "neutral": "➖",
        "boring": "💤",
    }
    
    CLASSIFICATION_COLORS = {
        "juicy": Colors.BRIGHT_GREEN + Colors.BOLD,
        "interesting": Colors.GREEN,
        "neutral": Colors.WHITE,
        "boring": Colors.DIM,
    }
    
    def __init__(self, config: Optional[OutputConfig] = None):
        self.config = config or OutputConfig()
        self._check_color_support()
    
    def _check_color_support(self):
        """Check if terminal supports colors."""
        if not self.config.color:
            return
        
        # Disable colors if not a TTY or on Windows without proper support
        if not sys.stdout.isatty():
            self.config.color = False
        elif sys.platform == "win32":
            # Enable ANSI colors on Windows 10+
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                self.config.color = False
    
    def _colorize(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if self.config.color:
            return f"{color}{text}{Colors.RESET}"
        return text
    
    def _severity_color(self, severity: Severity) -> str:
        """Get color for severity level."""
        return self.SEVERITY_COLORS.get(severity, "")
    
    def _format_severity(self, severity: Severity) -> str:
        """Format severity with color and icon."""
        icon = self.SEVERITY_ICONS.get(severity, "")
        color = self._severity_color(severity)
        text = severity.value.upper()
        if self.config.color:
            return f"{icon} {color}{text}{Colors.RESET}"
        return f"[{text}]"
    
    def _print_banner(self, output: TextIO):
        """Print the tool banner."""
        banner = """
     ██╗██╗   ██╗██╗ ██████╗██╗   ██╗██╗   ██╗██████╗ ██╗     ███████╗
     ██║██║   ██║██║██╔════╝╚██╗ ██╔╝██║   ██║██╔══██╗██║     ██╔════╝
     ██║██║   ██║██║██║      ╚████╔╝ ██║   ██║██████╔╝██║     ███████╗
██   ██║██║   ██║██║██║       ╚██╔╝  ██║   ██║██╔══██╗██║     ╚════██║
╚█████╔╝╚██████╔╝██║╚██████╗   ██║   ╚██████╔╝██║  ██║███████╗███████║
 ╚════╝  ╚═════╝ ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
                                                                      
        🎯 Bug Bounty URL Analyzer - Find the Juice! 🧃
"""
        if self.config.color:
            output.write(self._colorize(banner, Colors.BRIGHT_GREEN))
        else:
            output.write(banner)
        output.write("\n")
    
    def _print_stats(self, result: AnalysisResult, output: TextIO):
        """Print analysis statistics."""
        stats = result.get_stats()
        
        output.write(self._colorize("\n📊 Analysis Statistics\n", Colors.BOLD))
        output.write(self._colorize("=" * 50 + "\n", Colors.DIM))
        
        output.write(f"  Total URLs processed: {self._colorize(str(stats['total_urls_processed']), Colors.BRIGHT_WHITE)}\n")
        output.write(f"  Unique URLs: {self._colorize(str(stats['unique_urls']), Colors.BRIGHT_WHITE)}\n")
        output.write(f"  Matched URLs: {self._colorize(str(stats['matched_urls']), Colors.BRIGHT_GREEN)}\n")
        if 'similar_urls_removed' in stats:
            output.write(f"  Similar URLs grouped: {self._colorize(str(stats['similar_urls_removed']), Colors.DIM)} (kept max per pattern)\n")
        if 'boring_urls_filtered' in stats:
            output.write(f"  Boring URLs filtered: {self._colorize(str(stats['boring_urls_filtered']), Colors.DIM)} (static/tracking/CDN)\n")
        if 'potential_secrets_found' in stats and stats['potential_secrets_found'] > 0:
            output.write(f"  🔑 SECRETS FOUND: {self._colorize(str(stats['potential_secrets_found']), Colors.BRIGHT_RED + Colors.BOLD)} (check immediately!)\n")
        output.write(f"  Domains found: {self._colorize(str(stats['domains_found']), Colors.BRIGHT_CYAN)}\n")
        
        output.write(self._colorize("\n  By Severity:\n", Colors.UNDERLINE))
        for sev_name, count in stats['by_severity'].items():
            if count > 0:
                sev = Severity(sev_name)
                color = self._severity_color(sev)
                output.write(f"    {self._colorize(sev_name.upper(), color)}: {count}\n")
        
        # Show classification stats if available
        if 'by_classification' in stats and stats['by_classification']:
            output.write(self._colorize("\n  By Intelligence:\n", Colors.UNDERLINE))
            class_order = ['juicy', 'interesting', 'neutral', 'boring']
            for cls in class_order:
                count = stats['by_classification'].get(cls, 0)
                if count > 0:
                    icon = self.CLASSIFICATION_ICONS.get(cls, "")
                    output.write(f"    {icon} {cls}: {count}\n")
        
        output.write(self._colorize("\n  By Category:\n", Colors.UNDERLINE))
        # Sort by count descending
        sorted_cats = sorted(stats['by_category'].items(), key=lambda x: x[1], reverse=True)
        for cat, count in sorted_cats:
            if count > 0:
                output.write(f"    {cat}: {count}\n")
        
        output.write("\n")
    
    def format_plain(self, result: AnalysisResult, output: TextIO):
        """Format output as plain text with colors."""
        if self.config.show_stats:
            self._print_banner(output)
            self._print_stats(result, output)
        
        # Always group by severity
        self._format_by_severity(result, output)
    
    def _format_by_severity(self, result: AnalysisResult, output: TextIO):
        """Format results grouped by severity."""
        severity_order = [Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        
        for severity in severity_order:
            urls = result.by_severity.get(severity, [])
            if not urls:
                continue
            
            header = f"\n{self._format_severity(severity)} ({len(urls)} URLs)\n"
            output.write(header)
            output.write(self._colorize("-" * 60 + "\n", Colors.DIM))
            
            for match in urls:
                self._format_match(match, output)
    
    def _format_by_category(self, result: AnalysisResult, output: TextIO):
        """Format results grouped by category."""
        for category, urls in sorted(result.categorized.items()):
            if not urls:
                continue
            
            header = f"\n🏷️  {self._colorize(category.upper(), Colors.BOLD + Colors.BRIGHT_CYAN)} ({len(urls)} URLs)\n"
            output.write(header)
            output.write(self._colorize("-" * 60 + "\n", Colors.DIM))
            
            for match in urls:
                self._format_match(match, output)
    
    def _format_by_domain(self, result: AnalysisResult, output: TextIO):
        """Format results grouped by domain."""
        for domain, urls in sorted(result.by_domain.items()):
            if not urls:
                continue
            
            header = f"\n🌐 {self._colorize(domain, Colors.BOLD + Colors.BRIGHT_BLUE)} ({len(urls)} URLs)\n"
            output.write(header)
            output.write(self._colorize("-" * 60 + "\n", Colors.DIM))
            
            for match in urls:
                self._format_match(match, output)
    
    def _format_all(self, result: AnalysisResult, output: TextIO):
        """Format all results without grouping."""
        for match in result.all_matches:
            self._format_match(match, output)
    
    def _format_match(self, match: MatchedURL, output: TextIO):
        """Format a single matched URL."""
        severity_str = self._format_severity(match.highest_severity)
        
        # Format confidence indicator
        if match.confidence >= 0.7:
            conf_indicator = self._colorize("★★★", Colors.BRIGHT_GREEN)
        elif match.confidence >= 0.5:
            conf_indicator = self._colorize("★★☆", Colors.YELLOW)
        elif match.confidence >= 0.3:
            conf_indicator = self._colorize("★☆☆", Colors.DIM)
        else:
            conf_indicator = self._colorize("☆☆☆", Colors.DIM)
        
        # Format classification indicator
        class_icon = self.CLASSIFICATION_ICONS.get(match.classification, "")
        class_color = self.CLASSIFICATION_COLORS.get(match.classification, "")
        
        # Check if URL has secrets
        has_secrets = getattr(match, 'has_secrets', False)
        detected_secrets = getattr(match, 'detected_secrets', [])
        secret_indicator = ""
        if has_secrets:
            secret_indicator = self._colorize(" 🔑 SECRET", Colors.BRIGHT_RED + Colors.BOLD)
        
        if self.config.verbose:
            output.write(f"\n  {severity_str} {conf_indicator} (confidence: {match.confidence:.0%}){secret_indicator}\n")
            output.write(f"  URL: {self._colorize(match.url, Colors.BRIGHT_WHITE)}\n")
            output.write(f"  Categories: {', '.join(match.categories)}\n")
            if match.params:
                output.write(f"  Parameters: {', '.join(match.params.keys())}\n")
            if match.confidence_reasons:
                output.write(f"  Why: {'; '.join(match.confidence_reasons[:3])}\n")
            # Show detected secrets
            if detected_secrets:
                output.write(self._colorize("  🔑 DETECTED SECRETS:\n", Colors.BRIGHT_RED + Colors.BOLD))
                for secret in detected_secrets:
                    secret_type = secret.get('secret_type', 'unknown') if isinstance(secret, dict) else getattr(secret, 'secret_type', 'unknown')
                    masked = secret.get('masked_value', '***') if isinstance(secret, dict) else getattr(secret, 'masked_value', '***')
                    location = secret.get('location', '') if isinstance(secret, dict) else getattr(secret, 'location', '')
                    output.write(f"    ⚠️  {self._colorize(secret_type, Colors.YELLOW)}: {masked} (in {location})\n")
            # Show intelligence info if enabled or in verbose mode
            if self.config.show_intel or self.config.verbose:
                output.write(f"  Intelligence: {class_icon} {self._colorize(match.classification, class_color)} (score: {match.intelligence_score:+.2f})\n")
                if match.intelligence_reasons:
                    output.write(f"  Intel reasons: {'; '.join(match.intelligence_reasons[:4])}\n")
        else:
            categories = self._colorize(f"[{', '.join(match.categories)}]", Colors.CYAN)
            if has_secrets:
                output.write(f"  🔑 {conf_indicator} {match.url} {categories}\n")
            elif self.config.show_intel:
                output.write(f"  {conf_indicator} {class_icon} {match.url} {categories}\n")
            else:
                output.write(f"  {conf_indicator} {match.url} {categories}\n")
    
    def format_urls_only(self, result: AnalysisResult, output: TextIO):
        """Output only the URLs, one per line."""
        for match in result.all_matches:
            output.write(f"{match.url}\n")
    
    def output(self, result: AnalysisResult, output: Optional[TextIO] = None):
        """Output the analysis results in the configured format."""
        if output is None:
            output = sys.stdout
        
        formatters = {
            OutputFormat.PLAIN: self.format_plain,
            OutputFormat.URLS_ONLY: self.format_urls_only,
        }
        
        formatter = formatters.get(self.config.format, self.format_plain)
        
        # If output file specified, write there
        if self.config.output_file:
            with open(self.config.output_file, 'w', encoding='utf-8') as f:
                # Disable colors for file output
                original_color = self.config.color
                self.config.color = False
                formatter(result, f)
                self.config.color = original_color
            print(f"Results written to: {self.config.output_file}")
        else:
            formatter(result, output)
    
    def format_to_string(self, result: AnalysisResult) -> str:
        """Format results and return as string."""
        buffer = io.StringIO()
        self.output(result, buffer)
        return buffer.getvalue()
