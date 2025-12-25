#!/usr/bin/env python3
"""
JuicyURLs - Command Line Interface

A powerful URL filtering tool for security researchers and bug bounty hunters.
Filters URLs from waybackurls/gau to identify potentially vulnerable endpoints.
"""

import argparse
import sys
import subprocess
import shutil
import os
from typing import List, Optional

from .analyzer import URLAnalyzer
from .patterns import PatternManager, Severity
from .output import OutputFormatter, OutputConfig, OutputFormat


def get_version() -> str:
    """Get the tool version."""
    return "1.0.0"


def find_tool(tool: str) -> Optional[str]:
    """
    Find an external tool, checking multiple locations.
    
    Args:
        tool: Tool name (waybackurls, gau, etc.)
    
    Returns:
        Full path to the tool if found, None otherwise
    """
    # First, try shutil.which (checks PATH)
    tool_path = shutil.which(tool)
    if tool_path:
        return tool_path
    
    # On Windows, also try with .exe extension
    if sys.platform == 'win32' and not tool.endswith('.exe'):
        tool_path = shutil.which(tool + '.exe')
        if tool_path:
            return tool_path
    
    # Check common Go bin locations
    go_bin_paths = []
    
    # GOBIN environment variable
    gobin = os.environ.get('GOBIN')
    if gobin:
        go_bin_paths.append(gobin)
    
    # GOPATH/bin
    gopath = os.environ.get('GOPATH')
    if gopath:
        go_bin_paths.append(os.path.join(gopath, 'bin'))
    
    # Default Go bin location: ~/go/bin
    home = os.path.expanduser('~')
    go_bin_paths.append(os.path.join(home, 'go', 'bin'))
    
    # Check each Go bin path
    for bin_path in go_bin_paths:
        if sys.platform == 'win32':
            candidate = os.path.join(bin_path, tool + '.exe')
        else:
            candidate = os.path.join(bin_path, tool)
        
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    
    return None


def run_external_tool(tool: str, domain: str, extra_args: List[str] = None) -> List[str]:
    """
    Run an external URL gathering tool.
    
    Args:
        tool: Tool name (waybackurls, gau, etc.)
        domain: Target domain
        extra_args: Additional arguments for the tool
    
    Returns:
        List of URLs gathered
    """
    # Check if tool is available
    tool_path = find_tool(tool)
    if not tool_path:
        print(f"Error: {tool} not found in PATH. Please install it first.", file=sys.stderr)
        print(f"  Install waybackurls: go install github.com/tomnomnom/waybackurls@latest", file=sys.stderr)
        print(f"  Install gau: go install github.com/lc/gau/v2/cmd/gau@latest", file=sys.stderr)
        sys.exit(1)
    
    cmd = [tool_path]
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(domain)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        urls = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        return urls
    except subprocess.TimeoutExpired:
        print(f"Error: {tool} timed out", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Error running {tool}: {e}", file=sys.stderr)
        return []


def read_urls_from_stdin() -> List[str]:
    """Read URLs from stdin."""
    if sys.stdin.isatty():
        return []
    return [line.strip() for line in sys.stdin if line.strip()]


def read_urls_from_file(filepath: str) -> List[str]:
    """Read URLs from a file."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return []


def parse_severity(value: str) -> Optional[Severity]:
    """Parse severity string to enum."""
    try:
        return Severity(value.lower())
    except ValueError:
        return None


def list_categories(pattern_manager: PatternManager):
    """List all available categories with descriptions."""
    print("\n📋 Available Categories:\n")
    print("-" * 70)
    
    for name, pattern in sorted(pattern_manager.get_all_patterns().items()):
        severity_icon = {
            Severity.HIGH: "🔴",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
        }.get(pattern.severity, "")
        
        print(f"\n  {severity_icon} {name}")
        print(f"     Severity: {pattern.severity.value.upper()}")
        print(f"     {pattern.description}")
    
    print("\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog='juicyurls',
        description='''
🧃 JuicyURLs - Find the Juice in Bug Bounty URLs!

A powerful URL filtering tool for security researchers.
Filters URLs from waybackurls/gau to identify potentially vulnerable endpoints.

Examples:
  cat urls.txt | juicyurls
  juicyurls -f urls.txt
  gau example.com | juicyurls -c sqli idor ssrf
  juicyurls -d example.com --tool waybackurls
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Input options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument(
        '-f', '--file',
        help='Input file containing URLs (one per line)'
    )
    input_group.add_argument(
        '-d', '--domain',
        help='Domain to gather URLs for (requires external tool)'
    )
    input_group.add_argument(
        '--tool',
        choices=['waybackurls', 'gau', 'both'],
        default='gau',
        help='External tool to use for URL gathering (default: gau)'
    )
    
    # Filter options
    filter_group = parser.add_argument_group('Filter Options')
    filter_group.add_argument(
        '-c', '--categories',
        nargs='+',
        metavar='CAT',
        help='Filter by specific categories (e.g., sqli idor ssrf)'
    )
    filter_group.add_argument(
        '-s', '--severity',
        choices=['high', 'medium', 'low'],
        help='Minimum severity level to include'
    )
    filter_group.add_argument(
        '--exclude',
        nargs='+',
        metavar='CAT',
        help='Exclude specific categories'
    )
    filter_group.add_argument(
        '--no-dedupe',
        action='store_true',
        help='Do not remove duplicate URLs'
    )
    filter_group.add_argument(
        '--min-confidence',
        type=float,
        default=0.0,
        metavar='0.0-1.0',
        help='Minimum confidence score (0.0-1.0, default: 0.0). Higher = fewer false positives'
    )
    filter_group.add_argument(
        '--high-confidence',
        action='store_true',
        help='Only show high confidence results (equivalent to --min-confidence 0.5)'
    )
    filter_group.add_argument(
        '--no-smart-dedupe',
        action='store_true',
        help='Disable smart deduplication (keep all similar URLs that differ only in param values)'
    )
    filter_group.add_argument(
        '--max-per-pattern',
        type=int,
        default=1,
        metavar='N',
        help='Max URLs to keep per similar endpoint pattern (default: 1). Use with smart dedupe.'
    )
    filter_group.add_argument(
        '--interesting-files',
        action='store_true',
        help='Only show interesting files (backups, configs, source code leaks)'
    )
    
    # Intelligence/Smart filtering options
    smart_group = parser.add_argument_group('Smart Filtering (URL Intelligence)')
    smart_group.add_argument(
        '--no-smart',
        action='store_true',
        help='Disable URL intelligence (analyze all URLs equally without context)'
    )
    smart_group.add_argument(
        '--show-boring',
        action='store_true',
        help='Include boring URLs (static assets, tracking, CDN) that are normally filtered'
    )
    smart_group.add_argument(
        '--only-juicy',
        action='store_true',
        help='Only show URLs classified as "juicy" or "interesting" by intelligence'
    )
    smart_group.add_argument(
        '--show-intel',
        action='store_true',
        help='Show URL intelligence classification and reasons in output'
    )
    smart_group.add_argument(
        '--detect-secrets',
        action='store_true',
        default=True,
        help='Detect leaked secrets (API keys, tokens, JWTs) in URLs (default: enabled)'
    )
    smart_group.add_argument(
        '--no-secrets',
        action='store_true',
        help='Disable secret detection (faster processing)'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Output file (default: stdout)'
    )
    output_group.add_argument(
        '--format',
        choices=['plain', 'urls'],
        default='plain',
        help='Output format: plain (with stats) or urls (just URLs)'
    )
    output_group.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    output_group.add_argument(
        '--no-stats',
        action='store_true',
        help='Do not show statistics'
    )
    output_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output with match details'
    )
    output_group.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode - output URLs only'
    )
    
    # Other options
    parser.add_argument(
        '--list-categories',
        action='store_true',
        help='List all available categories and exit'
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {get_version()}'
    )
    
    args = parser.parse_args()
    
    # Initialize pattern manager
    pattern_manager = PatternManager()
    
    # List categories and exit
    if args.list_categories:
        list_categories(pattern_manager)
        return 0
    
    # Collect URLs
    urls = []
    
    # Read from stdin
    stdin_urls = read_urls_from_stdin()
    urls.extend(stdin_urls)
    
    # Read from file
    if args.file:
        file_urls = read_urls_from_file(args.file)
        urls.extend(file_urls)
    
    # Gather URLs using external tool
    if args.domain:
        print(f"🔍 Gathering URLs for {args.domain}...", file=sys.stderr)
        
        if args.tool == 'both':
            urls.extend(run_external_tool('waybackurls', args.domain))
            urls.extend(run_external_tool('gau', args.domain))
        else:
            urls.extend(run_external_tool(args.tool, args.domain))
        
        print(f"📥 Gathered {len(urls)} URLs", file=sys.stderr)
    
    # Check if we have any URLs
    if not urls:
        print("Error: No URLs provided. Use -f, -d, or pipe URLs to stdin.", file=sys.stderr)
        print("Use --help for usage information.", file=sys.stderr)
        return 1
    
    # Show analysis message
    if not args.quiet:
        print(f"🧃 Analyzing {len(urls)} URLs for juicy endpoints...", file=sys.stderr)
    
    # Prepare categories filter
    categories = args.categories
    
    # If --interesting-files is set, filter by that category only
    if args.interesting_files:
        categories = ['interesting_files']
    elif args.exclude and categories:
        categories = [c for c in categories if c not in args.exclude]
    elif args.exclude:
        all_cats = pattern_manager.get_category_names()
        categories = [c for c in all_cats if c not in args.exclude]
    
    # Parse minimum severity
    min_severity = parse_severity(args.severity) if args.severity else None
    
    # Calculate minimum confidence
    min_confidence = args.min_confidence
    if args.high_confidence:
        min_confidence = 0.5
    
    # Smart filtering settings
    use_smart = not args.no_smart
    hide_boring = not args.show_boring
    detect_secrets = not args.no_secrets  # Default: enabled
    
    # Initialize analyzer
    analyzer = URLAnalyzer(pattern_manager)
    
    # Analyze URLs
    result = analyzer.analyze_urls(
        urls,
        categories=categories,
        deduplicate=not args.no_dedupe,
        min_severity=min_severity,
        min_confidence=min_confidence,
        smart_dedupe=not args.no_smart_dedupe,
        max_per_pattern=args.max_per_pattern,
        smart_filter=use_smart,
        hide_boring=hide_boring,
        detect_secrets=detect_secrets,
    )
    
    # Filter to only juicy/interesting if requested
    if args.only_juicy:
        result.all_matches = [m for m in result.all_matches if m.classification in ('juicy', 'interesting')]
        # Update matched count
        result.matched_urls = len(result.all_matches)
    
    # Configure output
    output_format = OutputFormat(args.format) if not args.quiet else OutputFormat.URLS_ONLY
    
    config = OutputConfig(
        format=output_format,
        color=not args.no_color,
        show_stats=not args.no_stats and not args.quiet,
        verbose=args.verbose,
        output_file=args.output,
        show_intel=args.show_intel,
    )
    
    # Output results
    formatter = OutputFormatter(config)
    formatter.output(result)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
