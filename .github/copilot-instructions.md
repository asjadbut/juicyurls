# JuicyURLs - Copilot Instructions

## Project Overview
JuicyURLs is a Python CLI tool for bug bounty hunters that filters and categorizes URLs from reconnaissance tools (waybackurls, gau) to identify potentially vulnerable endpoints. It uses regex-based pattern matching with confidence scoring to reduce false positives.

## Architecture

### Module Structure (in `juicyurls/`)
- **cli.py** - Entry point (`main()`), argparse handling, external tool integration (waybackurls/gau)
- **analyzer.py** - Core URL analysis: `URLAnalyzer` parses URLs, matches patterns, calculates confidence scores, handles smart deduplication
- **patterns.py** - `PatternManager` with 25+ vulnerability categories (`VulnPattern` dataclass), each with path/param/extension regex patterns
- **output.py** - `OutputFormatter` with color-coded terminal output, severity icons (🔴🟡🔵), confidence stars (★★★)

### Data Flow
```
stdin/file/external tool → URLAnalyzer.analyze_urls() → pattern matching → confidence scoring → smart deduplication → OutputFormatter
```

### Key Classes
- `URLAnalyzer` - Main analysis engine, uses `PatternManager` to match URLs
- `VulnPattern` - Defines a vulnerability category with compiled regex patterns
- `MatchedURL` - Result dataclass with URL, categories, severity, confidence score
- `AnalysisResult` - Aggregates all matches with statistics

## Development Workflow

### Installation
```bash
pip install -e .  # Development install
python -m juicyurls --help  # Run without install
```

### Testing Changes
```bash
# Test with stdin
echo "https://example.com/search?id=1" | python -m juicyurls

# Test with file
python -m juicyurls -f urls.txt -c sqli idor --verbose

# List all categories
python -m juicyurls --list-categories
```

## Conventions

### Adding New Vulnerability Patterns
Add to `PatternManager._load_default_patterns()` in [patterns.py](juicyurls/patterns.py):
```python
self.patterns["category_name"] = VulnPattern(
    name="Display Name",
    severity=Severity.HIGH,  # HIGH, MEDIUM, or LOW
    description="What this category identifies",
    path_patterns=[r"/pattern\?"],  # Regex for URL path
    param_patterns=[r"^param_name$"],  # Regex for parameter names
    exclude_patterns=[r"\.js$"],  # False positive exclusions
    require_params=True,  # Only match if params present
)
```

### Confidence Scoring
Confidence is calculated in `URLAnalyzer._calculate_param_confidence()`. Value patterns in `VALUE_PATTERNS` dict boost confidence when parameter values look suspicious (URLs, file paths, numeric IDs).

### Output Formatting
Colors and icons are defined in `OutputFormatter`. Severity mapping:
- HIGH → 🔴 Red
- MEDIUM → 🟡 Yellow  
- LOW → 🔵 Cyan

## External Dependencies
- No runtime dependencies (pure Python 3.8+)
- Optional: `waybackurls`, `gau` (Go tools) for domain scanning via `-d` flag

## Common Tasks

### Filter output by severity or category
Use `-s high` for severity, `-c sqli idor` for categories, `--min-confidence 0.5` for fewer false positives

### Modify pattern matching behavior
Edit `match_url()` method in analyzer.py - patterns are matched against path, params, and extensions separately

### Add new output format
Extend `OutputFormat` enum and add handler in `OutputFormatter.output()`
