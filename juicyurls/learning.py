"""
JuicyURLs - Lightweight Feedback Learning System

Learns from user feedback to improve URL classification accuracy.
No heavy ML dependencies - uses statistical pattern analysis.

Features:
- Stores feedback in ~/.juicyurls/feedback.json
- Extracts features from URLs (path segments, params, extensions, etc.)
- Calculates confidence adjustments based on feedback patterns
- Domain-specific learning (learns quirks of specific targets)
"""

import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
from datetime import datetime


@dataclass
class URLFeatures:
    """Extracted features from a URL for learning."""
    domain: str
    path_segments: List[str]
    param_names: List[str]
    extension: Optional[str]
    categories: List[str]  # Categories it was matched to
    depth: int  # Path depth
    has_numeric_id: bool
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'URLFeatures':
        return cls(**data)


@dataclass  
class FeedbackEntry:
    """A single feedback entry."""
    url: str
    feedback_type: str  # 'tp' (true positive) or 'fp' (false positive)
    features: URLFeatures
    timestamp: str
    categories: List[str]
    
    def to_dict(self) -> dict:
        d = asdict(self)
        d['features'] = self.features.to_dict()
        return d
    
    @classmethod
    def from_dict(cls, data: dict) -> 'FeedbackEntry':
        data['features'] = URLFeatures.from_dict(data['features'])
        return cls(**data)


class FeedbackLearner:
    """
    Learns from user feedback to adjust confidence scores.
    
    Learning approach:
    1. Extracts features from URLs (path patterns, params, extensions)
    2. Tracks which features correlate with FP/TP
    3. Adjusts confidence based on learned patterns
    
    Storage: ~/.juicyurls/feedback.json
    """
    
    DEFAULT_DIR = Path.home() / '.juicyurls'
    FEEDBACK_FILE = 'feedback.json'
    
    def __init__(self, data_dir: Optional[Path] = None):
        """Initialize the learner."""
        self.data_dir = data_dir or self.DEFAULT_DIR
        self.feedback_file = self.data_dir / self.FEEDBACK_FILE
        
        # Feedback storage
        self.feedback_entries: List[FeedbackEntry] = []
        
        # Learned adjustments (calculated from feedback)
        self.adjustments: Dict[str, float] = {}
        
        # Load existing feedback
        self._load_feedback()
        self._calculate_adjustments()
    
    def _ensure_dir(self):
        """Ensure data directory exists."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_feedback(self):
        """Load feedback from disk."""
        if not self.feedback_file.exists():
            return
        
        try:
            with open(self.feedback_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.feedback_entries = [
                    FeedbackEntry.from_dict(entry) 
                    for entry in data.get('entries', [])
                ]
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"Warning: Could not load feedback file: {e}")
            self.feedback_entries = []
    
    def _save_feedback(self):
        """Save feedback to disk."""
        self._ensure_dir()
        
        data = {
            'version': 1,
            'updated': datetime.now().isoformat(),
            'entries': [entry.to_dict() for entry in self.feedback_entries]
        }
        
        with open(self.feedback_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    def extract_features(self, url: str, categories: List[str] = None) -> URLFeatures:
        """Extract learnable features from a URL."""
        parsed = urlparse(url)
        
        # Get path segments (excluding empty strings)
        path_segments = [seg for seg in parsed.path.split('/') if seg]
        
        # Normalize path segments - replace IDs with placeholders
        normalized_segments = []
        has_numeric_id = False
        for seg in path_segments:
            if re.match(r'^\d+$', seg):
                normalized_segments.append('<ID>')
                has_numeric_id = True
            elif re.match(r'^[a-f0-9]{8,}$', seg, re.IGNORECASE):
                normalized_segments.append('<HASH>')
            elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', seg, re.IGNORECASE):
                normalized_segments.append('<UUID>')
            else:
                normalized_segments.append(seg.lower())
        
        # Get parameter names
        params = parse_qs(parsed.query)
        param_names = sorted(params.keys())
        
        # Get extension
        extension = None
        if '.' in parsed.path:
            ext_match = re.search(r'\.([a-zA-Z0-9]{1,10})$', parsed.path)
            if ext_match:
                extension = ext_match.group(1).lower()
        
        return URLFeatures(
            domain=parsed.netloc.lower(),
            path_segments=normalized_segments,
            param_names=param_names,
            extension=extension,
            categories=categories or [],
            depth=len(normalized_segments),
            has_numeric_id=has_numeric_id,
        )
    
    def add_feedback(self, url: str, feedback_type: str, categories: List[str] = None) -> bool:
        """
        Add feedback for a URL.
        
        Args:
            url: The URL to provide feedback on
            feedback_type: 'tp' (true positive) or 'fp' (false positive)
            categories: Categories the URL was matched to
        
        Returns:
            True if feedback was added successfully
        """
        if feedback_type not in ('tp', 'fp'):
            print(f"Error: feedback_type must be 'tp' or 'fp', got '{feedback_type}'")
            return False
        
        features = self.extract_features(url, categories or [])
        
        entry = FeedbackEntry(
            url=url,
            feedback_type=feedback_type,
            features=features,
            timestamp=datetime.now().isoformat(),
            categories=categories or [],
        )
        
        # Check for duplicate feedback on same URL
        for existing in self.feedback_entries:
            if existing.url == url:
                # Update existing feedback
                self.feedback_entries.remove(existing)
                break
        
        self.feedback_entries.append(entry)
        self._save_feedback()
        self._calculate_adjustments()
        
        return True
    
    def _calculate_adjustments(self):
        """
        Calculate confidence adjustments from feedback.
        
        Creates adjustment keys for:
        - Path segment patterns (e.g., 'path:upload' -> -0.2 if often FP)
        - Category adjustments (e.g., 'cat:admin_debug' -> -0.1)
        - Extension adjustments (e.g., 'ext:html' -> -0.15)
        - Domain-specific (e.g., 'domain:example.com:path:upload' -> -0.3)
        - Param patterns (e.g., 'param:id' -> +0.1 if often TP)
        """
        if not self.feedback_entries:
            self.adjustments = {}
            return
        
        # Track feature occurrences with TP/FP counts
        feature_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {'tp': 0, 'fp': 0})
        
        for entry in self.feedback_entries:
            feedback = entry.feedback_type
            features = entry.features
            
            # Path segment patterns
            for seg in features.path_segments:
                if seg not in ('<ID>', '<HASH>', '<UUID>'):
                    key = f"path:{seg}"
                    feature_stats[key][feedback] += 1
            
            # Category patterns
            for cat in features.categories:
                key = f"cat:{cat}"
                feature_stats[key][feedback] += 1
            
            # Extension patterns
            if features.extension:
                key = f"ext:{features.extension}"
                feature_stats[key][feedback] += 1
            
            # Param name patterns
            for param in features.param_names:
                key = f"param:{param}"
                feature_stats[key][feedback] += 1
            
            # Domain-specific patterns (for frequent patterns)
            for seg in features.path_segments:
                if seg not in ('<ID>', '<HASH>', '<UUID>'):
                    key = f"domain:{features.domain}:path:{seg}"
                    feature_stats[key][feedback] += 1
            
            # Category + extension combo
            for cat in features.categories:
                if features.extension:
                    key = f"cat:{cat}:ext:{features.extension}"
                    feature_stats[key][feedback] += 1
            
            # Path depth pattern
            key = f"depth:{features.depth}"
            feature_stats[key][feedback] += 1
        
        # Calculate adjustments using simple ratio
        # Adjustment = (TP_rate - FP_rate) * weight
        self.adjustments = {}
        
        for key, stats in feature_stats.items():
            total = stats['tp'] + stats['fp']
            if total < 2:
                continue  # Need at least 2 data points
            
            tp_rate = stats['tp'] / total
            fp_rate = stats['fp'] / total
            
            # Calculate adjustment (-0.3 to +0.3 range)
            # Positive = more likely TP, negative = more likely FP
            adjustment = (tp_rate - fp_rate) * 0.3
            
            # Only store significant adjustments
            if abs(adjustment) >= 0.05:
                self.adjustments[key] = round(adjustment, 3)
    
    def get_confidence_adjustment(self, url: str, categories: List[str] = None) -> Tuple[float, List[str]]:
        """
        Get the confidence adjustment for a URL based on learned patterns.
        
        Args:
            url: The URL to check
            categories: Categories the URL was matched to
        
        Returns:
            Tuple of (adjustment float, list of reasons)
        """
        if not self.adjustments:
            return 0.0, []
        
        features = self.extract_features(url, categories or [])
        
        adjustments_applied = []
        total_adjustment = 0.0
        
        # Check all relevant feature keys
        keys_to_check = []
        
        # Path segments
        for seg in features.path_segments:
            if seg not in ('<ID>', '<HASH>', '<UUID>'):
                keys_to_check.append(f"path:{seg}")
                keys_to_check.append(f"domain:{features.domain}:path:{seg}")
        
        # Categories
        for cat in (categories or []):
            keys_to_check.append(f"cat:{cat}")
            if features.extension:
                keys_to_check.append(f"cat:{cat}:ext:{features.extension}")
        
        # Extension
        if features.extension:
            keys_to_check.append(f"ext:{features.extension}")
        
        # Params
        for param in features.param_names:
            keys_to_check.append(f"param:{param}")
        
        # Depth
        keys_to_check.append(f"depth:{features.depth}")
        
        # Apply matching adjustments
        for key in keys_to_check:
            if key in self.adjustments:
                adj = self.adjustments[key]
                total_adjustment += adj
                direction = "↑" if adj > 0 else "↓"
                adjustments_applied.append(f"{direction} {key}: {adj:+.2f}")
        
        # Clamp total adjustment to reasonable range
        total_adjustment = max(-0.5, min(0.5, total_adjustment))
        
        return total_adjustment, adjustments_applied
    
    def get_stats(self) -> Dict:
        """Get statistics about the learned model."""
        if not self.feedback_entries:
            return {
                'total_feedback': 0,
                'true_positives': 0,
                'false_positives': 0,
                'learned_patterns': 0,
                'domains_seen': 0,
            }
        
        tp_count = sum(1 for e in self.feedback_entries if e.feedback_type == 'tp')
        fp_count = sum(1 for e in self.feedback_entries if e.feedback_type == 'fp')
        domains = set(e.features.domain for e in self.feedback_entries)
        
        return {
            'total_feedback': len(self.feedback_entries),
            'true_positives': tp_count,
            'false_positives': fp_count,
            'learned_patterns': len(self.adjustments),
            'domains_seen': len(domains),
            'domains': list(domains)[:10],  # Top 10 domains
        }
    
    def get_learned_patterns(self) -> Dict[str, float]:
        """Get all learned pattern adjustments."""
        return dict(sorted(self.adjustments.items(), key=lambda x: abs(x[1]), reverse=True))
    
    def reset(self) -> bool:
        """Reset all learning data."""
        self.feedback_entries = []
        self.adjustments = {}
        
        if self.feedback_file.exists():
            self.feedback_file.unlink()
        
        return True
    
    def show_learning_summary(self) -> str:
        """Generate a human-readable summary of learned patterns."""
        stats = self.get_stats()
        patterns = self.get_learned_patterns()
        
        lines = [
            "🧠 JuicyURLs Learning Summary",
            "=" * 50,
            "",
            f"📊 Feedback Statistics:",
            f"   Total feedback entries: {stats['total_feedback']}",
            f"   True positives (TP):    {stats['true_positives']}",
            f"   False positives (FP):   {stats['false_positives']}",
            f"   Domains analyzed:       {stats['domains_seen']}",
            f"   Learned patterns:       {stats['learned_patterns']}",
            "",
        ]
        
        if patterns:
            lines.extend([
                "📈 Learned Confidence Adjustments:",
                "   (Positive = more likely TP, Negative = more likely FP)",
                "",
            ])
            
            # Group by type
            path_patterns = {k: v for k, v in patterns.items() if k.startswith('path:')}
            cat_patterns = {k: v for k, v in patterns.items() if k.startswith('cat:') and ':ext:' not in k}
            ext_patterns = {k: v for k, v in patterns.items() if k.startswith('ext:')}
            combo_patterns = {k: v for k, v in patterns.items() if ':ext:' in k}
            domain_patterns = {k: v for k, v in patterns.items() if k.startswith('domain:')}
            
            if path_patterns:
                lines.append("   Path Patterns:")
                for k, v in list(path_patterns.items())[:10]:
                    icon = "✅" if v > 0 else "❌"
                    lines.append(f"      {icon} {k}: {v:+.3f}")
                lines.append("")
            
            if cat_patterns:
                lines.append("   Category Patterns:")
                for k, v in list(cat_patterns.items())[:10]:
                    icon = "✅" if v > 0 else "❌"
                    lines.append(f"      {icon} {k}: {v:+.3f}")
                lines.append("")
            
            if ext_patterns:
                lines.append("   Extension Patterns:")
                for k, v in list(ext_patterns.items())[:10]:
                    icon = "✅" if v > 0 else "❌"
                    lines.append(f"      {icon} {k}: {v:+.3f}")
                lines.append("")
            
            if combo_patterns:
                lines.append("   Category+Extension Combos:")
                for k, v in list(combo_patterns.items())[:10]:
                    icon = "✅" if v > 0 else "❌"
                    lines.append(f"      {icon} {k}: {v:+.3f}")
                lines.append("")
            
            if domain_patterns:
                lines.append("   Domain-Specific Patterns:")
                for k, v in list(domain_patterns.items())[:10]:
                    icon = "✅" if v > 0 else "❌"
                    lines.append(f"      {icon} {k}: {v:+.3f}")
                lines.append("")
        else:
            lines.extend([
                "No patterns learned yet.",
                "",
                "Provide feedback to start learning:",
                "  juicyurls --feedback fp 'https://example.com/boring/url'",
                "  juicyurls --feedback tp 'https://example.com/juicy/endpoint'",
                "",
            ])
        
        return "\n".join(lines)
