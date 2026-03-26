"""
Detection module initialization.
"""

from .engine import DetectionEngine, get_detection_engine, AnalysisResult
from .classifiers import AttackClassifier, HeuristicAnalyzer, DetectionResult
from .patterns import get_all_patterns, AttackPattern, Severity

__all__ = [
    'DetectionEngine',
    'get_detection_engine',
    'AnalysisResult',
    'AttackClassifier',
    'HeuristicAnalyzer',
    'DetectionResult',
    'get_all_patterns',
    'AttackPattern',
    'Severity'
]
