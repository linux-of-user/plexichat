from .core.antivirus_engine import AdvancedAntivirusEngine
from .core.behavioral_analyzer import BehavioralAnalyzer
from .core.filename_analyzer import FilenameAnalyzer
from .core.hash_scanner import HashBasedScanner
from .core.link_scanner import LinkSafetyScanner
from .core.threat_intelligence import ThreatIntelligenceEngine


"""
PlexiChat Advanced Antivirus System

Comprehensive antivirus and security scanning system with:
- Real-time file scanning with multiple engines
- Hash-based virus database checking
- Suspicious filename detection
- Link safety analysis
- Network-based threat intelligence
- Behavioral analysis and heuristics
- Integration with public virus databases
"""

__all__ = [
    'AdvancedAntivirusEngine',
    'HashBasedScanner', 
    'BehavioralAnalyzer',
    'LinkSafetyScanner',
    'FilenameAnalyzer',
    'ThreatIntelligenceEngine'
]

# Antivirus system capabilities
ANTIVIRUS_FEATURES = {
    "real_time_scanning": True,
    "hash_based_detection": True,
    "behavioral_analysis": True,
    "link_safety_checking": True,
    "filename_analysis": True,
    "threat_intelligence": True,
    "public_database_integration": True,
    "heuristic_detection": True,
    "quarantine_system": True,
    "automatic_updates": True,
    "clustering_integration": True,
    "api_integration": True
}
