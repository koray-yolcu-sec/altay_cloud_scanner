"""
Risk Skorlama Sistemi
0-100 arası güvenlik skoru hesaplama
"""

from typing import List, Dict
from enum import Enum


class Severity(Enum):
    """Bulgu severity seviyeleri"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskScorer:
    """Risk skor hesaplama motoru"""

    # Severity bazlı skor etkileri
    SEVERITY_SCORES = {
        Severity.CRITICAL: -25,
        Severity.HIGH: -15,
        Severity.MEDIUM: -8,
        Severity.LOW: -3,
        Severity.INFO: -1,
    }

    def __init__(self, base_score: int = 100):
        """
        Args:
            base_score: Başlangıç skoru (varsayılan 100)
        """
        self.base_score = base_score
        self.findings = []
        self.total_score = base_score
        self.errors = []

    def add_finding(self, finding: Dict) -> None:
        """
        Bulgu ekle ve skoru güncelle
        
        Args:
            finding: Bulgu dict (score_impact içermeli)
        """
        self.findings.append(finding)
        
        # Skor etki hesapla
        score_impact = finding.get("score_impact", 0)
        self.total_score += score_impact

        # Skoru 0-100 arasında tut
        self.total_score = max(0, min(100, self.total_score))

    def add_error(self, error: Dict) -> None:
        """
        Tarama hatası ekle
        
        Args:
            error: Hata dict
        """
        self.errors.append(error)

    def get_score(self) -> int:
        """Mevcut risk skorunu döndür"""
        return self.total_score

    def get_grade(self) -> str:
        """Skora göre grade döndür"""
        if self.total_score >= 90:
            return "A"
        elif self.total_score >= 70:
            return "B"
        elif self.total_score >= 50:
            return "C"
        elif self.total_score >= 30:
            return "D"
        else:
            return "F"

    def get_severity_counts(self) -> Dict[str, int]:
        """Severity bazlı bulgu sayıları"""
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        for finding in self.findings:
            severity = finding.get("severity", "info").lower()
            if severity in counts:
                counts[severity] += 1
        
        return counts

    def get_summary(self) -> Dict:
        """Özet bilgiler döndür"""
        return {
            "total_score": self.total_score,
            "grade": self.get_grade(),
            "total_findings": len(self.findings),
            "severity_counts": self.get_severity_counts(),
            "total_errors": len(self.errors),
            "is_partial_scan": len(self.errors) > 0,
        }

    def reset(self) -> None:
        """Skorlayıcıyı sıfırla"""
        self.findings = []
        self.total_score = self.base_score
        self.errors = []

    @staticmethod
    def calculate_impact(severity: str, confidence: str = "medium") -> int:
        """
        Severity ve confidence'a göre skor etkisi hesapla
        
        Args:
            severity: Bulgu severity
            confidence: Güven seviyesi
            
        Returns:
            Skor etki değeri (negatif)
        """
        try:
            sev = Severity(severity.lower())
            base_impact = RiskScorer.SEVERITY_SCORES[sev]
            
            # Confidence ile ayarla
            if confidence.lower() == "high":
                return base_impact
            elif confidence.lower() == "medium":
                return int(base_impact * 0.7)
            else:  # low confidence
                return int(base_impact * 0.4)
                
        except (KeyError, ValueError):
            return -1  # Bilinmeyen severity için varsayılan