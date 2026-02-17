"""
AWS Misconfiguration Check Modülleri
Her bir bulgu standart formatta döndürülür
"""

import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from datetime import datetime


logger = logging.getLogger(__name__)


class BaseFinder(ABC):
    """Base finder sınıfı - tüm check modülleri bunu extend eder"""

    def __init__(self, session_manager, region: str):
        """
        Args:
            session_manager: AWSSessionManager örneği
            region: Tarama bölgesi
        """
        self.session_manager = session_manager
        self.region = region
        self.findings = []
        self.errors = []

    @abstractmethod
    def run(self) -> List[Dict]:
        """
        Taramayı çalıştır ve bulguları döndür
        
        Returns:
            Bulgu listesi
        """
        pass

    def add_finding(
        self,
        finding_id: str,
        title: str,
        severity: str,
        confidence: str,
        service: str,
        resource_arn: str,
        resource_name: str,
        evidence: List[str],
        risk: str,
        recommendation: List[str],
        score_impact: int,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Standart bulgu formatında bulgu ekle
        
        Args:
            finding_id: Bulgu ID
            title: Bulgu başlığı
            severity: severity (high/medium/low/info)
            confidence: güven (high/medium/low)
            service: AWS servisi (s3/iam/ec2/rds/elb)
            resource_arn: Kaynak ARN
            resource_name: Kaynak adı
            evidence: Delil listesi
            risk: Risk açıklaması
            recommendation: Öneri listesi
            score_impact: Skor etki değeri (negatif)
            tags: Etiket listesi
        """
        finding = {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "service": service,
            "resource": {
                "arn": resource_arn,
                "name": resource_name,
                "region": self.region,
            },
            "evidence": evidence,
            "risk": risk,
            "recommendation": recommendation,
            "score_impact": score_impact,
            "tags": tags or [],
            "timestamp": datetime.now().isoformat(),
        }
        
        self.findings.append(finding)
        logger.info(f"Bulgu eklendi: {finding_id} - {title}")

    def add_error(self, check_name: str, error_message: str) -> None:
        """
        Hata ekle
        
        Args:
            check_name: Check adı
            error_message: Hata mesajı
        """
        error = {
            "check": check_name,
            "service": self.__class__.__name__.replace("Finder", "").lower(),
            "region": self.region,
            "error": error_message,
            "timestamp": datetime.now().isoformat(),
        }
        
        self.errors.append(error)
        logger.error(f"Hata ({check_name}): {error_message}")

    def get_findings(self) -> List[Dict]:
        """Bulguları döndür"""
        return self.findings

    def get_errors(self) -> List[Dict]:
        """Hataları döndür"""
        return self.errors

    def clear(self) -> None:
        """Bulguları ve hataları temizle"""
        self.findings = []
        self.errors = []