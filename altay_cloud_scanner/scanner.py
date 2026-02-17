"""
Ana Tarama Motoru
Check modüllerini koordine eder, bulguları toplar
"""

import logging
from typing import List, Dict, Optional

from .aws_session import AWSSessionManager
from .scoring import RiskScorer
from .checks.s3 import S3Finder
from .checks.iam import IAMFinder
from .checks.network import NetworkFinder
from .checks.rds import RDSFinder
from .checks.elb import ELBFinder


logger = logging.getLogger(__name__)


class CloudScanner:
    """Ana cloud tarayıcı sınıfı"""

    def __init__(
        self,
        session_manager: AWSSessionManager,
        regions: List[str],
        verbose: bool = False,
    ):
        """
        Args:
            session_manager: AWS session manager
            regions: Taranacak bölgeler listesi
            verbose: Detaylı çıktı
        """
        self.session_manager = session_manager
        self.regions = regions
        self.verbose = verbose
        self.scorer = RiskScorer()
        self.findings = []
        self.scan_errors = []

    def scan(self) -> Dict:
        """
        Tüm bölgelerde taramayı çalıştır
        
        Returns:
            Tarama özeti dict
        """
        logger.info(f"Tarama başlıyor: {len(self.regions)} bölge")
        
        total_checks = 0
        completed_checks = 0
        
        for region in self.regions:
            logger.info(f"Region {region} taraması başlıyor...")
            
            # Her region için finder'ları oluştur ve çalıştır
            finders = [
                ("S3", S3Finder(self.session_manager, region)),
                ("IAM", IAMFinder(self.session_manager, region)),  # IAM global, region param yok ama interface için
                ("Network", NetworkFinder(self.session_manager, region)),
                ("RDS", RDSFinder(self.session_manager, region)),
                ("ELB", ELBFinder(self.session_manager, region)),
            ]
            
            for finder_name, finder in finders:
                total_checks += 1
                
                try:
                    if self.verbose:
                        logger.info(f"Running {finder_name} check in {region}...")
                    
                    region_findings = finder.run()
                    region_errors = finder.get_errors()
                    
                    # Bulguları ekle
                    for finding in region_findings:
                        self.findings.append(finding)
                        self.scorer.add_finding(finding)
                    
                    # Hataları ekle
                    for error in region_errors:
                        self.scan_errors.append(error)
                        self.scorer.add_error(error)
                    
                    completed_checks += 1
                    
                except Exception as e:
                    logger.error(f"{finder_name} check hatası ({region}): {e}")
                    self.scan_errors.append({
                        "check": finder_name,
                        "region": region,
                        "error": str(e),
                    })
                    self.scorer.add_error({"check": finder_name, "error": str(e)})
        
        # Özet oluştur
        summary = self.scorer.get_summary()
        summary["total_checks"] = total_checks
        summary["completed_checks"] = completed_checks
        
        logger.info(f"Tarama tamamlandı: {len(self.findings)} bulgu, {len(self.scan_errors)} hata")
        
        return summary

    def get_findings(self) -> List[Dict]:
        """Bulguları döndür"""
        return self.findings

    def get_errors(self) -> List[Dict]:
        """Tarama hatalarını döndür"""
        return self.scan_errors

    def get_score(self) -> int:
        """Risk skorunu döndür"""
        return self.scorer.get_score()


class MockScanner:
    """Mock tarayıcı - demo modu için"""

    def __init__(self, verbose: bool = False):
        """
        Args:
            verbose: Detaylı çıktı
        """
        self.verbose = verbose
        self.scorer = RiskScorer()
        self.findings = []
        self.scan_errors = []

    def scan(self) -> Dict:
        """Mock tarama çalıştır"""
        logger.info("Mock tarama çalışıyor...")
        
        # Mock bulgular oluştur
        mock_findings = self._generate_mock_findings()
        
        for finding in mock_findings:
            self.findings.append(finding)
            self.scorer.add_finding(finding)
        
        summary = self.scorer.get_summary()
        summary["total_checks"] = 5
        summary["completed_checks"] = 5
        
        logger.info(f"Mock tarama tamamlandı: {len(self.findings)} bulgu")
        
        return summary

    def get_findings(self) -> List[Dict]:
        return self.findings

    def get_errors(self) -> List[Dict]:
        return self.scan_errors

    def get_score(self) -> int:
        return self.scorer.get_score()

    def _generate_mock_findings(self) -> List[Dict]:
        """Örnek bulgular oluştur"""
        findings = [
            {
                "id": "AWS-S3-PUBLIC-001",
                "title": "S3 Bucket PublicAccessBlock Kapalı",
                "severity": "high",
                "confidence": "high",
                "service": "s3",
                "resource": {
                    "arn": "arn:aws:s3:::example-bucket-mock",
                    "name": "example-bucket-mock",
                    "region": "eu-north-1",
                },
                "evidence": [
                    "PublicAccessBlock konfigürasyonu yok veya devre dışı",
                    "BlockPublicAcls: False",
                    "IgnorePublicAcls: False",
                ],
                "risk": "Bucket içerikleri internete açık olabilir",
                "recommendation": [
                    "PublicAccessBlock aktif et",
                    "Bucket policy'yi gözden geçir",
                ],
                "score_impact": -15,
                "tags": ["s3", "public-access", "storage"],
                "timestamp": "2024-01-01T00:00:00",
            },
            {
                "id": "AWS-IAM-ADMIN-001",
                "title": "IAM Kullanıcı AdministratorAccess Attached",
                "severity": "high",
                "confidence": "high",
                "service": "iam",
                "resource": {
                    "arn": "arn:aws:iam::123456789012:user/admin-user",
                    "name": "admin-user",
                    "region": "global",
                },
                "evidence": [
                    "Kullanıcı AdministratorAccess managed policy'e sahip",
                    "Policy: AdministratorAccess",
                ],
                "risk": "Kullanıcı tam yönetici izinlerine sahip",
                "recommendation": [
                    "En az prensiplerine göre minimal izinler verin",
                    "Spesifik policy'ler oluşturun",
                ],
                "score_impact": -15,
                "tags": ["iam", "admin-access", "permissions"],
                "timestamp": "2024-01-01T00:00:00",
            },
            {
                "id": "AWS-EC2-PUBLIC-001",
                "title": "EC2 Security Group 0.0.0.0/0: SSH (Port 22)",
                "severity": "high",
                "confidence": "high",
                "service": "ec2",
                "resource": {
                    "arn": "arn:aws:ec2:eu-north-1:123456789012:security-group/sg-12345678",
                    "name": "default",
                    "region": "eu-north-1",
                },
                "evidence": [
                    "Port: 22 (SSH)",
                    "Protocol: tcp",
                    "Kaynak: 0.0.0.0/0",
                ],
                "risk": "Security group port 22 (SSH) için dünyaya açık",
                "recommendation": [
                    "Port 22 için 0.0.0.0/0 kullanmaktan kaçının",
                    "Spesifik IP aralıkları kullanın",
                ],
                "score_impact": -12,
                "tags": ["ec2", "security-group", "public-access", "network"],
                "timestamp": "2024-01-01T00:00:00",
            },
            {
                "id": "AWS-RDS-PUBLIC-001",
                "title": "RDS DB Instance PubliclyAccessible True",
                "severity": "high",
                "confidence": "high",
                "service": "rds",
                "resource": {
                    "arn": "arn:aws:rds:eu-north-1:123456789012:db:mydb",
                    "name": "mydb",
                    "region": "eu-north-1",
                },
                "evidence": [
                    "PubliclyAccessible: True",
                    "Engine: postgres 15.4",
                ],
                "risk": "RDS instance'i public erişime açık",
                "recommendation": [
                    "PubliclyAccessible'i False olarak değiştirin",
                    "VPC içinde private subnet kullanın",
                ],
                "score_impact": -15,
                "tags": ["rds", "public-access", "database"],
                "timestamp": "2024-01-01T00:00:00",
            },
            {
                "id": "AWS-S3-VERSIONING-001",
                "title": "S3 Bucket Versioning Kapalı",
                "severity": "medium",
                "confidence": "high",
                "service": "s3",
                "resource": {
                    "arn": "arn:aws:s3:::another-bucket-mock",
                    "name": "another-bucket-mock",
                    "region": "eu-north-1",
                },
                "evidence": [
                    "Versioning durumu: Suspended",
                ],
                "risk": "Bucket versioning kapalı",
                "recommendation": [
                    "Versioning'i aktif edin",
                    "MFA Delete özelliğini de aktif etmeyi düşünün",
                ],
                "score_impact": -5,
                "tags": ["s3", "versioning", "storage"],
                "timestamp": "2024-01-01T00:00:00",
            },
        ]
        
        return findings