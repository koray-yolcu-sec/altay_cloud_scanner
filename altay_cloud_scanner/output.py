"""
Çıktı Formatlama
JSON ve rapor oluşturma
"""

import json
import logging
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path


logger = logging.getLogger(__name__)


class OutputManager:
    """Çıktı formatlama ve kaydetme yöneticisi"""

    def __init__(self, output_format: str = "terminal"):
        """
        Args:
            output_format: terminal veya json
        """
        self.output_format = output_format
        self.findings = []
        self.errors = []
        self.summary = {}
        self.scan_info = {}

    def set_scan_info(
        self,
        account_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        mock: bool = False,
        profile: Optional[str] = None,
    ) -> None:
        """Tarama bilgilerini ayarla"""
        self.scan_info = {
            "scanner_name": "AltaySec Cloud Security Scanner",
            "scanner_version": "1.0.0",
            "scan_time": datetime.now().isoformat(),
            "account_id": account_id,
            "regions": regions or [],
            "mock_mode": mock,
            "profile": profile,
        }

    def add_finding(self, finding: Dict) -> None:
        """Bulgu ekle"""
        self.findings.append(finding)

    def add_error(self, error: Dict) -> None:
        """Hata ekle"""
        self.errors.append(error)

    def set_summary(self, summary: Dict) -> None:
        """Özet bilgileri ayarla"""
        self.summary = summary

    def generate_report(self) -> Dict:
        """
        Tam rapor oluştur
        
        Returns:
            Dict formatında tam rapor
        """
        report = {
            "scan_info": self.scan_info,
            "summary": self.summary,
            "findings": self.findings,
            "scan_errors": self.errors,
        }
        
        return report

    def save_json(self, filepath: str) -> None:
        """
        Raporu JSON dosyasına kaydet
        
        Args:
            filepath: Kaydedilecek dosya yolu
        """
        try:
            report = self.generate_report()
            
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Rapor kaydedildi: {filepath}")
            
        except Exception as e:
            logger.error(f"JSON kaydetme hatası: {e}")
            raise

    def get_json_string(self) -> str:
        """
        Raporu JSON string olarak döndür
        
        Returns:
            JSON formatında string
        """
        report = self.generate_report()
        return json.dumps(report, ensure_ascii=False, indent=2)

    @staticmethod
    def format_finding(finding: Dict) -> str:
        """
        Bulgu insan okunabilir formatda string'e çevir
        
        Args:
            finding: Bulgu dict
            
        Returns:
            Formatlanmış string
        """
        lines = []
        lines.append(f"\n{'='*60}")
        lines.append(f"ID: {finding.get('id', 'N/A')}")
        lines.append(f"Başlık: {finding.get('title', 'N/A')}")
        lines.append(f"Severity: {finding.get('severity', 'unknown').upper()}")
        lines.append(f"Hizmet: {finding.get('service', 'unknown')}")
        lines.append(f"Güven: {finding.get('confidence', 'unknown')}")
        
        resource = finding.get('resource', {})
        lines.append(f"Kaynak ARN: {resource.get('arn', 'N/A')}")
        lines.append(f"Kaynak Adı: {resource.get('name', 'N/A')}")
        lines.append(f"Bölge: {resource.get('region', 'N/A')}")
        
        lines.append(f"\nRisk:")
        lines.append(f"  {finding.get('risk', 'Açıklama yok')}")
        
        lines.append(f"\nDeliller:")
        for evidence in finding.get("evidence", []):
            lines.append(f"  • {evidence}")
        
        lines.append(f"\nÖneriler:")
        for rec in finding.get("recommendation", []):
            lines.append(f"  • {rec}")
        
        lines.append(f"Skor Etkisi: {finding.get('score_impact', 0)}")
        
        tags = finding.get('tags', [])
        if tags:
            lines.append(f"Etiketler: {', '.join(tags)}")
        
        lines.append(f"{'='*60}\n")
        
        return "\n".join(lines)

    @staticmethod
    def format_summary(summary: Dict) -> str:
        """
        Özeti string formatında döndür
        
        Args:
            summary: Özet dict
            
        Returns:
            Formatlanmış string
        """
        lines = []
        lines.append(f"\n{'='*60}")
        lines.append("GÜVENLİK SKORU ÖZETİ")
        lines.append(f"{'='*60}")
        lines.append(f"Toplam Skor: {summary.get('total_score', 'N/A')}/100")
        lines.append(f"Not: {summary.get('grade', 'N/A')}")
        lines.append(f"Toplam Bulgu: {summary.get('total_findings', 0)}")
        
        severity_counts = summary.get('severity_counts', {})
        lines.append(f"\nSeverity Dağılımı:")
        lines.append(f"  Kritik: {severity_counts.get('critical', 0)}")
        lines.append(f"  HIGH: {severity_counts.get('high', 0)}")
        lines.append(f"  MEDIUM: {severity_counts.get('medium', 0)}")
        lines.append(f"  LOW: {severity_counts.get('low', 0)}")
        lines.append(f"  INFO: {severity_counts.get('info', 0)}")
        
        lines.append(f"\nTarama Hataları: {summary.get('total_errors', 0)}")
        
        if summary.get('is_partial_scan'):
            lines.append("\n⚠ Kısmi tarama yapıldı")
        
        lines.append(f"{'='*60}\n")
        
        return "\n".join(lines)