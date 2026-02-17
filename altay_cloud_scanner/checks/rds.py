"""
RDS Güvenlik Kontrolleri
PubliclyAccessible kontrolü
"""

import logging
from typing import List, Dict, Optional

from botocore.exceptions import ClientError

from . import BaseFinder


logger = logging.getLogger(__name__)


class RDSFinder(BaseFinder):
    """RDS güvenlik kontrolleri"""

    CHECKS = {
        "public_access": True,
    }

    def run(self) -> List[Dict]:
        """RDS taramasını çalıştır"""
        try:
            rds_client = self.session_manager.get_client("rds", region_name=self.region)
            
            # Tüm DB instance'ları getir
            db_instances = self._describe_db_instances(rds_client)
            
            if not db_instances:
                logger.info(f"{self.region} bölgesinde RDS instance bulunamadı")
                return self.findings
            
            logger.info(f"{len(db_instances)} RDS instance taranıyor...")
            
            for db_instance in db_instances:
                self._check_db_instance(db_instance)
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDenied":
                self.add_error(
                    "RDS listeleme",
                    "RDS describe_db_instances erişimi reddedildi"
                )
            else:
                self.add_error("RDS genel", f"ClientError: {e}")
        except Exception as e:
            self.add_error("RDS genel", f"Beklenmeyen hata: {e}")
        
        return self.findings

    def _describe_db_instances(self, rds_client) -> List[Dict]:
        """Tüm DB instance'ları listele"""
        instances = []
        try:
            for page in self.session_manager.paginate(
                rds_client, "describe_db_instances"
            ):
                instances.extend(page.get("DBInstances", []))
        except Exception as e:
            logger.error(f"DB instance listeleme hatası: {e}")
        return instances

    def _check_db_instance(self, db_instance: Dict) -> None:
        """Tek DB instance için kontrolleri çalıştır"""
        db_id = db_instance.get("DBInstanceIdentifier", "")
        db_arn = db_instance.get("DBInstanceArn", "")
        engine = db_instance.get("Engine", "")
        engine_version = db_instance.get("EngineVersion", "")
        
        # PubliclyAccessible kontrolü
        if self.CHECKS["public_access"]:
            self._check_publicly_accessible(
                db_id, db_arn, engine, engine_version, db_instance
            )

    def _check_publicly_accessible(
        self,
        db_id: str,
        db_arn: str,
        engine: str,
        engine_version: str,
        db_instance: Dict,
    ) -> None:
        """PubliclyAccessible kontrolü"""
        publicly_accessible = db_instance.get("PubliclyAccessible", False)
        
        if publicly_accessible:
            # VPC ve subnet bilgileri
            vpc_id = db_instance.get("DBSubnetGroup", {}).get("VpcId", "")
            subnet_group = db_instance.get("DBSubnetGroup", {}).get("DBSubnetGroupName", "")
            
            # Security group'lar
            security_groups = db_instance.get("VpcSecurityGroups", [])
            sg_ids = [sg.get("VpcSecurityGroupId", "") for sg in security_groups]
            
            self.add_finding(
                finding_id="AWS-RDS-PUBLIC-001",
                title="RDS DB Instance PubliclyAccessible True",
                severity="high",
                confidence="high",
                service="rds",
                resource_arn=db_arn,
                resource_name=db_id,
                evidence=[
                    f"PubliclyAccessible: {publicly_accessible}",
                    f"Engine: {engine} {engine_version}",
                    f"VPC: {vpc_id}",
                    f"Subnet Group: {subnet_group}",
                    f"Security Groups: {', '.join(sg_ids) if sg_ids else 'Yok'}"
                ],
                risk=(
                    "RDS instance'i public erişime açık. "
                    "Veritabanı internet üzerinden erişilebilir durumda. "
                    "Bu durum veri sızıntısı ve unauthorized erişim riski oluşturur."
                ),
                recommendation=[
                    "PubliclyAccessible'i False olarak değiştirin",
                    "VPC içinde private subnet kullanın",
                    "VPN, Direct Connect veya PrivateLink ile erişin",
                    "Security Group'ları kısıtlayın",
                    "SSL/TLS zorunlu yapın"
                ],
                score_impact=-15,
                tags=["rds", "public-access", "database"],
            )