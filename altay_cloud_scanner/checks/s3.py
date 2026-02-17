"""
S3 Bucket Güvenlik Kontrolleri
Public erişim, encryption, versioning, ACL kontrolleri
"""

import logging
from typing import List, Dict, Optional

from botocore.exceptions import ClientError

from . import BaseFinder


logger = logging.getLogger(__name__)


class S3Finder(BaseFinder):
    """S3 bucket güvenlik kontrolleri"""

    # Tarama yapılacak portlar ve kontroller
    CHECKS = {
        "public_access_block": True,
        "bucket_policy": True,
        "acl": True,
        "encryption": True,
        "versioning": True,
    }

    def run(self) -> List[Dict]:
        """S3 bucket taramasını çalıştır"""
        try:
            s3_client = self.session_manager.get_client("s3", region_name=self.region)
            
            # Tüm bucket'ları listele
            buckets = self._list_buckets(s3_client)
            
            if not buckets:
                logger.info(f"{self.region} bölgesinde S3 bucket bulunamadı")
                return self.findings
            
            logger.info(f"{len(buckets)} S3 bucket taranıyor...")
            
            for bucket_name in buckets:
                self._check_bucket(s3_client, bucket_name)
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDenied":
                self.add_error(
                    "S3 bucket listeleme",
                    "S3 list_buckets erişimi reddedildi"
                )
            else:
                self.add_error("S3 genel", f"ClientError: {e}")
        except Exception as e:
            self.add_error("S3 genel", f"Beklenmeyen hata: {e}")
        
        return self.findings

    def _list_buckets(self, s3_client) -> List[str]:
        """Tüm bucket isimlerini döndür"""
        try:
            response = s3_client.list_buckets()
            return [bucket["Name"] for bucket in response.get("Buckets", [])]
        except Exception as e:
            logger.error(f"Bucket listeleme hatası: {e}")
            return []

    def _check_bucket(self, s3_client, bucket_name: str) -> None:
        """Tek bucket için tüm kontrolleri çalıştır"""
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        
        # Bucket bölgesini tespit et
        bucket_region = self._get_bucket_region(s3_client, bucket_name)
        if bucket_region and bucket_region != self.region:
            # Sadece belirtilen bölgedeki bucket'ları tara
            return
        
        # PublicAccessBlock kontrolü
        if self.CHECKS["public_access_block"]:
            self._check_public_access_block(s3_client, bucket_name, bucket_arn)
        
        # Bucket policy kontrolü
        if self.CHECKS["bucket_policy"]:
            self._check_bucket_policy(s3_client, bucket_name, bucket_arn)
        
        # ACL kontrolü
        if self.CHECKS["acl"]:
            self._check_bucket_acl(s3_client, bucket_name, bucket_arn)
        
        # Encryption kontrolü
        if self.CHECKS["encryption"]:
            self._check_encryption(s3_client, bucket_name, bucket_arn)
        
        # Versioning kontrolü
        if self.CHECKS["versioning"]:
            self._check_versioning(s3_client, bucket_name, bucket_arn)

    def _get_bucket_region(self, s3_client, bucket_name: str) -> Optional[str]:
        """Bucket bölgesini tespit et"""
        try:
            response = s3_client.get_bucket_location(Bucket=bucket_name)
            return response.get("LocationConstraint") or "us-east-1"
        except Exception as e:
            logger.warning(f"Bucket bölge tespiti hatası ({bucket_name}): {e}")
            return None

    def _check_public_access_block(
        self, s3_client, bucket_name: str, bucket_arn: str
    ) -> None:
        """PublicAccessBlock konfigürasyonunu kontrol et"""
        try:
            response = s3_client.get_public_access_block(Bucket=bucket_name)
            config = response.get("PublicAccessBlockConfiguration", {})
            
            # Herhangi bir block kapalı mı?
            blocks_closed = []
            
            if not config.get("BlockPublicAcls", True):
                blocks_closed.append("BlockPublicAcls")
            
            if not config.get("IgnorePublicAcls", True):
                blocks_closed.append("IgnorePublicAcls")
            
            if not config.get("BlockPublicPolicy", True):
                blocks_closed.append("BlockPublicPolicy")
            
            if not config.get("RestrictPublicBuckets", True):
                blocks_closed.append("RestrictPublicBuckets")
            
            if blocks_closed:
                self.add_finding(
                    finding_id="AWS-S3-PUBLIC-001",
                    title="S3 Bucket PublicAccessBlock Kısıtlamaları Kapalı",
                    severity="high",
                    confidence="high",
                    service="s3",
                    resource_arn=bucket_arn,
                    resource_name=bucket_name,
                    evidence=[
                        f"Kapalı ayarlar: {', '.join(blocks_closed)}"
                    ],
                    risk=(
                        "PublicAccessBlock kısıtlamalarının bazıları devre dışı. "
                        "Bucket içerikleri yanlışlıkla public erişime açılabilir."
                    ),
                    recommendation=[
                        "S3 Console veya API üzerinden PublicAccessBlock'ı tamamen etkinleştirin",
                        "En azından BlockPublicPolicy ve RestrictPublicBuckets açık olmalı",
                        "CloudTrail ile bucket access loglarını izleyin"
                    ],
                    score_impact=-15,
                    tags=["s3", "public-access", "storage"],
                )
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                # Konfigürasyon yok = açık kabul et
                self.add_finding(
                    finding_id="AWS-S3-PUBLIC-001",
                    title="S3 Bucket PublicAccessBlock Konfigürasyonu Yok",
                    severity="medium",
                    confidence="high",
                    service="s3",
                    resource_arn=bucket_arn,
                    resource_name=bucket_name,
                    evidence=[
                        "PublicAccessBlock konfigürasyonu tanımlı değil"
                    ],
                    risk=(
                        "PublicAccessBlock konfigürasyonu yok. "
                        "Bucket varsayılan güvenlik ayarlarına bağlı."
                    ),
                    recommendation=[
                        "PublicAccessBlock konfigürasyonu oluşturun ve tüm ayarları etkinleştirin"
                    ],
                    score_impact=-10,
                    tags=["s3", "public-access", "storage"],
                )
            else:
                logger.warning(f"PublicAccessBlock kontrol hatası ({bucket_name}): {e}")

    def _check_bucket_policy(
        self, s3_client, bucket_name: str, bucket_arn: str
    ) -> None:
        """Bucket policy'de public principal kontrolü"""
        try:
            response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_str = response.get("Policy", "")
            
            if not policy_str:
                return
            
            # Basit string kontrol - JSON parse olmadan
            if '"Principal": "*"' in policy_str or '"Principal": "*"' in policy_str:
                self.add_finding(
                    finding_id="AWS-S3-PUBLIC-002",
                    title="S3 Bucket Policy'de Public Principal (*)",
                    severity="high",
                    confidence="high",
                    service="s3",
                    resource_arn=bucket_arn,
                    resource_name=bucket_name,
                    evidence=[
                        "Bucket policy'de Principal: '*' kullanımı tespit edildi"
                    ],
                    risk=(
                        "Bucket policy'de wild-card principal (*) kullanılıyor. "
                        "Bu durum bucket'ın internete tam açık olmasına neden olabilir."
                    ),
                    recommendation=[
                        "Principal: '*' kullanmaktan kaçının",
                        "Spesifik AWS hesap ID'leri veya IAM kullanıcısı/rolleri kullanın",
                        "S3 Bucket Policy best practice'lerini inceleyin"
                    ],
                    score_impact=-15,
                    tags=["s3", "public-policy", "storage"],
                )
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code != "NoSuchBucketPolicy":
                logger.warning(f"Bucket policy kontrol hatası ({bucket_name}): {e}")

    def _check_bucket_acl(
        self, s3_client, bucket_name: str, bucket_arn: str
    ) -> None:
        """Bucket ACL'de public erişim kontrolü"""
        try:
            response = s3_client.get_bucket_acl(Bucket=bucket_name)
            grants = response.get("Grants", [])
            
            public_grants = []
            
            for grant in grants:
                grantee = grant.get("Grantee", {})
                grantee_type = grantee.get("Type", "")
                
                # AllUsers veya AuthenticatedUsers = public
                if grantee_type in ["AllUsers", "AuthenticatedUsers", "Group"]:
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        permission = grant.get("Permission", "")
                        public_grants.append(f"{uri} -> {permission}")
            
            if public_grants:
                self.add_finding(
                    finding_id="AWS-S3-PUBLIC-003",
                    title="S3 Bucket ACL'de Public Erişim",
                    severity="high",
                    confidence="high",
                    service="s3",
                    resource_arn=bucket_arn,
                    resource_name=bucket_name,
                    evidence=[
                        f"Public ACL izinleri: {', '.join(public_grants)}"
                    ],
                    risk=(
                        "Bucket ACL'sinde public gruplara (AllUsers/AuthenticatedUsers) "
                        "izin verilmiş. Bu durum unauthorized erişime neden olabilir."
                    ),
                    recommendation=[
                        "ACL'leri kaldırın ve bucket policy kullanın",
                        "Bucket Policy ve PublicAccessBlock kullanarak erişimi yönetin",
                        "S3 Object Ownership'ı BucketOwnerPreferred olarak ayarlayın"
                    ],
                    score_impact=-15,
                    tags=["s3", "public-acl", "storage"],
                )
            
        except ClientError as e:
            logger.warning(f"Bucket ACL kontrol hatası ({bucket_name}): {e}")

    def _check_encryption(
        self, s3_client, bucket_name: str, bucket_arn: str
    ) -> None:
        """Default encryption kontrolü"""
        try:
            response = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            
            if rules:
                # Encryption var, iyi
                pass
            else:
                # Empty rules = encryption yok
                self.add_finding(
                    finding_id="AWS-S3-ENCRYPTION-001",
                    title="S3 Bucket Default Encryption Kapalı",
                    severity="medium",
                    confidence="high",
                    service="s3",
                    resource_arn=bucket_arn,
                    resource_name=bucket_name,
                    evidence=[
                        "Default encryption konfigürasyonu yok veya boş"
                    ],
                    risk=(
                        "Bucket'ta default encryption aktif değil. "
                        "Bucket'a yeni yüklenen nesneler otomatik olarak şifrelenmeyecek."
                    ),
                    recommendation=[
                        "Bucket default encryption'ı AES-256 (SSE-S3) veya KMS (SSE-KMS) ile aktif edin",
                        "Mevcut nesneleri manuel olarak şifreleyin",
                        "Bucket policy ile şifreleme gerektirin"
                    ],
                    score_impact=-8,
                    tags=["s3", "encryption", "storage"],
                )
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                # Encryption konfigürasyonu yok
                self.add_finding(
                    finding_id="AWS-S3-ENCRYPTION-001",
                    title="S3 Bucket Default Encryption Konfigürasyonu Yok",
                    severity="medium",
                    confidence="high",
                    service="s3",
                    resource_arn=bucket_arn,
                    resource_name=bucket_name,
                    evidence=[
                        "Default encryption konfigürasyonu tanımlı değil"
                    ],
                    risk=(
                        "Bucket'ta default encryption aktif değil. "
                        "Bucket'a yeni yüklenen nesneler otomatik olarak şifrelenmeyecek."
                    ),
                    recommendation=[
                        "Bucket default encryption'ı AES-256 (SSE-S3) veya KMS (SSE-KMS) ile aktif edin"
                    ],
                    score_impact=-8,
                    tags=["s3", "encryption", "storage"],
                )
            else:
                logger.warning(f"Encryption kontrol hatası ({bucket_name}): {e}")

    def _check_versioning(
        self, s3_client, bucket_name: str, bucket_arn: str
    ) -> None:
        """Versioning kontrolü"""
        try:
            response = s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = response.get("Status", "Suspended")
            
            if status != "Enabled":
                self.add_finding(
                    finding_id="AWS-S3-VERSIONING-001",
                    title="S3 Bucket Versioning Kapalı",
                    severity="medium",
                    confidence="high",
                    service="s3",
                    resource_arn=bucket_arn,
                    resource_name=bucket_name,
                    evidence=[
                        f"Versioning durumu: {status}"
                    ],
                    risk=(
                        "Bucket versioning kapalı. "
                        "Kazara silme veya overwrite durumlarında veri kurtarılamaz."
                    ),
                    recommendation=[
                        "Versioning'i aktif edin",
                        "MFA Delete özelliğini de aktif etmeyi düşünün",
                        "Object Lock ile kritik verileri koruyun"
                    ],
                    score_impact=-5,
                    tags=["s3", "versioning", "storage"],
                )
            
        except ClientError as e:
            logger.warning(f"Versioning kontrol hatası ({bucket_name}): {e}")