"""
IAM Güvenlik Kontrolleri
AdministratorAccess, wildcard policies, access key age, MFA kontrolleri
"""

import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta

from botocore.exceptions import ClientError

from . import BaseFinder


logger = logging.getLogger(__name__)


class IAMFinder(BaseFinder):
    """IAM güvenlik kontrolleri"""

    CHECKS = {
        "admin_access": True,
        "wildcard_policy": True,
        "access_key_age": True,
        "mfa": True,
    }

    # Kontrollere özel portlar/permission yok, IAM global servis
    def run(self) -> List[Dict]:
        """IAM taramasını çalıştır"""
        try:
            iam_client = self.session_manager.get_client("iam")
            
            # Kullanıcıları tara
            self._scan_users(iam_client)
            
            # Rolleri tara
            self._scan_roles(iam_client)
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDenied":
                self.add_error(
                    "IAM listeleme",
                    "IAM list_users/list_roles erişimi reddedildi"
                )
            else:
                self.add_error("IAM genel", f"ClientError: {e}")
        except Exception as e:
            self.add_error("IAM genel", f"Beklenmeyen hata: {e}")
        
        return self.findings

    def _scan_users(self, iam_client) -> None:
        """IAM kullanıcılarını tara"""
        try:
            users = self._list_users(iam_client)
            
            if not users:
                logger.info("IAM kullanıcı bulunamadı")
                return
            
            logger.info(f"{len(users)} IAM kullanıcı taranıyor...")
            
            for user in users:
                user_name = user.get("UserName", "")
                user_arn = user.get("Arn", "")
                
                # AdministratorAccess kontrolü
                if self.CHECKS["admin_access"]:
                    self._check_admin_access(iam_client, user_name, user_arn)
                
                # Wildcard policy kontrolü
                if self.CHECKS["wildcard_policy"]:
                    self._check_wildcard_policies(iam_client, user_name, user_arn, "user")
                
                # Access key age kontrolü
                if self.CHECKS["access_key_age"]:
                    self._check_access_key_age(iam_client, user_name, user_arn)
                
                # MFA kontrolü
                if self.CHECKS["mfa"]:
                    self._check_mfa(iam_client, user_name, user_arn)
            
        except Exception as e:
            logger.error(f"User tarama hatası: {e}")

    def _scan_roles(self, iam_client) -> None:
        """IAM rollerini tara"""
        try:
            roles = self._list_roles(iam_client)
            
            if not roles:
                logger.info("IAM rol bulunamadı")
                return
            
            logger.info(f"{len(roles)} IAM rol taranıyor...")
            
            for role in roles:
                role_name = role.get("RoleName", "")
                role_arn = role.get("Arn", "")
                
                # AdministratorAccess kontrolü
                if self.CHECKS["admin_access"]:
                    self._check_admin_access(iam_client, role_name, role_arn, is_role=True)
                
                # Wildcard policy kontrolü
                if self.CHECKS["wildcard_policy"]:
                    self._check_wildcard_policies(iam_client, role_name, role_arn, "role")
            
        except Exception as e:
            logger.error(f"Role tarama hatası: {e}")

    def _list_users(self, iam_client) -> List[Dict]:
        """Tüm kullanıcıları listele"""
        users = []
        try:
            paginator = iam_client.get_paginator("list_users")
            for page in paginator.paginate():
                users.extend(page.get("Users", []))
        except Exception as e:
            logger.error(f"User listeleme hatası: {e}")
        return users

    def _list_roles(self, iam_client) -> List[Dict]:
        """Tüm rolleri listele"""
        roles = []
        try:
            paginator = iam_client.get_paginator("list_roles")
            for page in paginator.paginate():
                roles.extend(page.get("Roles", []))
        except Exception as e:
            logger.error(f"Role listeleme hatası: {e}")
        return roles

    def _check_admin_access(
        self, iam_client, name: str, arn: str, is_role: bool = False
    ) -> None:
        """AdministratorAccess attached policy kontrolü"""
        try:
            if is_role:
                attached = iam_client.list_attached_role_policies(RoleName=name)
            else:
                attached = iam_client.list_attached_user_policies(UserName=name)
            
            attached_policies = attached.get("AttachedPolicies", [])
            
            for policy in attached_policies:
                policy_name = policy.get("PolicyName", "")
                
                # AdministratorAccess kontrolü (case-insensitive)
                if "administratoraccess" in policy_name.lower():
                    resource_type = "Rol" if is_role else "Kullanıcı"
                    self.add_finding(
                        finding_id="AWS-IAM-ADMIN-001",
                        title=f"IAM {resource_type} AdministratorAccess Attached",
                        severity="high",
                        confidence="high",
                        service="iam",
                        resource_arn=arn,
                        resource_name=name,
                        evidence=[
                            f"{resource_type} AdministratorAccess managed policy'e sahip",
                            f"Policy: {policy_name}"
                        ],
                        risk=(
                            f"{resource_type} tam yönetici izinlerine sahip. "
                            "Bu durum yüksek güvenlik riski oluşturur."
                        ),
                        recommendation=[
                            "En az prensiplerine göre minimal izinler verin",
                            "Spesifik policy'ler oluşturun",
                            "Sadece gerçekten gerektiğinde admin access verin"
                        ],
                        score_impact=-15,
                        tags=["iam", "admin-access", "permissions"],
                    )
            
        except ClientError as e:
            logger.warning(f"Admin access kontrol hatası ({name}): {e}")

    def _check_wildcard_policies(
        self, iam_client, name: str, arn: str, resource_type: str
    ) -> None:
        """Wildcard action/resource içeren policy kontrolü"""
        try:
            # Inline policy'leri kontrol et
            if resource_type == "user":
                policies = iam_client.list_user_policies(UserName=name)
                policy_names = policies.get("PolicyNames", [])
            else:
                policies = iam_client.list_role_policies(RoleName=name)
                policy_names = policies.get("PolicyNames", [])
            
            for policy_name in policy_names:
                try:
                    if resource_type == "user":
                        policy_doc = iam_client.get_user_policy(
                            UserName=name, PolicyName=policy_name
                        )
                    else:
                        policy_doc = iam_client.get_role_policy(
                            RoleName=name, PolicyName=policy_name
                        )
                    
                    policy_str = policy_doc.get("PolicyDocument", "{}")
                    policy_str_str = str(policy_doc)
                    
                    # Action: "*" veya Resource: "*" kontrolü
                    has_wildcard_action = '"Action": "*"' in policy_str_str or '"Action": "*"' in policy_str_str
                    has_wildcard_resource = '"Resource": "*"' in policy_str_str or '"Resource": "*"' in policy_str_str
                    has_wildcard_action_any = '"Action": "*:*"' in policy_str_str or '"Action": "*:*"' in policy_str_str
                    
                    if has_wildcard_action or has_wildcard_action_any:
                        self.add_finding(
                            finding_id="AWS-IAM-WILDCARD-001",
                            title="IAM Policy Wildcard Action İçeriyor",
                            severity="high",
                            confidence="high",
                            service="iam",
                            resource_arn=arn,
                            resource_name=name,
                            evidence=[
                                f"Policy: {policy_name}",
                                "Wild-card Action (*) veya Action: *:* tespit edildi"
                            ],
                            risk=(
                                "Policy'de wild-card action kullanılıyor. "
                                "Bu durum geniş yetki verme riski oluşturur."
                            ),
                            recommendation=[
                                "Spesifik action'lar kullanın",
                                "Wildcard kullanımından kaçının",
                                "IAM Policy Simulator ile etkileri test edin"
                            ],
                            score_impact=-12,
                            tags=["iam", "wildcard", "permissions"],
                        )
                    
                    elif has_wildcard_resource:
                        self.add_finding(
                            finding_id="AWS-IAM-WILDCARD-002",
                            title="IAM Policy Wildcard Resource İçeriyor",
                            severity="medium",
                            confidence="high",
                            service="iam",
                            resource_arn=arn,
                            resource_name=name,
                            evidence=[
                                f"Policy: {policy_name}",
                                "Wild-card Resource (*) tespit edildi"
                            ],
                            risk=(
                                "Policy'de wild-card resource kullanılıyor. "
                                "Bu durum kaynak bazlı geniş yetki riski oluşturur."
                            ),
                            recommendation=[
                                "Spesifik resource ARN'ları kullanın",
                                "Wildcard kullanımından kaçının",
                                "Kaynak ARN formatına dikkat edin"
                            ],
                            score_impact=-8,
                            tags=["iam", "wildcard", "permissions"],
                        )
                
                except ClientError as e:
                    logger.warning(f"Policy okuma hatası ({policy_name}): {e}")
            
        except ClientError as e:
            logger.warning(f"Wildcard policy kontrol hatası ({name}): {e}")

    def _check_access_key_age(self, iam_client, user_name: str, user_arn: str) -> None:
        """Access key yaş kontrolü (>90 gün)"""
        try:
            keys = iam_client.list_access_keys(UserName=user_name)
            access_keys = keys.get("AccessKeyMetadata", [])
            
            current_date = datetime.now()
            
            for key in access_keys:
                key_id = key.get("AccessKeyId", "")
                status = key.get("Status", "")
                create_date = key.get("CreateDate")
                
                if not create_date:
                    continue
                
                # Status = Active ise kontrol et
                if status == "Active":
                    age = (current_date - create_date.replace(tzinfo=None)).days
                    
                    if age > 90:
                        self.add_finding(
                            finding_id="AWS-IAM-KEY-AGE-001",
                            title="IAM Access Key Yaşı 90 Günü Aşıyor",
                            severity="medium",
                            confidence="high",
                            service="iam",
                            resource_arn=user_arn,
                            resource_name=user_name,
                            evidence=[
                                f"Key ID: {key_id}",
                                f"Key Yaşı: {age} gün",
                                f"Durum: {status}"
                            ],
                            risk=(
                                f"Access key {age} gündir aktif. "
                                "Uzun süre kullanılan key'ler tehlikeye atılmış olabilir."
                            ),
                            recommendation=[
                                "Eski key'leri devre dışı bırakın",
                                "Yeni access key oluşturun",
                                "Eski key'leri silin",
                                "Key rotation düzenli yapın"
                            ],
                            score_impact=-8,
                            tags=["iam", "access-key", "credentials"],
                        )
            
        except ClientError as e:
            logger.warning(f"Access key kontrol hatası ({user_name}): {e}")

    def _check_mfa(self, iam_client, user_name: str, user_arn: str) -> None:
        """MFA kontrolü (kullanıcı bazlı)"""
        try:
            # MFA cihazlarını listele
            mfa_devices = iam_client.list_mfa_devices(UserName=user_name)
            devices = mfa_devices.get("MFADevices", [])
            
            # Console login var mı kontrol et (LoginProfile)
            try:
                login_profile = iam_client.get_login_profile(UserName=user_name)
                has_console = True
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "NoSuchEntity":
                    has_console = False
                else:
                    has_console = False
            
            # Console access var ama MFA yok
            if has_console and not devices:
                self.add_finding(
                    finding_id="AWS-IAM-MFA-001",
                    title="IAM Kullanıcısı Console Access MFA Yok",
                    severity="medium",
                    confidence="medium",
                    service="iam",
                    resource_arn=user_arn,
                    resource_name=user_name,
                    evidence=[
                        "Console login profili var",
                        "MFA cihazı tanımlı değil"
                    ],
                    risk=(
                        "Kullanıcı console access'e sahip ama MFA kullanmıyor. "
                        "Credential theft durumunda hesap ele geçirilebilir."
                    ),
                    recommendation=[
                        "MFA zorunlu yapın (account settings veya policy ile)",
                        "Kullanıcıya MFA tanımlaması talimatı verin",
                        "Root account için mutlaka MFA kullanın"
                    ],
                    score_impact=-10,
                    tags=["iam", "mfa", "authentication"],
                )
            
        except ClientError as e:
            logger.warning(f"MFA kontrol hatası ({user_name}): {e}")