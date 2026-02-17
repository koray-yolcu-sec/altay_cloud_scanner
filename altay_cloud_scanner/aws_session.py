"""
AWS Session Yönetimi
STS doğrulama, exponential backoff ve retry mekanizması
"""

import logging
from typing import Optional

import boto3
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    BotoCoreError,
)

logger = logging.getLogger(__name__)


class AWSSessionManager:
    """AWS oturum ve bağlantı yönetimi"""

    def __init__(
        self,
        profile_name: Optional[str] = None,
        region: Optional[str] = None,
        expected_account_id: Optional[str] = None,
    ):
        self.profile_name = profile_name
        self.region = region
        self.expected_account_id = expected_account_id
        self._session = None
        self._caller_identity = None

        # Botocore config - exponential backoff ile
        self.config = Config(
            region_name=region,
            retries={
                "max_attempts": 5,
                "mode": "adaptive",
            },
            connect_timeout=10,
            read_timeout=30,
        )

    def get_session(self) -> boto3.Session:
        """Boto3 session döndür"""
        if self._session is None:
            if self.profile_name:
                self._session = boto3.Session(
                    profile_name=self.profile_name, region_name=self.region
                )
            else:
                self._session = boto3.Session(region_name=self.region)
        return self._session

    def get_client(self, service_name: str, region_name: Optional[str] = None):
        """Boto3 client oluştur"""
        session = self.get_session()
        client_region = region_name or self.region
        
        try:
            return session.client(
                service_name,
                region_name=client_region,
                config=self.config,
            )
        except Exception as e:
            logger.error(f"{service_name} client oluşturma hatası: {e}")
            raise

    def verify_caller_identity(self) -> dict:
        """STS GetCallerIdentity ile kimlik doğrula"""
        try:
            sts_client = self.get_client("sts")
            self._caller_identity = sts_client.get_caller_identity()
            
            account_id = self._caller_identity.get("Account")
            user_arn = self._caller_identity.get("Arn")
            
            logger.info(f"AWS Account ID: {account_id}")
            logger.info(f"Caller ARN: {user_arn}")
            
            # Beklenen account ID kontrolü
            if self.expected_account_id:
                if account_id != self.expected_account_id:
                    error_msg = (
                        f"Account ID uyuşmazlığı! Beklenen: {self.expected_account_id}, "
                        f"Gerçek: {account_id}"
                    )
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                logger.info(f"Account ID doğrulandı: {account_id}")
            
            return self._caller_identity
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"STS GetCallerIdentity hatası [{error_code}]: {e}")
            raise
        except Exception as e:
            logger.error(f"STS kimlik doğrulama hatası: {e}")
            raise

    def get_caller_identity(self) -> Optional[dict]:
        """Caller identity bilgisini döndür"""
        return self._caller_identity

    def check_access(self, service_name: str, action: str) -> bool:
        """Belirli bir servis için erişim kontrolü"""
        try:
            client = self.get_client(service_name)
            
            # Servis özelinde basit bir kontrol
            if service_name == "s3":
                client.list_buckets()
            elif service_name == "iam":
                client.list_users(MaxItems=1)
            elif service_name == "ec2":
                client.describe_regions()
            elif service_name == "rds":
                client.describe_db_instances(MaxRecords=1)
            elif service_name == "elb":
                client.describe_load_balancers()
            
            return True
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDenied":
                logger.warning(f"{service_name}.{action} erişimi reddedildi")
                return False
            logger.warning(f"{service_name} erişim kontrolü hatası: {e}")
            return False
        except Exception as e:
            logger.warning(f"{service_name} erişim kontrolü beklenmeyen hata: {e}")
            return False

    def paginate(
        self,
        client,
        method_name: str,
        **kwargs
    ):
        """
        AWS API pagination için generator
        Throttling toleranslı ve error handling'li
        """
        paginator = None
        try:
            paginator = client.get_paginator(method_name)
        except Exception as e:
            logger.warning(f"Paginator oluşturulamadı {method_name}: {e}")
            return

        try:
            for page in paginator.paginate(**kwargs):
                yield page
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDenied":
                logger.warning(f"{method_name} AccessDenied: Pagination durduruldu")
            elif error_code == "Throttling":
                logger.warning(f"{method_name} Throttling: Pagination durduruldu")
            else:
                logger.warning(f"{method_name} pagination hatası: {e}")
        except (EndpointConnectionError, BotoCoreError) as e:
            logger.warning(f"{method_name} connection hatası: {e}")
        except Exception as e:
            logger.warning(f"{method_name} pagination beklenmeyen hata: {e}")