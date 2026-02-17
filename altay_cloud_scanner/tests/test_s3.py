"""
S3 Security Tests
S3 bucket güvenlik kontrolleri için unit testler
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from botocore.exceptions import ClientError

from altay_cloud_scanner.aws_session import AWSSessionManager
from altay_cloud_scanner.checks.s3 import S3Finder


@pytest.fixture
def mock_session_manager():
    """Mock AWS Session Manager"""
    mock_manager = Mock(spec=AWSSessionManager)
    return mock_manager


@pytest.fixture
def mock_s3_client():
    """Mock S3 client"""
    client = Mock()
    return client


def test_s3_public_access_block_closed(mock_session_manager, mock_s3_client):
    """S3 bucket PublicAccessBlock kapalı olduğunda bulgu oluşturmalı"""
    # Setup mock responses
    mock_session_manager.get_client.return_value = mock_s3_client
    mock_session_manager.paginate.return_value = iter([
        {"Buckets": [{"Name": "test-bucket"}]}
    ])
    mock_s3_client.get_bucket_location.return_value = {
        "LocationConstraint": None
    }
    
    # PublicAccessBlock kapalı
    mock_s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
    }
    
    # Finder oluştur ve çalıştır
    finder = S3Finder(mock_session_manager, "us-east-1")
    findings = finder.run()
    
    # Doğrula
    assert len(findings) > 0
    public_findings = [f for f in findings if "PUBLIC-001" in f.get("id", "")]
    assert len(public_findings) > 0
    
    finding = public_findings[0]
    assert finding["severity"] == "high"
    assert "PublicAccessBlock" in finding["title"]


def test_s3_bucket_policy_wildcard(mock_session_manager, mock_s3_client):
    """S3 bucket policy'de wildcard principal olduğunda bulgu oluşturmalı"""
    mock_session_manager.get_client.return_value = mock_s3_client
    mock_session_manager.paginate.return_value = iter([
        {"Buckets": [{"Name": "test-bucket"}]}
    ])
    mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": None}
    
    # PublicAccessBlock açık (bulgu üretmesin)
    mock_s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    
    # Wildcard policy
    mock_s3_client.get_bucket_policy.return_value = {
        "Policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::test-bucket/*"}]}'
    }
    
    finder = S3Finder(mock_session_manager, "us-east-1")
    findings = finder.run()
    
    assert len(findings) > 0
    policy_findings = [f for f in findings if "PUBLIC-002" in f.get("id", "")]
    assert len(policy_findings) > 0
    
    finding = policy_findings[0]
    assert finding["severity"] == "high"
    assert "wildcard" in finding["title"].lower() or "Principal" in finding["title"]


def test_s3_encryption_disabled(mock_session_manager, mock_s3_client):
    """S3 bucket encryption kapalı olduğunda bulgu oluşturmalı"""
    mock_session_manager.get_client.return_value = mock_s3_client
    mock_session_manager.paginate.return_value = iter([
        {"Buckets": [{"Name": "test-bucket"}]}
    ])
    mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": None}
    
    # Diğer kontroller açık (bulgu üretmesin)
    mock_s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    
    # Policy yok (NoSuchBucketPolicy hatası fırlatmalı)
    error_response = {"Error": {"Code": "NoSuchBucketPolicy"}}
    mock_s3_client.get_bucket_policy.side_effect = ClientError(error_response, "GetBucketPolicy")
    
    # Encryption yok
    error_response = {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}
    mock_s3_client.get_bucket_encryption.side_effect = ClientError(error_response, "GetBucketEncryption")
    
    finder = S3Finder(mock_session_manager, "us-east-1")
    findings = finder.run()
    
    assert len(findings) > 0
    encryption_findings = [f for f in findings if "ENCRYPTION" in f.get("id", "")]
    assert len(encryption_findings) > 0
    
    finding = encryption_findings[0]
    assert finding["severity"] == "medium"
    assert "Encryption" in finding["title"]


def test_s3_access_denied(mock_session_manager, mock_s3_client):
    """S3 AccessDenied durumunda hata kaydetmeli"""
    mock_session_manager.get_client.return_value = mock_s3_client
    mock_session_manager.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
        "ListBuckets"
    )
    
    finder = S3Finder(mock_session_manager, "us-east-1")
    findings = finder.run()
    errors = finder.get_errors()
    
    assert len(findings) == 0
    assert len(errors) > 0
    assert "AccessDenied" in errors[0]["error"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])