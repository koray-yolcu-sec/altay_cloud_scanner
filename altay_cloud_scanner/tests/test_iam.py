"""
IAM Security Tests
IAM güvenlik kontrolleri için unit testler
"""

import pytest
from unittest.mock import Mock, MagicMock
from botocore.exceptions import ClientError

from altay_cloud_scanner.aws_session import AWSSessionManager
from altay_cloud_scanner.checks.iam import IAMFinder


@pytest.fixture
def mock_session_manager():
    """Mock AWS Session Manager"""
    mock_manager = Mock(spec=AWSSessionManager)
    return mock_manager


@pytest.fixture
def mock_iam_client():
    """Mock IAM client"""
    client = Mock()
    return client


def test_iam_admin_access_attached(mock_session_manager, mock_iam_client):
    """IAM kullanıcı AdministratorAccess attached olduğunda bulgu oluşturmalı"""
    mock_session_manager.get_client.return_value = mock_iam_client
    mock_iam_client.get_paginator.return_value.paginate.return_value = iter([
        {"Users": [{"UserName": "admin-user", "Arn": "arn:aws:iam::123456789012:user/admin-user"}]}
    ])
    
    # Attached policies
    mock_iam_client.list_attached_user_policies.return_value = {
        "AttachedPolicies": [
            {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
        ]
    }
    
    # Policy listesi boş (inline policy yok)
    mock_iam_client.list_user_policies.return_value = {"PolicyNames": []}
    
    # Access keys yok
    mock_iam_client.list_access_keys.return_value = {"AccessKeyMetadata": []}
    
    # MFA yok
    mock_iam_client.list_mfa_devices.return_value = {"MFADevices": []}
    
    # Login profile yok (console access yok)
    error_response = {"Error": {"Code": "NoSuchEntity"}}
    mock_iam_client.get_login_profile.side_effect = ClientError(error_response, "GetLoginProfile")
    
    finder = IAMFinder(mock_session_manager, "global")
    findings = finder.run()
    
    assert len(findings) > 0
    admin_findings = [f for f in findings if "ADMIN-001" in f.get("id", "")]
    assert len(admin_findings) > 0
    
    finding = admin_findings[0]
    assert finding["severity"] == "high"
    assert "AdministratorAccess" in finding["title"]


def test_iam_wildcard_policy_action(mock_session_manager, mock_iam_client):
    """IAM policy'de wildcard action olduğunda bulgu oluşturmalı"""
    mock_session_manager.get_client.return_value = mock_iam_client
    mock_iam_client.get_paginator.return_value.paginate.return_value = iter([
        {"Users": [{"UserName": "wildcard-user", "Arn": "arn:aws:iam::123456789012:user/wildcard-user"}]}
    ])
    
    # Attached policies yok
    mock_iam_client.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    
    # Inline policy'ler
    mock_iam_client.list_user_policies.return_value = {
        "PolicyNames": ["WildcardPolicy"]
    }
    
    # Wildcard policy
    mock_iam_client.get_user_policy.return_value = {
        "PolicyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    }
    
    mock_iam_client.list_access_keys.return_value = {"AccessKeyMetadata": []}
    mock_iam_client.list_mfa_devices.return_value = {"MFADevices": []}
    
    error_response = {"Error": {"Code": "NoSuchEntity"}}
    mock_iam_client.get_login_profile.side_effect = ClientError(error_response, "GetLoginProfile")
    
    finder = IAMFinder(mock_session_manager, "global")
    findings = finder.run()
    
    assert len(findings) > 0
    wildcard_findings = [f for f in findings if "WILDCARD" in f.get("id", "")]
    assert len(wildcard_findings) > 0
    
    finding = wildcard_findings[0]
    assert finding["severity"] in ["high", "medium"]
    assert "wildcard" in finding["title"].lower() or "Wildcard" in finding["title"]


def test_iam_access_key_age(mock_session_manager, mock_iam_client):
    """IAM access key yaşı 90 günden fazla olduğunda bulgu oluşturmalı"""
    from datetime import datetime, timedelta
    
    mock_session_manager.get_client.return_value = mock_iam_client
    mock_iam_client.get_paginator.return_value.paginate.return_value = iter([
        {"Users": [{"UserName": "old-key-user", "Arn": "arn:aws:iam::123456789012:user/old-key-user"}]}
    ])
    
    # Attached policies yok
    mock_iam_client.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    
    # Inline policy'ler yok
    mock_iam_client.list_user_policies.return_value = {"PolicyNames": []}
    
    # Eski access key (100 gün önce)
    old_date = datetime.now() - timedelta(days=100)
    mock_iam_client.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "Status": "Active",
                "CreateDate": old_date
            }
        ]
    }
    
    mock_iam_client.list_mfa_devices.return_value = {"MFADevices": []}
    
    error_response = {"Error": {"Code": "NoSuchEntity"}}
    mock_iam_client.get_login_profile.side_effect = ClientError(error_response, "GetLoginProfile")
    
    finder = IAMFinder(mock_session_manager, "global")
    findings = finder.run()
    
    assert len(findings) > 0
    key_findings = [f for f in findings if "KEY-AGE" in f.get("id", "")]
    assert len(key_findings) > 0
    
    finding = key_findings[0]
    assert finding["severity"] == "medium"
    assert "90" in finding["risk"] or "gün" in finding["risk"]


def test_iam_mfa_disabled(mock_session_manager, mock_iam_client):
    """Console access'li ama MFA'sız kullanıcıda bulgu oluşturmalı"""
    mock_session_manager.get_client.return_value = mock_iam_client
    mock_iam_client.get_paginator.return_value.paginate.return_value = iter([
        {"Users": [{"UserName": "no-mfa-user", "Arn": "arn:aws:iam::123456789012:user/no-mfa-user"}]}
    ])
    
    mock_iam_client.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    mock_iam_client.list_user_policies.return_value = {"PolicyNames": []}
    mock_iam_client.list_access_keys.return_value = {"AccessKeyMetadata": []}
    
    # MFA yok
    mock_iam_client.list_mfa_devices.return_value = {"MFADevices": []}
    
    # Console access var (login profile var)
    mock_iam_client.get_login_profile.return_value = {
        "LoginProfile": {"UserName": "no-mfa-user"}
    }
    
    finder = IAMFinder(mock_session_manager, "global")
    findings = finder.run()
    
    assert len(findings) > 0
    mfa_findings = [f for f in findings if "MFA" in f.get("id", "")]
    assert len(mfa_findings) > 0
    
    finding = mfa_findings[0]
    assert finding["severity"] == "medium"
    assert "MFA" in finding["title"]


def test_iam_access_denied(mock_session_manager, mock_iam_client):
    """IAM AccessDenied durumunda hata kaydetmeli"""
    mock_session_manager.get_client.return_value = mock_iam_client
    
    # AccessDenied hatası
    error_response = {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}
    mock_iam_client.list_users.side_effect = ClientError(error_response, "ListUsers")
    
    finder = IAMFinder(mock_session_manager, "global")
    findings = finder.run()
    errors = finder.get_errors()
    
    assert len(findings) == 0
    assert len(errors) > 0
    assert "AccessDenied" in errors[0]["error"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])