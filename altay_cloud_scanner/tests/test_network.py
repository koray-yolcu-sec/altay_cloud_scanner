"""
Network Security Tests
EC2 Security Group kontrolleri için unit testler
"""

import pytest
from unittest.mock import Mock, MagicMock
from botocore.exceptions import ClientError

from altay_cloud_scanner.aws_session import AWSSessionManager
from altay_cloud_scanner.checks.network import NetworkFinder


@pytest.fixture
def mock_session_manager():
    """Mock AWS Session Manager"""
    mock_manager = Mock(spec=AWSSessionManager)
    return mock_manager


@pytest.fixture
def mock_ec2_client():
    """Mock EC2 client"""
    client = Mock()
    return client


def test_sg_ssh_public_access(mock_session_manager, mock_ec2_client):
    """Security Group SSH (port 22) 0.0.0.0/0 olduğunda HIGH bulgu oluşturmalı"""
    mock_session_manager.get_client.return_value = mock_ec2_client
    mock_session_manager.paginate.return_value = iter([
        {"SecurityGroups": [
            {
                "GroupId": "sg-12345678",
                "GroupName": "default",
                "OwnerId": "123456789012",
                "Description": "Default security group",
                "VpcId": "vpc-12345678",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [
                            {
                                "CidrIp": "0.0.0.0/0",
                                "Description": "SSH access"
                            }
                        ]
                    }
                ]
            }
        ]}
    ])
    
    finder = NetworkFinder(mock_session_manager, "us-east-1")
    findings = finder.run()
    
    assert len(findings) > 0
    ssh_findings = [f for f in findings if "PUBLIC-001" in f.get("id", "")]
    assert len(ssh_findings) > 0
    
    finding = ssh_findings[0]
    assert finding["severity"] == "high"
    assert "22" in finding["title"] or "SSH" in finding["title"]
    assert "0.0.0.0/0" in finding["evidence"][2]


def test_sg_rdp_public_access(mock_session_manager, mock_ec2_client):
    """Security Group RDP (port 3389) 0.0.0.0/0 olduğunda HIGH bulgu oluşturmalı"""
    mock_session_manager.get_client.return_value = mock_ec2_client
    mock_session_manager.paginate.return_value = iter([
        {"SecurityGroups": [
            {
                "GroupId": "sg-87654321",
                "GroupName": "windows-sg",
                "OwnerId": "123456789012",
                "Description": "Windows security group",
                "VpcId": "vpc-12345678",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3389,
                        "ToPort": 3389,
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0"}
                        ]
                    }
                ]
            }
        ]}
    ])
    
    finder = NetworkFinder(mock_session_manager, "us-east-1")
    findings = finder.run()
    
    assert len(findings) > 0
    rdp_findings = [f for f in findings if "PUBLIC-001" in f.get("id", "")]
    assert len(rdp_findings) > 0
    
    finding = rdp_findings[0]
    assert finding["severity"] == "high"
    assert "3389" in finding["title"] or "RDP" in finding["title"]


def test_sg_all_traffic_public(mock_session_manager, mock_ec2_client):
    """Security Group ALL TRAFFIC 0.0.0.0/0 olduğunda bulgu oluşturmalı"""
    mock_session_manager.get_client.return_value = mock_ec2_client
    mock_session_manager.paginate.return_value = iter([
        {"SecurityGroups": [
            {
                "GroupId": "sg-11111111",
                "GroupName": "all-traffic-sg",
                "OwnerId": "123456789012",
                "Description": "All traffic open",
                "VpcId": "vpc-12345678",
                "IpPermissions": [
                    {
                        "IpProtocol": "-1",  # ALL TRAFFIC
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0"}
                        ]
                    }
                ]
            }
        ]}
    ])
    
    finder = NetworkFinder(mock_session_manager, "us-east-1")
    findings = finder.run()
    
    assert len(findings) > 0
    all_traffic_findings = [f for f in findings if "PUBLIC-004" in f.get("id", "")]
    assert len(all_traffic_findings) > 0
    
    finding = all_traffic_findings[0]
    assert finding["severity"] == "high"
    assert "ALL TRAFFIC" in finding["title"]
    assert finding["score_impact"] == -20


def test_sg_http_public_access(mock_session_manager, mock_ec2_client):
    """Security Group HTTP (port 80) 0.0.0.0/0 olduğunda LOW bulgu oluşturmalı"""
    mock_session_manager.get_client.return_value = mock_ec2_client
    mock_session_manager.paginate.return_value = iter([
        {"SecurityGroups": [
            {
                "GroupId": "sg-22222222",
                "GroupName": "web-sg",
                "OwnerId": "123456789012",
                "Description": "Web security group",
                "VpcId": "vpc-12345678",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 80,
                        "ToPort": 80,
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0"}
                        ]
                    }
                ]
            }
        ]}
    ])
    
    finder = NetworkFinder(mock_session_manager, "us-east-1")
    findings = finder.run()
    
    assert len(findings) > 0
    http_findings = [f for f in findings if "PUBLIC-002" in f.get("id", "")]
    assert len(http_findings) > 0
    
    finding = http_findings[0]
    assert finding["severity"] == "low"
    assert "80" in finding["title"] or "HTTP" in finding["title"]


def test_sg_default_sg_reduced_severity(mock_session_manager, mock_ec2_client):
    """Default security group için severity düşürülmeli"""
    mock_session_manager.get_client.return_value = mock_ec2_client
    mock_session_manager.paginate.return_value = iter([
        {"SecurityGroups": [
            {
                "GroupId": "sg-33333333",
                "GroupName": "default",  # Default SG
                "OwnerId": "123456789012",
                "Description": "Default VPC security group",
                "VpcId": "vpc-12345678",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 80,
                        "ToPort": 80,
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0"}
                        ]
                    }
                ]
            }
        ]}
    ])
    
    finder = NetworkFinder(mock_session_manager, "us-east-1")
    findings = finder.run()
    
    assert len(findings) > 0
    finding = findings[0]
    assert "Default SG" in finding["title"]
    assert finding["severity"] == "low"


def test_sg_access_denied(mock_session_manager, mock_ec2_client):
    """EC2 AccessDenied durumunda hata kaydetmeli"""
    mock_session_manager.get_client.return_value = mock_ec2_client
    
    # AccessDenied hatası
    error_response = {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}
    mock_ec2_client.describe_security_groups.side_effect = ClientError(error_response, "DescribeSecurityGroups")
    
    finder = NetworkFinder(mock_session_manager, "us-east-1")
    findings = finder.run()
    errors = finder.get_errors()
    
    assert len(findings) == 0
    assert len(errors) > 0
    assert "AccessDenied" in errors[0]["error"]


def test_sg_no_public_access(mock_session_manager, mock_ec2_client):
    """Public erişim olmayan SG'de bulgu oluşturmamalı"""
    mock_session_manager.get_client.return_value = mock_ec2_client
    mock_session_manager.paginate.return_value = iter([
        {"SecurityGroups": [
            {
                "GroupId": "sg-44444444",
                "GroupName": "private-sg",
                "OwnerId": "123456789012",
                "Description": "Private security group",
                "VpcId": "vpc-12345678",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [
                            {"CidrIp": "10.0.0.0/8"}  # Private IP range
                        ]
                    }
                ]
            }
        ]}
    ])
    
    finder = NetworkFinder(mock_session_manager, "us-east-1")
    findings = finder.run()
    
    assert len(findings) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])