import pytest
import json
import boto3
from moto import mock_securityhub, mock_guardduty, mock_config, mock_s3, mock_sns
from unittest.mock import patch, MagicMock
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambda'))

from security_findings_processor import SecurityFindingProcessor, SecurityFinding


class TestSecurityFindingProcessor:
    """Test suite for SecurityFindingProcessor Lambda function"""
    
    @mock_securityhub
    @mock_guardduty
    @mock_config
    @mock_s3
    @mock_sns
    def test_lambda_handler_security_hub_finding(self):
        """Test processing of Security Hub finding"""
        processor = SecurityFindingProcessor()
        
        # Mock event from Security Hub
        event = {
            'Records': [{
                'eventSource': 'aws:securityhub',
                'eventName': 'SecurityHubFinding',
                'eventSourceARN': 'arn:aws:securityhub:us-east-1:123456789012:finding/test-finding',
                'awsRegion': 'us-east-1',
                'eventTime': '2024-08-27T10:00:00Z',
                'userIdentity': {'type': 'Service'},
                'eventVersion': '1.0',
                'detail': {
                    'findings': [{
                        'Id': 'test-finding-id',
                        'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
                        'GeneratorId': 'security-control/EC2.1',
                        'AwsAccountId': '123456789012',
                        'Region': 'us-east-1',
                        'Title': 'EC2 instances should not have a public IP address',
                        'Description': 'This control checks whether EC2 instances have a public IP address.',
                        'Severity': {
                            'Label': 'HIGH'
                        },
                        'Compliance': {
                            'Status': 'FAILED'
                        },
                        'Resources': [{
                            'Id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0',
                            'Type': 'AwsEc2Instance'
                        }],
                        'CreatedAt': '2024-08-27T10:00:00.000Z',
                        'UpdatedAt': '2024-08-27T10:00:00.000Z'
                    }]
                }
            }]
        }
        
        context = MagicMock()
        context.aws_request_id = 'test-request-id'
        
        # Mock environment variables
        with patch.dict(os.environ, {
            'S3_BUCKET_NAME': 'test-security-findings-bucket',
            'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:security-alerts'
        }):
            result = processor.lambda_handler(event, context)
        
        assert result['statusCode'] == 200
        assert 'Successfully processed 1 findings' in result['body']
    
    @mock_guardduty
    def test_lambda_handler_guardduty_finding(self):
        """Test processing of GuardDuty finding"""
        processor = SecurityFindingProcessor()
        
        event = {
            'Records': [{
                'eventSource': 'aws:guardduty',
                'eventName': 'GuardDutyFinding',
                'eventSourceARN': 'arn:aws:guardduty:us-east-1:123456789012:detector/test-detector',
                'awsRegion': 'us-east-1',
                'eventTime': '2024-08-27T10:00:00Z',
                'detail': {
                    'id': 'test-guardduty-finding',
                    'type': 'Trojan:EC2/DNSDataExfiltration',
                    'severity': 8.5,
                    'title': 'DNS data exfiltration detected',
                    'description': 'EC2 instance is performing DNS data exfiltration',
                    'accountId': '123456789012',
                    'region': 'us-east-1',
                    'resource': {
                        'instanceDetails': {
                            'instanceId': 'i-1234567890abcdef0'
                        }
                    },
                    'createdAt': '2024-08-27T10:00:00.000Z',
                    'updatedAt': '2024-08-27T10:00:00.000Z'
                }
            }]
        }
        
        context = MagicMock()
        
        with patch.dict(os.environ, {
            'S3_BUCKET_NAME': 'test-security-findings-bucket',
            'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:security-alerts'
        }):
            result = processor.lambda_handler(event, context)
        
        assert result['statusCode'] == 200
    
    def test_security_finding_dataclass(self):
        """Test SecurityFinding dataclass"""
        finding = SecurityFinding(
            finding_id='test-id',
            account_id='123456789012',
            region='us-east-1',
            service='SecurityHub',
            severity='HIGH',
            title='Test Finding',
            description='Test description',
            resource_id='test-resource',
            compliance_status='FAILED',
            created_at='2024-08-27T10:00:00Z'
        )
        
        assert finding.finding_id == 'test-id'
        assert finding.severity == 'HIGH'
        assert finding.service == 'SecurityHub'
        
        # Test to_dict method
        finding_dict = finding.to_dict()
        assert finding_dict['finding_id'] == 'test-id'
        assert finding_dict['severity'] == 'HIGH'
    
    def test_calculate_security_score(self):
        """Test security score calculation"""
        processor = SecurityFindingProcessor()
        
        findings = [
            SecurityFinding(
                finding_id='1', account_id='123456789012', region='us-east-1',
                service='SecurityHub', severity='CRITICAL', title='Test',
                description='Test', resource_id='resource-1',
                compliance_status='FAILED', created_at='2024-08-27T10:00:00Z'
            ),
            SecurityFinding(
                finding_id='2', account_id='123456789012', region='us-east-1',
                service='SecurityHub', severity='HIGH', title='Test',
                description='Test', resource_id='resource-2',
                compliance_status='FAILED', created_at='2024-08-27T10:00:00Z'
            ),
            SecurityFinding(
                finding_id='3', account_id='123456789012', region='us-east-1',
                service='SecurityHub', severity='LOW', title='Test',
                description='Test', resource_id='resource-3',
                compliance_status='PASSED', created_at='2024-08-27T10:00:00Z'
            )
        ]
        
        score = processor.calculate_security_score(findings)
        
        # With 1 critical (10 points), 1 high (7 points), 1 low (3 points)
        # Total penalty: 10 + 7 + 3 = 20
        # Score: max(0, 100 - 20) = 80
        assert score == 80.0
    
    def test_determine_criticality(self):
        """Test criticality determination logic"""
        processor = SecurityFindingProcessor()
        
        # Test critical finding
        critical_finding = SecurityFinding(
            finding_id='1', account_id='123456789012', region='us-east-1',
            service='SecurityHub', severity='CRITICAL', title='Test',
            description='Test', resource_id='resource-1',
            compliance_status='FAILED', created_at='2024-08-27T10:00:00Z'
        )
        
        assert processor.determine_criticality(critical_finding) == 'CRITICAL'
        
        # Test high finding with failed compliance
        high_finding = SecurityFinding(
            finding_id='2', account_id='123456789012', region='us-east-1',
            service='SecurityHub', severity='HIGH', title='Test',
            description='Test', resource_id='resource-2',
            compliance_status='FAILED', created_at='2024-08-27T10:00:00Z'
        )
        
        assert processor.determine_criticality(high_finding) == 'HIGH'
    
    def test_error_handling(self):
        """Test error handling in lambda handler"""
        processor = SecurityFindingProcessor()
        
        # Invalid event structure
        invalid_event = {'invalid': 'data'}
        context = MagicMock()
        
        result = processor.lambda_handler(invalid_event, context)
        
        assert result['statusCode'] == 500
        assert 'error' in result['body']
    
    @patch('boto3.client')
    def test_s3_storage_failure(self, mock_boto_client):
        """Test handling of S3 storage failures"""
        processor = SecurityFindingProcessor()
        
        # Mock S3 client to raise exception
        mock_s3_client = MagicMock()
        mock_s3_client.put_object.side_effect = Exception("S3 Error")
        mock_boto_client.return_value = mock_s3_client
        
        finding = SecurityFinding(
            finding_id='test', account_id='123456789012', region='us-east-1',
            service='SecurityHub', severity='HIGH', title='Test',
            description='Test', resource_id='resource',
            compliance_status='FAILED', created_at='2024-08-27T10:00:00Z'
        )
        
        with patch.dict(os.environ, {'S3_BUCKET_NAME': 'test-bucket'}):
            # Should not raise exception, but log error
            try:
                processor.store_findings_in_s3([finding])
            except Exception:
                pytest.fail("store_findings_in_s3 should handle S3 errors gracefully")


if __name__ == '__main__':
    pytest.main([__file__])
