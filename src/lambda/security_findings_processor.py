"""
AWS Platform Audit System - Security Findings Processor Lambda Function
=========================================================================

This Lambda function processes security findings from various AWS security services
and performs the following operations:
1. Normalizes findings from different sources
2. Enriches findings with additional context
3. Calculates security scores
4. Sends notifications based on severity
5. Stores processed findings in S3 data lake
6. Updates CloudWatch metrics

This is designed to be an enterprise-grade, production-ready solution with
comprehensive error handling, logging, and monitoring capabilities.

Author: AWS Audit Platform Team
Version: 1.0.0
Last Updated: 2024
"""

import json
import boto3
import logging
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError, BotoCoreError
from dataclasses import dataclass, asdict
import hashlib
import uuid

# Configure logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.environ.get('LOG_LEVEL', 'INFO')))

# Initialize AWS clients
sns_client = boto3.client('sns')
s3_client = boto3.client('s3')
cloudwatch_client = boto3.client('cloudwatch')
securityhub_client = boto3.client('securityhub')

# Configuration from environment variables
SECURITY_SNS_TOPIC_ARN = os.environ.get('SECURITY_SNS_TOPIC_ARN', '')
COMPLIANCE_SNS_TOPIC_ARN = os.environ.get('COMPLIANCE_SNS_TOPIC_ARN', '')
OPERATIONAL_SNS_TOPIC_ARN = os.environ.get('OPERATIONAL_SNS_TOPIC_ARN', '')
S3_BUCKET = os.environ.get('S3_BUCKET', '')
KMS_KEY_ID = os.environ.get('KMS_KEY_ID', '')
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

@dataclass
class SecurityFinding:
    """Normalized security finding data structure"""
    finding_id: str
    account_id: str
    region: str
    service: str
    severity: str
    title: str
    description: str
    resource_id: str
    resource_type: str
    compliance_status: str
    first_observed_at: str
    last_observed_at: str
    workflow_state: str
    record_state: str
    raw_finding: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

@dataclass
class SecurityMetrics:
    """Security metrics for CloudWatch"""
    account_id: str
    region: str
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    compliance_score: float
    security_score: float
    timestamp: str

class SecurityFindingsProcessor:
    """Main processor class for security findings"""
    
    def __init__(self):
        self.logger = logger
        self.findings_processed = 0
        self.errors_encountered = 0
        
    def handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """
        Main Lambda handler function
        
        Args:
            event: AWS Lambda event
            context: AWS Lambda context
            
        Returns:
            Response dictionary with processing results
        """
        try:
            self.logger.info(f"Processing security findings event: {json.dumps(event, default=str)}")
            
            # Extract event details
            source = event.get('source', '')
            detail_type = event.get('detail-type', '')
            detail = event.get('detail', {})
            account_id = event.get('account', '')
            region = event.get('region', '')
            
            # Process based on event source
            if source == 'aws.securityhub':
                findings = self._process_security_hub_findings(detail, account_id, region)
            elif source == 'aws.guardduty':
                findings = self._process_guardduty_findings(detail, account_id, region)
            elif source == 'aws.access-analyzer':
                findings = self._process_access_analyzer_findings(detail, account_id, region)
            elif source == 'aws.config':
                findings = self._process_config_findings(detail, account_id, region)
            elif source == 'aws.inspector2':
                findings = self._process_inspector_findings(detail, account_id, region)
            elif source == 'aws.macie':
                findings = self._process_macie_findings(detail, account_id, region)
            else:
                self.logger.warning(f"Unknown event source: {source}")
                return self._create_response(400, f"Unknown event source: {source}")
            
            # Process each finding
            processed_findings = []
            for finding in findings:
                try:
                    processed_finding = self._enrich_finding(finding)
                    processed_findings.append(processed_finding)
                    self.findings_processed += 1
                    
                    # Send notifications based on severity
                    self._send_notifications(processed_finding)
                    
                except Exception as e:
                    self.logger.error(f"Error processing individual finding: {str(e)}")
                    self.errors_encountered += 1
                    continue
            
            # Store findings in S3
            if processed_findings:
                self._store_findings_in_s3(processed_findings, account_id, region)
            
            # Update CloudWatch metrics
            self._update_cloudwatch_metrics(processed_findings, account_id, region)
            
            # Log processing summary
            self.logger.info(f"Processing completed. Findings processed: {self.findings_processed}, Errors: {self.errors_encountered}")
            
            return self._create_response(200, "Successfully processed security findings", {
                'findings_processed': self.findings_processed,
                'errors_encountered': self.errors_encountered,
                'account_id': account_id,
                'region': region
            })
            
        except Exception as e:
            self.logger.error(f"Critical error in security findings processor: {str(e)}")
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            
            # Send operational alert
            self._send_operational_alert(f"Critical error in security findings processor: {str(e)}")
            
            return self._create_response(500, f"Internal error: {str(e)}")
    
    def _process_security_hub_findings(self, detail: Dict[str, Any], account_id: str, region: str) -> List[SecurityFinding]:
        """Process Security Hub findings"""
        findings = []
        
        for finding_data in detail.get('findings', []):
            try:
                finding = SecurityFinding(
                    finding_id=finding_data.get('Id', ''),
                    account_id=account_id,
                    region=region,
                    service='SecurityHub',
                    severity=finding_data.get('Severity', {}).get('Label', 'UNKNOWN'),
                    title=finding_data.get('Title', ''),
                    description=finding_data.get('Description', ''),
                    resource_id=finding_data.get('Resources', [{}])[0].get('Id', ''),
                    resource_type=finding_data.get('Resources', [{}])[0].get('Type', ''),
                    compliance_status=finding_data.get('Compliance', {}).get('Status', 'UNKNOWN'),
                    first_observed_at=finding_data.get('FirstObservedAt', ''),
                    last_observed_at=finding_data.get('LastObservedAt', ''),
                    workflow_state=finding_data.get('Workflow', {}).get('Status', 'NEW'),
                    record_state=finding_data.get('RecordState', 'ACTIVE'),
                    raw_finding=finding_data
                )
                findings.append(finding)
                
            except Exception as e:
                self.logger.error(f"Error processing Security Hub finding: {str(e)}")
                continue
                
        return findings
    
    def _process_guardduty_findings(self, detail: Dict[str, Any], account_id: str, region: str) -> List[SecurityFinding]:
        """Process GuardDuty findings"""
        findings = []
        
        try:
            severity_score = detail.get('severity', 0)
            severity_label = self._convert_guardduty_severity(severity_score)
            
            finding = SecurityFinding(
                finding_id=detail.get('id', ''),
                account_id=account_id,
                region=region,
                service='GuardDuty',
                severity=severity_label,
                title=detail.get('title', ''),
                description=detail.get('description', ''),
                resource_id=detail.get('resource', {}).get('instanceDetails', {}).get('instanceId', ''),
                resource_type='AWS::EC2::Instance',
                compliance_status='NON_COMPLIANT' if severity_score >= 7.0 else 'COMPLIANT',
                first_observed_at=detail.get('createdAt', ''),
                last_observed_at=detail.get('updatedAt', ''),
                workflow_state='NEW',
                record_state='ACTIVE',
                raw_finding=detail
            )
            findings.append(finding)
            
        except Exception as e:
            self.logger.error(f"Error processing GuardDuty finding: {str(e)}")
            
        return findings
    
    def _process_access_analyzer_findings(self, detail: Dict[str, Any], account_id: str, region: str) -> List[SecurityFinding]:
        """Process Access Analyzer findings"""
        findings = []
        
        try:
            finding = SecurityFinding(
                finding_id=detail.get('id', ''),
                account_id=account_id,
                region=region,
                service='AccessAnalyzer',
                severity='HIGH',  # Access Analyzer findings are typically high priority
                title=f"External access detected: {detail.get('resourceType', '')}",
                description=detail.get('condition', {}).get('description', ''),
                resource_id=detail.get('resource', ''),
                resource_type=detail.get('resourceType', ''),
                compliance_status='NON_COMPLIANT',
                first_observed_at=detail.get('createdAt', ''),
                last_observed_at=detail.get('analyzedAt', ''),
                workflow_state='NEW',
                record_state='ACTIVE',
                raw_finding=detail
            )
            findings.append(finding)
            
        except Exception as e:
            self.logger.error(f"Error processing Access Analyzer finding: {str(e)}")
            
        return findings
    
    def _process_config_findings(self, detail: Dict[str, Any], account_id: str, region: str) -> List[SecurityFinding]:
        """Process AWS Config compliance changes"""
        findings = []
        
        try:
            new_evaluation = detail.get('newEvaluationResult', {})
            config_rule_name = detail.get('configRuleName', '')
            
            # Only process non-compliant findings
            if new_evaluation.get('complianceType') == 'NON_COMPLIANT':
                finding = SecurityFinding(
                    finding_id=f"{config_rule_name}-{detail.get('resourceId', '')}-{datetime.now().isoformat()}",
                    account_id=account_id,
                    region=region,
                    service='Config',
                    severity=self._get_config_rule_severity(config_rule_name),
                    title=f"Config Rule Violation: {config_rule_name}",
                    description=new_evaluation.get('annotation', ''),
                    resource_id=detail.get('resourceId', ''),
                    resource_type=detail.get('resourceType', ''),
                    compliance_status='NON_COMPLIANT',
                    first_observed_at=detail.get('notificationCreationTime', ''),
                    last_observed_at=detail.get('notificationCreationTime', ''),
                    workflow_state='NEW',
                    record_state='ACTIVE',
                    raw_finding=detail
                )
                findings.append(finding)
            
        except Exception as e:
            self.logger.error(f"Error processing Config finding: {str(e)}")
            
        return findings
    
    def _process_inspector_findings(self, detail: Dict[str, Any], account_id: str, region: str) -> List[SecurityFinding]:
        """Process Amazon Inspector findings"""
        findings = []
        
        try:
            finding = SecurityFinding(
                finding_id=detail.get('findingArn', ''),
                account_id=account_id,
                region=region,
                service='Inspector',
                severity=detail.get('severity', 'MEDIUM'),
                title=detail.get('title', ''),
                description=detail.get('description', ''),
                resource_id=detail.get('resources', [{}])[0].get('id', ''),
                resource_type=detail.get('type', ''),
                compliance_status='NON_COMPLIANT',
                first_observed_at=detail.get('firstObservedAt', ''),
                last_observed_at=detail.get('lastObservedAt', ''),
                workflow_state='NEW',
                record_state='ACTIVE',
                raw_finding=detail
            )
            findings.append(finding)
            
        except Exception as e:
            self.logger.error(f"Error processing Inspector finding: {str(e)}")
            
        return findings
    
    def _process_macie_findings(self, detail: Dict[str, Any], account_id: str, region: str) -> List[SecurityFinding]:
        """Process Amazon Macie findings"""
        findings = []
        
        try:
            finding = SecurityFinding(
                finding_id=detail.get('id', ''),
                account_id=account_id,
                region=region,
                service='Macie',
                severity=detail.get('severity', {}).get('description', 'MEDIUM'),
                title=detail.get('title', ''),
                description=detail.get('description', ''),
                resource_id=detail.get('resourcesAffected', {}).get('s3Bucket', {}).get('arn', ''),
                resource_type='AWS::S3::Bucket',
                compliance_status='NON_COMPLIANT',
                first_observed_at=detail.get('createdAt', ''),
                last_observed_at=detail.get('updatedAt', ''),
                workflow_state='NEW',
                record_state='ACTIVE',
                raw_finding=detail
            )
            findings.append(finding)
            
        except Exception as e:
            self.logger.error(f"Error processing Macie finding: {str(e)}")
            
        return findings
    
    def _enrich_finding(self, finding: SecurityFinding) -> SecurityFinding:
        """Enrich finding with additional context and metadata"""
        try:
            # Add risk score based on severity and resource type
            risk_score = self._calculate_risk_score(finding)
            
            # Add business impact assessment
            business_impact = self._assess_business_impact(finding)
            
            # Add remediation recommendations
            remediation = self._get_remediation_recommendations(finding)
            
            # Enrich the raw finding with additional data
            finding.raw_finding.update({
                'enrichment': {
                    'risk_score': risk_score,
                    'business_impact': business_impact,
                    'remediation_recommendations': remediation,
                    'enriched_at': datetime.now(timezone.utc).isoformat(),
                    'processor_version': '1.0.0'
                }
            })
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error enriching finding: {str(e)}")
            return finding
    
    def _send_notifications(self, finding: SecurityFinding) -> None:
        """Send notifications based on finding severity"""
        try:
            message = self._create_notification_message(finding)
            
            # Send to appropriate SNS topic based on severity
            if finding.severity in ['CRITICAL', 'HIGH']:
                if SECURITY_SNS_TOPIC_ARN:
                    self._publish_to_sns(SECURITY_SNS_TOPIC_ARN, message, finding.severity)
            
            if finding.service == 'Config' and finding.compliance_status == 'NON_COMPLIANT':
                if COMPLIANCE_SNS_TOPIC_ARN:
                    self._publish_to_sns(COMPLIANCE_SNS_TOPIC_ARN, message, 'COMPLIANCE')
            
        except Exception as e:
            self.logger.error(f"Error sending notifications: {str(e)}")
    
    def _store_findings_in_s3(self, findings: List[SecurityFinding], account_id: str, region: str) -> None:
        """Store processed findings in S3 data lake"""
        try:
            if not S3_BUCKET:
                self.logger.warning("S3_BUCKET not configured, skipping S3 storage")
                return
            
            timestamp = datetime.now(timezone.utc)
            date_prefix = timestamp.strftime('%Y/%m/%d')
            hour_prefix = timestamp.strftime('%H')
            
            # Create S3 key with partitioning
            s3_key = f"security-findings/account_id={account_id}/region={region}/date={date_prefix}/hour={hour_prefix}/findings-{timestamp.strftime('%Y%m%d%H%M%S')}.json"
            
            # Prepare data for storage
            findings_data = {
                'metadata': {
                    'account_id': account_id,
                    'region': region,
                    'processed_at': timestamp.isoformat(),
                    'findings_count': len(findings),
                    'processor_version': '1.0.0'
                },
                'findings': [finding.to_dict() for finding in findings]
            }
            
            # Upload to S3
            s3_client.put_object(
                Bucket=S3_BUCKET,
                Key=s3_key,
                Body=json.dumps(findings_data, default=str, indent=2),
                ContentType='application/json',
                ServerSideEncryption='aws:kms',
                SSEKMSKeyId=KMS_KEY_ID if KMS_KEY_ID else None
            )
            
            self.logger.info(f"Successfully stored {len(findings)} findings in S3: s3://{S3_BUCKET}/{s3_key}")
            
        except Exception as e:
            self.logger.error(f"Error storing findings in S3: {str(e)}")
    
    def _update_cloudwatch_metrics(self, findings: List[SecurityFinding], account_id: str, region: str) -> None:
        """Update CloudWatch metrics based on processed findings"""
        try:
            # Calculate metrics
            metrics = SecurityMetrics(
                account_id=account_id,
                region=region,
                total_findings=len(findings),
                critical_findings=len([f for f in findings if f.severity == 'CRITICAL']),
                high_findings=len([f for f in findings if f.severity == 'HIGH']),
                medium_findings=len([f for f in findings if f.severity == 'MEDIUM']),
                low_findings=len([f for f in findings if f.severity == 'LOW']),
                compliance_score=self._calculate_compliance_score(findings),
                security_score=self._calculate_security_score(findings),
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            
            # Prepare CloudWatch metrics
            metric_data = [
                {
                    'MetricName': 'TotalFindings',
                    'Dimensions': [
                        {'Name': 'AccountId', 'Value': account_id},
                        {'Name': 'Region', 'Value': region}
                    ],
                    'Value': metrics.total_findings,
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'CriticalFindings',
                    'Dimensions': [
                        {'Name': 'AccountId', 'Value': account_id},
                        {'Name': 'Region', 'Value': region}
                    ],
                    'Value': metrics.critical_findings,
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'SecurityScore',
                    'Dimensions': [
                        {'Name': 'AccountId', 'Value': account_id},
                        {'Name': 'Region', 'Value': region}
                    ],
                    'Value': metrics.security_score,
                    'Unit': 'Percent'
                },
                {
                    'MetricName': 'ComplianceRatio',
                    'Dimensions': [
                        {'Name': 'AccountId', 'Value': account_id},
                        {'Name': 'Region', 'Value': region}
                    ],
                    'Value': metrics.compliance_score,
                    'Unit': 'Percent'
                }
            ]
            
            # Publish metrics to CloudWatch
            cloudwatch_client.put_metric_data(
                Namespace='Custom/SecurityPlatform',
                MetricData=metric_data
            )
            
            self.logger.info(f"Successfully published CloudWatch metrics for {len(metric_data)} metrics")
            
        except Exception as e:
            self.logger.error(f"Error updating CloudWatch metrics: {str(e)}")
    
    # Helper methods
    def _convert_guardduty_severity(self, severity_score: float) -> str:
        """Convert GuardDuty severity score to label"""
        if severity_score >= 7.0:
            return 'HIGH'
        elif severity_score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_config_rule_severity(self, rule_name: str) -> str:
        """Get severity level for Config rule"""
        critical_rules = [
            'root-access-key-check',
            'iam-password-policy',
            'cloudtrail-enabled'
        ]
        high_rules = [
            'encrypted-volumes',
            's3-bucket-server-side-encryption-enabled',
            'security-group-ssh-restricted'
        ]
        
        if rule_name in critical_rules:
            return 'CRITICAL'
        elif rule_name in high_rules:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _calculate_risk_score(self, finding: SecurityFinding) -> float:
        """Calculate risk score for finding"""
        severity_scores = {
            'CRITICAL': 10.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5
        }
        
        base_score = severity_scores.get(finding.severity, 5.0)
        
        # Adjust based on resource type
        if 'IAM' in finding.resource_type:
            base_score *= 1.2
        elif 'S3' in finding.resource_type:
            base_score *= 1.1
        
        return min(base_score, 10.0)
    
    def _assess_business_impact(self, finding: SecurityFinding) -> str:
        """Assess business impact of finding"""
        if finding.severity == 'CRITICAL':
            return 'HIGH'
        elif finding.severity == 'HIGH':
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_remediation_recommendations(self, finding: SecurityFinding) -> List[str]:
        """Get remediation recommendations"""
        recommendations = []
        
        if finding.service == 'SecurityHub':
            recommendations.append("Review Security Hub finding details")
            recommendations.append("Follow AWS security best practices")
        elif finding.service == 'GuardDuty':
            recommendations.append("Investigate suspicious activity")
            recommendations.append("Review network traffic patterns")
        elif finding.service == 'Config':
            recommendations.append("Update resource configuration")
            recommendations.append("Ensure compliance with organizational policies")
        
        return recommendations
    
    def _calculate_compliance_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate overall compliance score"""
        if not findings:
            return 100.0
        
        non_compliant = len([f for f in findings if f.compliance_status == 'NON_COMPLIANT'])
        return max(0.0, 100.0 - (non_compliant / len(findings) * 100.0))
    
    def _calculate_security_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate overall security score"""
        if not findings:
            return 100.0
        
        critical_count = len([f for f in findings if f.severity == 'CRITICAL'])
        high_count = len([f for f in findings if f.severity == 'HIGH'])
        
        # Weighted scoring
        penalty = (critical_count * 10) + (high_count * 5)
        return max(0.0, 100.0 - penalty)
    
    def _create_notification_message(self, finding: SecurityFinding) -> Dict[str, Any]:
        """Create notification message"""
        return {
            'title': f'🚨 Security Alert: {finding.title}',
            'severity': finding.severity,
            'account_id': finding.account_id,
            'region': finding.region,
            'service': finding.service,
            'resource_id': finding.resource_id,
            'description': finding.description,
            'compliance_status': finding.compliance_status,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'finding_id': finding.finding_id
        }
    
    def _publish_to_sns(self, topic_arn: str, message: Dict[str, Any], severity: str) -> None:
        """Publish message to SNS topic"""
        try:
            sns_client.publish(
                TopicArn=topic_arn,
                Subject=f"[{severity}] Security Finding Alert",
                Message=json.dumps(message, default=str, indent=2)
            )
        except Exception as e:
            self.logger.error(f"Error publishing to SNS: {str(e)}")
    
    def _send_operational_alert(self, error_message: str) -> None:
        """Send operational alert for system errors"""
        if OPERATIONAL_SNS_TOPIC_ARN:
            try:
                sns_client.publish(
                    TopicArn=OPERATIONAL_SNS_TOPIC_ARN,
                    Subject="🔥 Security Platform Error",
                    Message=json.dumps({
                        'error': error_message,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'function_name': 'security-findings-processor'
                    }, indent=2)
                )
            except Exception as e:
                self.logger.error(f"Error sending operational alert: {str(e)}")
    
    def _create_response(self, status_code: int, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create standardized response"""
        response = {
            'statusCode': status_code,
            'message': message,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        if data:
            response['data'] = data
        
        return response

# Global processor instance
processor = SecurityFindingsProcessor()

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda entry point
    """
    return processor.handler(event, context)
