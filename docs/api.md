# AWS Audit Platform - API Reference

## Overview

This document provides comprehensive API reference for the AWS Audit Platform Lambda functions, including function signatures, parameters, return values, and usage examples.

## Lambda Functions

### Security Findings Processor

**Function Name**: `security-findings-processor`  
**Runtime**: Python 3.11  
**Purpose**: Process and correlate security findings from multiple AWS security services

#### Function Handler
```python
def lambda_handler(event, context)
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `event` | dict | EventBridge event containing security finding data |
| `context` | LambdaContext | AWS Lambda runtime context |

#### Event Structure

##### Security Hub Finding Event
```json
{
  "Records": [{
    "eventSource": "aws:securityhub",
    "eventName": "SecurityHubFinding",
    "eventSourceARN": "arn:aws:securityhub:us-east-1:123456789012:finding/test-finding",
    "awsRegion": "us-east-1",
    "eventTime": "2024-08-27T10:00:00Z",
    "detail": {
      "findings": [{
        "Id": "finding-id",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "GeneratorId": "security-control/EC2.1",
        "AwsAccountId": "123456789012",
        "Region": "us-east-1",
        "Title": "EC2 instances should not have a public IP address",
        "Description": "Control description",
        "Severity": {"Label": "HIGH"},
        "Compliance": {"Status": "FAILED"},
        "Resources": [{
          "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
          "Type": "AwsEc2Instance"
        }],
        "CreatedAt": "2024-08-27T10:00:00.000Z",
        "UpdatedAt": "2024-08-27T10:00:00.000Z"
      }]
    }
  }]
}
```

##### GuardDuty Finding Event
```json
{
  "Records": [{
    "eventSource": "aws:guardduty",
    "eventName": "GuardDutyFinding",
    "detail": {
      "id": "finding-id",
      "type": "Trojan:EC2/DNSDataExfiltration",
      "severity": 8.5,
      "title": "DNS data exfiltration detected",
      "description": "EC2 instance performing DNS data exfiltration",
      "accountId": "123456789012",
      "region": "us-east-1",
      "resource": {
        "instanceDetails": {
          "instanceId": "i-1234567890abcdef0"
        }
      },
      "createdAt": "2024-08-27T10:00:00.000Z",
      "updatedAt": "2024-08-27T10:00:00.000Z"
    }
  }]
}
```

#### Return Value
```json
{
  "statusCode": 200,
  "body": "{\"message\": \"Successfully processed N findings\", \"findings_processed\": N}"
}
```

#### Error Response
```json
{
  "statusCode": 500,
  "body": "{\"error\": \"Error message\"}"
}
```

#### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `S3_BUCKET_NAME` | Yes | S3 bucket for storing findings | `security-findings-bucket` |
| `SNS_TOPIC_ARN` | Yes | SNS topic for alerts | `arn:aws:sns:us-east-1:123456789012:security-alerts` |
| `ENVIRONMENT` | No | Environment name | `production` |
| `LOG_LEVEL` | No | Logging level | `INFO` |

#### Usage Example
```python
import json
import boto3

# Simulate EventBridge event
event = {
    "Records": [{
        "eventSource": "aws:securityhub",
        "detail": {
            "findings": [
                # Security Hub finding data
            ]
        }
    }]
}

# Invoke Lambda function
lambda_client = boto3.client('lambda')
response = lambda_client.invoke(
    FunctionName='security-findings-processor',
    InvocationType='Event',
    Payload=json.dumps(event)
)
```

### Dashboard Generator

**Function Name**: `dashboard-generator`  
**Runtime**: Python 3.11  
**Purpose**: Create and update CloudWatch dashboards dynamically

#### Function Handler
```python
def lambda_handler(event, context)
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `event` | dict | CloudWatch Events scheduled event or manual trigger |
| `context` | LambdaContext | AWS Lambda runtime context |

#### Event Structure

##### Scheduled Event
```json
{
  "source": ["aws.events"],
  "detail-type": ["Scheduled Event"],
  "detail": {},
  "time": "2024-08-27T10:00:00Z",
  "region": "us-east-1",
  "account": "123456789012"
}
```

##### Manual Trigger Event
```json
{
  "dashboard_type": "executive",
  "account_ids": ["123456789012", "123456789013"],
  "time_range": "24h",
  "refresh": true
}
```

#### Dashboard Types

| Type | Description | Widgets |
|------|-------------|---------|
| `executive` | High-level security metrics | Security score, compliance status, critical findings |
| `operational` | Detailed operational metrics | Service metrics, processing latency, error rates |
| `compliance` | Compliance-focused view | CIS compliance, PCI-DSS status, failed controls |
| `account` | Account-specific dashboard | Per-account findings, resource compliance |

#### Return Value
```json
{
  "statusCode": 200,
  "body": "{\"message\": \"Dashboards updated successfully\", \"dashboards\": [\"executive\", \"operational\"]}"
}
```

#### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `DASHBOARD_PREFIX` | No | Prefix for dashboard names | `Security-` |
| `DEFAULT_REGION` | No | Default AWS region | `us-east-1` |
| `ACCOUNT_LIST_S3_BUCKET` | Yes | S3 bucket containing account list | `security-config-bucket` |

### Cost Analyzer

**Function Name**: `cost-analyzer`  
**Runtime**: Python 3.11  
**Purpose**: Analyze costs and generate optimization recommendations

#### Function Handler
```python
def lambda_handler(event, context)
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `event` | dict | CloudWatch Events scheduled event or Cost Explorer event |
| `context` | LambdaContext | AWS Lambda runtime context |

#### Event Structure

##### Scheduled Analysis
```json
{
  "source": ["aws.events"],
  "detail-type": ["Scheduled Event"],
  "detail": {
    "analysis_type": "daily",
    "scope": "all_accounts"
  }
}
```

##### Cost Anomaly Event
```json
{
  "source": ["aws.costexplorer"],
  "detail-type": ["Cost Anomaly Detection"],
  "detail": {
    "anomaly": {
      "anomalyId": "anomaly-id",
      "anomalyScore": {
        "maxScore": 95.5
      },
      "impact": {
        "maxImpact": 150.0
      },
      "dimensionKey": "SERVICE",
      "dimensionValue": "Amazon GuardDuty"
    }
  }
}
```

#### Analysis Types

| Type | Description | Output |
|------|-------------|--------|
| `daily` | Daily cost analysis | Service breakdown, trends |
| `monthly` | Monthly cost analysis | Month-over-month comparison |
| `optimization` | Cost optimization analysis | Recommendations, potential savings |
| `anomaly` | Cost anomaly analysis | Anomaly details, root cause |
| `forecast` | Cost forecasting | 30-day cost forecast |

#### Return Value
```json
{
  "statusCode": 200,
  "body": "{\"analysis_results\": {...}, \"recommendations\": [...], \"total_cost\": 1234.56}"
}
```

#### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `COST_ALERT_TOPIC_ARN` | Yes | SNS topic for cost alerts | `arn:aws:sns:us-east-1:123456789012:cost-alerts` |
| `COST_THRESHOLD_DAILY` | No | Daily cost threshold | `1000` |
| `COST_THRESHOLD_MONTHLY` | No | Monthly cost threshold | `30000` |

## Data Classes

### SecurityFinding

A dataclass representing a normalized security finding from any AWS security service.

#### Class Definition
```python
@dataclass
class SecurityFinding:
    finding_id: str
    account_id: str
    region: str
    service: str
    severity: str
    title: str
    description: str
    resource_id: str
    compliance_status: str
    created_at: str
    updated_at: Optional[str] = None
    remediation: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
```

#### Properties

| Property | Type | Description | Example |
|----------|------|-------------|---------|
| `finding_id` | str | Unique finding identifier | `finding-12345` |
| `account_id` | str | AWS account ID | `123456789012` |
| `region` | str | AWS region | `us-east-1` |
| `service` | str | Source AWS service | `SecurityHub` |
| `severity` | str | Finding severity | `HIGH` |
| `title` | str | Finding title | `EC2 instance has public IP` |
| `description` | str | Finding description | `Detailed description` |
| `resource_id` | str | Affected resource ID | `i-1234567890abcdef0` |
| `compliance_status` | str | Compliance status | `FAILED` |
| `created_at` | str | Creation timestamp | `2024-08-27T10:00:00Z` |
| `updated_at` | str | Update timestamp | `2024-08-27T10:05:00Z` |
| `remediation` | str | Remediation guidance | `Remove public IP` |
| `tags` | dict | Resource tags | `{"Environment": "prod"}` |

#### Methods

##### to_dict()
Converts the SecurityFinding to a dictionary for JSON serialization.

```python
finding = SecurityFinding(
    finding_id="test-id",
    account_id="123456789012",
    region="us-east-1",
    service="SecurityHub",
    severity="HIGH",
    title="Test Finding",
    description="Test description",
    resource_id="test-resource",
    compliance_status="FAILED",
    created_at="2024-08-27T10:00:00Z"
)

finding_dict = finding.to_dict()
# Returns: {"finding_id": "test-id", "account_id": "123456789012", ...}
```

##### from_security_hub()
Class method to create SecurityFinding from Security Hub finding data.

```python
security_hub_finding = {
    "Id": "finding-id",
    "AwsAccountId": "123456789012",
    "Region": "us-east-1",
    "Title": "Finding title",
    # ... other Security Hub fields
}

finding = SecurityFinding.from_security_hub(security_hub_finding)
```

##### from_guardduty()
Class method to create SecurityFinding from GuardDuty finding data.

```python
guardduty_finding = {
    "id": "finding-id",
    "accountId": "123456789012",
    "region": "us-east-1",
    "type": "Trojan:EC2/DNSDataExfiltration",
    # ... other GuardDuty fields
}

finding = SecurityFinding.from_guardduty(guardduty_finding)
```

## Utility Functions

### Security Score Calculation

#### Function Signature
```python
def calculate_security_score(findings: List[SecurityFinding]) -> float
```

#### Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `findings` | List[SecurityFinding] | List of security findings |

#### Return Value
| Type | Description | Range |
|------|-------------|-------|
| `float` | Security score | 0.0 - 100.0 |

#### Scoring Algorithm
```python
# Base score starts at 100
base_score = 100.0

# Deduct points based on severity
severity_weights = {
    'CRITICAL': 10,
    'HIGH': 7,
    'MEDIUM': 4,
    'LOW': 2,
    'INFORMATIONAL': 1
}

total_deduction = sum(severity_weights.get(finding.severity, 0) for finding in findings)
security_score = max(0, base_score - total_deduction)
```

#### Usage Example
```python
findings = [
    SecurityFinding(severity='CRITICAL', ...),
    SecurityFinding(severity='HIGH', ...),
    SecurityFinding(severity='LOW', ...)
]

score = calculate_security_score(findings)
print(f"Security Score: {score}/100")
```

### Criticality Determination

#### Function Signature
```python
def determine_criticality(finding: SecurityFinding) -> str
```

#### Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `finding` | SecurityFinding | Security finding to evaluate |

#### Return Value
| Type | Description | Values |
|------|-------------|--------|
| `str` | Criticality level | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |

#### Criticality Rules
1. **CRITICAL**: Severity is CRITICAL OR (HIGH + compliance FAILED + public resource)
2. **HIGH**: Severity is HIGH OR (MEDIUM + compliance FAILED)
3. **MEDIUM**: Severity is MEDIUM OR (LOW + compliance FAILED)
4. **LOW**: All other findings

#### Usage Example
```python
finding = SecurityFinding(
    severity='HIGH',
    compliance_status='FAILED',
    resource_id='public-s3-bucket',
    ...
)

criticality = determine_criticality(finding)
print(f"Finding criticality: {criticality}")
```

## Error Handling

### Standard Error Response Format
```json
{
  "statusCode": 500,
  "body": {
    "error": "Error type",
    "message": "Detailed error message",
    "timestamp": "2024-08-27T10:00:00Z",
    "request_id": "aws-request-id"
  }
}
```

### Common Error Types

| Error Type | Status Code | Description |
|------------|-------------|-------------|
| `ValidationError` | 400 | Invalid input parameters |
| `AuthorizationError` | 403 | Insufficient permissions |
| `ServiceError` | 500 | AWS service error |
| `ProcessingError` | 500 | Data processing error |
| `StorageError` | 500 | S3 storage error |
| `NotificationError` | 500 | SNS notification error |

### Error Handling Best Practices

#### Retry Logic
```python
import time
import random
from botocore.exceptions import ClientError

def exponential_backoff_retry(func, max_retries=3):
    for attempt in range(max_retries):
        try:
            return func()
        except ClientError as e:
            if attempt == max_retries - 1:
                raise
            
            # Exponential backoff with jitter
            delay = (2 ** attempt) + random.uniform(0, 1)
            time.sleep(delay)
```

#### Graceful Error Handling
```python
def process_finding_safely(finding_data):
    try:
        finding = SecurityFinding.from_security_hub(finding_data)
        store_finding(finding)
        return {"status": "success", "finding_id": finding.finding_id}
    except ValidationError as e:
        logger.warning(f"Invalid finding data: {e}")
        return {"status": "skipped", "reason": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error processing finding: {e}")
        return {"status": "error", "reason": str(e)}
```

## CloudWatch Metrics

### Custom Metrics Published

| Metric Name | Namespace | Dimensions | Unit | Description |
|-------------|-----------|------------|------|-------------|
| `FindingsProcessed` | `AWS/Security` | Service, Region | Count | Number of findings processed |
| `ProcessingLatency` | `AWS/Security` | Function | Milliseconds | Processing time per finding |
| `ErrorRate` | `AWS/Security` | Function, ErrorType | Percent | Error rate by function |
| `SecurityScore` | `AWS/Security` | Account, Region | None | Security score (0-100) |
| `CriticalFindings` | `AWS/Security` | Account, Service | Count | Number of critical findings |
| `ComplianceStatus` | `AWS/Security` | Standard, Account | Percent | Compliance percentage |

### Metric Usage Examples

#### Publishing Custom Metrics
```python
import boto3

cloudwatch = boto3.client('cloudwatch')

# Publish security score metric
cloudwatch.put_metric_data(
    Namespace='AWS/Security',
    MetricData=[
        {
            'MetricName': 'SecurityScore',
            'Value': 85.5,
            'Unit': 'None',
            'Dimensions': [
                {
                    'Name': 'Account',
                    'Value': '123456789012'
                },
                {
                    'Name': 'Region',
                    'Value': 'us-east-1'
                }
            ]
        }
    ]
)
```

#### Querying Metrics
```python
import boto3
from datetime import datetime, timedelta

cloudwatch = boto3.client('cloudwatch')

# Get security score over last 24 hours
response = cloudwatch.get_metric_statistics(
    Namespace='AWS/Security',
    MetricName='SecurityScore',
    Dimensions=[
        {
            'Name': 'Account',
            'Value': '123456789012'
        }
    ],
    StartTime=datetime.utcnow() - timedelta(hours=24),
    EndTime=datetime.utcnow(),
    Period=3600,  # 1 hour
    Statistics=['Average', 'Maximum', 'Minimum']
)
```

## Configuration Reference

### Lambda Function Configuration

#### Security Findings Processor
```yaml
FunctionName: security-findings-processor
Runtime: python3.11
MemorySize: 1024
Timeout: 300
ReservedConcurrency: 100
Environment:
  Variables:
    S3_BUCKET_NAME: security-findings-bucket
    SNS_TOPIC_ARN: arn:aws:sns:us-east-1:123456789012:security-alerts
    LOG_LEVEL: INFO
```

#### Dashboard Generator
```yaml
FunctionName: dashboard-generator
Runtime: python3.11
MemorySize: 512
Timeout: 180
ReservedConcurrency: 10
Environment:
  Variables:
    DASHBOARD_PREFIX: Security-
    DEFAULT_REGION: us-east-1
```

#### Cost Analyzer
```yaml
FunctionName: cost-analyzer
Runtime: python3.11
MemorySize: 256
Timeout: 60
ReservedConcurrency: 5
Environment:
  Variables:
    COST_ALERT_TOPIC_ARN: arn:aws:sns:us-east-1:123456789012:cost-alerts
    COST_THRESHOLD_DAILY: 1000
```

### IAM Permissions

#### Lambda Execution Role Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::security-findings-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sns:Publish"
      ],
      "Resource": "arn:aws:sns:*:*:security-alerts"
    },
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricData",
        "cloudwatch:PutDashboard"
      ],
      "Resource": "*"
    }
  ]
}
```

---

**API Reference Version**: 1.0  
**Last Updated**: August 27, 2025  
**Next Review**: November 27, 2025
