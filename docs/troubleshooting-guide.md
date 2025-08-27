# AWS Audit Platform - Troubleshooting Guide

## Overview

This troubleshooting guide provides solutions for common issues encountered when deploying, configuring, and operating the AWS Audit Platform. The guide is organized by component and includes diagnostic steps, common solutions, and escalation procedures.

## General Troubleshooting Approach

### 1. Identify the Issue
- **Symptoms**: What is not working as expected?
- **Scope**: Which accounts/regions/services are affected?
- **Timeline**: When did the issue start?
- **Changes**: What recent changes were made?

### 2. Gather Information
- **CloudWatch Logs**: Check Lambda function and service logs
- **CloudWatch Metrics**: Review performance and error metrics
- **AWS Service Health**: Check AWS Service Health Dashboard
- **Configuration**: Verify configuration files and environment variables

### 3. Apply Solution
- **Quick Fixes**: Apply known solutions first
- **Configuration Changes**: Update configuration if needed
- **Code Changes**: Deploy fixes if code changes are required
- **Infrastructure Changes**: Update infrastructure if needed

### 4. Verify Resolution
- **Functional Testing**: Verify the fix resolves the issue
- **Monitoring**: Ensure metrics return to normal
- **Documentation**: Update runbooks with new information

## Hub Account Issues

### Security Hub Not Receiving Findings

#### Symptoms
- No findings appearing in Security Hub dashboard
- Spoke accounts showing as "not integrated"
- EventBridge rules not triggering

#### Diagnostic Steps
```bash
# Check Security Hub status
aws securityhub get-enabled-standards --region us-east-1

# Verify master-member relationships
aws securityhub list-members --region us-east-1

# Check EventBridge rules
aws events list-rules --name-prefix "security-hub" --region us-east-1

# Verify rule targets
aws events list-targets-by-rule --rule "security-hub-findings-rule" --region us-east-1
```

#### Common Causes and Solutions

##### 1. IAM Permission Issues
**Cause**: Insufficient permissions for cross-account access

**Solution**:
```bash
# Verify hub account role
aws iam get-role --role-name SecurityHubServiceRole

# Check trust relationship
aws iam get-role --role-name SecurityHubServiceRole --query 'Role.AssumeRolePolicyDocument'

# Update role if needed
aws iam update-assume-role-policy --role-name SecurityHubServiceRole --policy-document file://trust-policy.json
```

##### 2. EventBridge Configuration Issues
**Cause**: EventBridge rules not properly configured

**Solution**:
```bash
# Recreate EventBridge rule
aws events put-rule \
  --name security-hub-findings-rule \
  --event-pattern '{"source":["aws.securityhub"],"detail-type":["Security Hub Findings - Imported"]}' \
  --state ENABLED

# Add Lambda target
aws events put-targets \
  --rule security-hub-findings-rule \
  --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:ACCOUNT:function:security-findings-processor"
```

##### 3. Regional Configuration Issues
**Cause**: Security Hub not enabled in all required regions

**Solution**:
```bash
# Enable Security Hub in all regions
for region in us-east-1 us-west-2 eu-west-1; do
  aws securityhub enable-security-hub --region $region
  aws securityhub enable-import-findings-for-product \
    --product-arn "arn:aws:securityhub:$region::product/aws/guardduty" \
    --region $region
done
```

### GuardDuty Not Detecting Threats

#### Symptoms
- No GuardDuty findings generated
- GuardDuty console shows "No threats detected"
- Missing GuardDuty data sources

#### Diagnostic Steps
```bash
# Check GuardDuty detector status
aws guardduty list-detectors --region us-east-1

# Get detector details
aws guardduty get-detector --detector-id DETECTOR-ID --region us-east-1

# Check data sources
aws guardduty get-detector --detector-id DETECTOR-ID --query 'DataSources' --region us-east-1

# Verify member accounts
aws guardduty list-members --detector-id DETECTOR-ID --region us-east-1
```

#### Common Causes and Solutions

##### 1. Data Sources Not Enabled
**Cause**: Required data sources (VPC Flow Logs, DNS logs) not enabled

**Solution**:
```bash
# Enable all data sources
aws guardduty update-detector \
  --detector-id DETECTOR-ID \
  --data-sources '{
    "S3Logs": {"Enable": true},
    "Kubernetes": {"AuditLogs": {"Enable": true}},
    "MalwareProtection": {"ScanEc2InstanceWithFindings": {"EbsVolumes": {"Enable": true}}}
  }' \
  --region us-east-1
```

##### 2. VPC Flow Logs Not Configured
**Cause**: VPC Flow Logs not enabled for monitored VPCs

**Solution**:
```bash
# Enable VPC Flow Logs for all VPCs
aws ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text | while read vpc_id; do
  aws ec2 create-flow-logs \
    --resource-type VPC \
    --resource-ids $vpc_id \
    --traffic-type ALL \
    --log-destination-type cloud-watch-logs \
    --log-group-name VPCFlowLogs
done
```

##### 3. Trusted IP Lists Misconfigured
**Cause**: Legitimate traffic being flagged as threats

**Solution**:
```bash
# Create trusted IP list
aws guardduty create-ip-set \
  --detector-id DETECTOR-ID \
  --name TrustedIPs \
  --format TXT \
  --location s3://your-bucket/trusted-ips.txt \
  --activate \
  --region us-east-1
```

### Config Service Issues

#### Symptoms
- Config rules not evaluating
- Configuration history missing
- Compliance status not updating

#### Diagnostic Steps
```bash
# Check Config service status
aws configservice describe-configuration-recorders --region us-east-1

# Verify delivery channel
aws configservice describe-delivery-channels --region us-east-1

# Check Config rules
aws configservice describe-config-rules --region us-east-1

# Verify rule compliance
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name RULE-NAME \
  --region us-east-1
```

#### Common Causes and Solutions

##### 1. Config Recorder Not Running
**Cause**: Configuration recorder stopped or misconfigured

**Solution**:
```bash
# Start Config recorder
aws configservice start-configuration-recorder \
  --configuration-recorder-name default \
  --region us-east-1

# Verify recorder status
aws configservice describe-configuration-recorder-status --region us-east-1
```

##### 2. S3 Bucket Permissions
**Cause**: Config can't write to S3 bucket

**Solution**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::config-bucket-name"
    },
    {
      "Sid": "AWSConfigBucketExistenceCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::config-bucket-name"
    },
    {
      "Sid": "AWSConfigBucketDelivery",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::config-bucket-name/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
```

##### 3. Conformance Pack Deployment Failures
**Cause**: Conformance packs failing to deploy

**Solution**:
```bash
# Check conformance pack status
aws configservice describe-conformance-packs --region us-east-1

# Redeploy failed conformance pack
aws configservice put-conformance-pack \
  --conformance-pack-name CIS-AWS-Foundations-Benchmark \
  --template-s3-uri s3://aws-config-conformance-packs/CISAWSFoundationsBenchmark.yaml \
  --region us-east-1
```

## Spoke Account Issues

### Cross-Account Access Problems

#### Symptoms
- Spoke accounts can't send findings to hub
- "Access Denied" errors in Lambda logs
- Missing findings from specific accounts

#### Diagnostic Steps
```bash
# Test cross-account role assumption
aws sts assume-role \
  --role-arn arn:aws:iam::HUB-ACCOUNT:role/SecurityAuditCrossAccountRole \
  --role-session-name test-session

# Check EventBridge cross-account permissions
aws events describe-rule --name security-findings-forwarding --region us-east-1

# Verify IAM role trust relationships
aws iam get-role --role-name SecurityAuditSpokeRole --query 'Role.AssumeRolePolicyDocument'
```

#### Common Causes and Solutions

##### 1. Trust Relationship Issues
**Cause**: IAM trust relationship not properly configured

**Solution**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::HUB-ACCOUNT-ID:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id"
        }
      }
    }
  ]
}
```

##### 2. EventBridge Cross-Account Rules
**Cause**: EventBridge rules not configured for cross-account delivery

**Solution**:
```bash
# Create cross-account EventBridge rule in spoke account
aws events put-rule \
  --name forward-security-findings \
  --event-pattern '{"source":["aws.securityhub","aws.guardduty","aws.config"]}' \
  --targets '[{
    "Id": "1",
    "Arn": "arn:aws:events:us-east-1:HUB-ACCOUNT:event-bus/security-hub",
    "RoleArn": "arn:aws:iam::SPOKE-ACCOUNT:role/EventBridgeRole"
  }]' \
  --region us-east-1
```

### Service Enablement Issues

#### Symptoms
- Security services not enabled in spoke accounts
- Missing service configurations
- Incomplete integration setup

#### Diagnostic Steps
```bash
# Check Security Hub enablement
aws securityhub get-enabled-standards --region us-east-1

# Verify GuardDuty status
aws guardduty list-detectors --region us-east-1

# Check Config status
aws configservice describe-configuration-recorders --region us-east-1

# Verify Access Analyzer
aws accessanalyzer list-analyzers --region us-east-1
```

#### Common Causes and Solutions

##### 1. Services Not Enabled
**Cause**: Security services not enabled in spoke account

**Solution**:
```bash
# Enable Security Hub
aws securityhub enable-security-hub --region us-east-1

# Accept invitation from hub account
aws securityhub accept-invitation \
  --master-id HUB-ACCOUNT-ID \
  --invitation-id INVITATION-ID \
  --region us-east-1

# Enable GuardDuty
aws guardduty create-detector --enable --region us-east-1

# Accept GuardDuty invitation
aws guardduty accept-invitation \
  --detector-id DETECTOR-ID \
  --master-id HUB-ACCOUNT-ID \
  --invitation-id INVITATION-ID \
  --region us-east-1
```

## Lambda Function Issues

### Function Timeout Errors

#### Symptoms
- Lambda functions timing out
- "Task timed out" errors in CloudWatch logs
- Incomplete processing of findings

#### Diagnostic Steps
```bash
# Check Lambda function configuration
aws lambda get-function --function-name security-findings-processor

# Review CloudWatch logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/security-findings-processor \
  --filter-pattern "Task timed out" \
  --start-time $(date -d '1 hour ago' +%s)000

# Check function metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=security-findings-processor \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Maximum,Average
```

#### Common Causes and Solutions

##### 1. Insufficient Memory or Timeout
**Cause**: Lambda function needs more memory or longer timeout

**Solution**:
```bash
# Increase memory and timeout
aws lambda update-function-configuration \
  --function-name security-findings-processor \
  --memory-size 1024 \
  --timeout 300
```

##### 2. Large Batch Processing
**Cause**: Processing too many findings in a single invocation

**Solution**:
```python
# Implement batch processing with pagination
def process_findings_in_batches(findings, batch_size=100):
    for i in range(0, len(findings), batch_size):
        batch = findings[i:i + batch_size]
        process_batch(batch)
        
        # Add delay to prevent throttling
        time.sleep(0.1)
```

##### 3. External API Latency
**Cause**: Slow responses from AWS APIs

**Solution**:
```python
# Implement retry logic with exponential backoff
import time
import random
from botocore.exceptions import ClientError

def retry_with_backoff(func, max_retries=3):
    for attempt in range(max_retries):
        try:
            return func()
        except ClientError as e:
            if attempt == max_retries - 1:
                raise
            delay = (2 ** attempt) + random.uniform(0, 1)
            time.sleep(delay)
```

### Memory Errors

#### Symptoms
- "Runtime exited with error: signal: killed" errors
- Lambda function crashing unexpectedly
- Out of memory errors

#### Diagnostic Steps
```bash
# Check memory usage metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name MaxMemoryUsed \
  --dimensions Name=FunctionName,Value=security-findings-processor \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Maximum,Average
```

#### Solutions

##### 1. Increase Memory Allocation
```bash
aws lambda update-function-configuration \
  --function-name security-findings-processor \
  --memory-size 2048
```

##### 2. Optimize Code for Memory Usage
```python
# Use generators instead of loading all data into memory
def process_findings_generator(findings_iterator):
    for finding in findings_iterator:
        yield process_single_finding(finding)

# Clear variables when done
large_data = process_large_dataset()
# Use large_data
del large_data  # Free memory
```

### Permission Errors

#### Symptoms
- "Access Denied" errors
- "UnauthorizedOperation" exceptions
- Functions failing to access AWS services

#### Diagnostic Steps
```bash
# Check Lambda execution role
aws lambda get-function --function-name security-findings-processor --query 'Configuration.Role'

# Review role permissions
aws iam get-role-policy --role-name LambdaExecutionRole --policy-name LambdaExecutionPolicy

# Check CloudTrail for permission errors
aws logs filter-log-events \
  --log-group-name CloudTrail/SecurityAudit \
  --filter-pattern "{ $.errorCode = AccessDenied }" \
  --start-time $(date -d '1 hour ago' +%s)000
```

#### Solutions

##### 1. Update IAM Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "securityhub:GetFindings",
        "securityhub:BatchImportFindings",
        "s3:GetObject",
        "s3:PutObject",
        "sns:Publish",
        "cloudwatch:PutMetricData"
      ],
      "Resource": "*"
    }
  ]
}
```

##### 2. Add Resource-Based Permissions
```bash
# Add S3 bucket policy for Lambda access
aws s3api put-bucket-policy --bucket security-findings-bucket --policy file://bucket-policy.json
```

## Dashboard and Monitoring Issues

### Dashboards Not Loading

#### Symptoms
- CloudWatch dashboards showing "No data"
- Missing widgets or metrics
- Dashboard loading errors

#### Diagnostic Steps
```bash
# List all dashboards
aws cloudwatch list-dashboards --dashboard-name-prefix "Security"

# Get dashboard body
aws cloudwatch get-dashboard --dashboard-name "Security-Executive"

# Check metric availability
aws cloudwatch list-metrics --namespace "AWS/Security"
```

#### Solutions

##### 1. Missing Metrics Data
**Cause**: Lambda functions not publishing metrics

**Solution**:
```python
# Ensure metrics are being published
cloudwatch = boto3.client('cloudwatch')
cloudwatch.put_metric_data(
    Namespace='AWS/Security',
    MetricData=[
        {
            'MetricName': 'FindingsProcessed',
            'Value': findings_count,
            'Unit': 'Count',
            'Timestamp': datetime.utcnow()
        }
    ]
)
```

##### 2. Incorrect Dashboard Configuration
**Cause**: Dashboard widgets configured incorrectly

**Solution**:
```bash
# Regenerate dashboard
aws lambda invoke \
  --function-name dashboard-generator \
  --payload '{"dashboard_type": "executive", "refresh": true}' \
  response.json
```

### Missing Alerts

#### Symptoms
- No notifications being sent
- SNS topics not receiving messages
- Email/Slack alerts not working

#### Diagnostic Steps
```bash
# Check SNS topic subscriptions
aws sns list-subscriptions-by-topic --topic-arn arn:aws:sns:us-east-1:ACCOUNT:security-alerts

# Test SNS publishing
aws sns publish \
  --topic-arn arn:aws:sns:us-east-1:ACCOUNT:security-alerts \
  --message "Test message"

# Check CloudWatch alarms
aws cloudwatch describe-alarms --alarm-name-prefix "Security"
```

#### Solutions

##### 1. SNS Subscription Issues
```bash
# Add email subscription
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:ACCOUNT:security-alerts \
  --protocol email \
  --notification-endpoint security-team@company.com

# Confirm subscription
aws sns confirm-subscription \
  --topic-arn arn:aws:sns:us-east-1:ACCOUNT:security-alerts \
  --token CONFIRMATION-TOKEN
```

##### 2. CloudWatch Alarm Configuration
```bash
# Create alarm for critical findings
aws cloudwatch put-metric-alarm \
  --alarm-name "CriticalSecurityFindings" \
  --alarm-description "Alert on critical security findings" \
  --metric-name CriticalFindings \
  --namespace AWS/Security \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:security-alerts
```

## Data Flow Issues

### S3 Storage Problems

#### Symptoms
- Findings not being stored in S3
- S3 access errors in logs
- Missing or corrupted data files

#### Diagnostic Steps
```bash
# Check S3 bucket contents
aws s3 ls s3://security-findings-bucket/ --recursive

# Verify bucket permissions
aws s3api get-bucket-policy --bucket security-findings-bucket

# Check bucket encryption
aws s3api get-bucket-encryption --bucket security-findings-bucket
```

#### Solutions

##### 1. Bucket Permission Issues
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LambdaAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT:role/LambdaExecutionRole"
      },
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::security-findings-bucket/*"
    }
  ]
}
```

##### 2. S3 Key Structure Issues
```python
# Ensure proper key structure for partitioning
def generate_s3_key(finding):
    return f"year={finding.created_at[:4]}/month={finding.created_at[5:7]}/day={finding.created_at[8:10]}/account={finding.account_id}/finding-{finding.finding_id}.json"
```

### EventBridge Delivery Issues

#### Symptoms
- Events not being delivered
- EventBridge rules not triggering
- Cross-account events missing

#### Diagnostic Steps
```bash
# Check EventBridge rules
aws events list-rules --name-prefix "security" --region us-east-1

# Verify rule targets
aws events list-targets-by-rule --rule "security-hub-findings" --region us-east-1

# Check rule metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Events \
  --metric-name SuccessfulInvocations \
  --dimensions Name=RuleName,Value=security-hub-findings \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

#### Solutions

##### 1. Rule Pattern Issues
```bash
# Update event pattern to be more specific
aws events put-rule \
  --name security-hub-findings \
  --event-pattern '{
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported", "Security Hub Findings - Custom Action"],
    "detail": {
      "findings": {
        "Compliance": {
          "Status": ["FAILED"]
        }
      }
    }
  }' \
  --state ENABLED
```

##### 2. Cross-Account EventBridge Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCrossAccountEventDelivery",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::SPOKE-ACCOUNT:root"
      },
      "Action": "events:PutEvents",
      "Resource": "arn:aws:events:us-east-1:HUB-ACCOUNT:event-bus/security-hub"
    }
  ]
}
```

## Performance Issues

### High Latency

#### Symptoms
- Slow processing of security findings
- Long dashboard load times
- Delayed notifications

#### Diagnostic Steps
```bash
# Check Lambda function duration metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=security-findings-processor \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average,Maximum

# Check S3 request metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/S3 \
  --metric-name AllRequests \
  --dimensions Name=BucketName,Value=security-findings-bucket \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

#### Solutions

##### 1. Lambda Optimization
```python
# Use connection pooling
import boto3
from botocore.config import Config

# Configure connection pooling
config = Config(
    max_pool_connections=50,
    retries={'max_attempts': 3}
)

s3_client = boto3.client('s3', config=config)
```

##### 2. S3 Performance Optimization
```bash
# Enable S3 Transfer Acceleration
aws s3api put-bucket-accelerate-configuration \
  --bucket security-findings-bucket \
  --accelerate-configuration Status=Enabled
```

##### 3. Parallel Processing
```python
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

def process_findings_parallel(findings, max_workers=10):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_finding, finding) for finding in findings]
        results = []
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                logger.error(f"Error processing finding: {e}")
        return results
```

### Throttling Issues

#### Symptoms
- "ThrottlingException" errors
- Rate limit exceeded messages
- Intermittent failures

#### Diagnostic Steps
```bash
# Check Lambda throttling metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Throttles \
  --dimensions Name=FunctionName,Value=security-findings-processor \
  --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

#### Solutions

##### 1. Increase Lambda Concurrency
```bash
# Set reserved concurrency
aws lambda put-reserved-concurrency-request \
  --function-name security-findings-processor \
  --reserved-concurrent-executions 100
```

##### 2. Implement Exponential Backoff
```python
import time
import random
from botocore.exceptions import ClientError

def call_with_backoff(func, *args, **kwargs):
    max_retries = 5
    base_delay = 1
    
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            if e.response['Error']['Code'] in ['Throttling', 'ThrottlingException']:
                if attempt == max_retries - 1:
                    raise
                
                # Exponential backoff with jitter
                delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                time.sleep(delay)
            else:
                raise
```

## Cost-Related Issues

### Unexpected Cost Increases

#### Symptoms
- Higher than expected AWS bills
- Cost anomaly alerts
- Rapid cost growth

#### Diagnostic Steps
```bash
# Check cost by service
aws ce get-cost-and-usage \
  --time-period Start=2024-08-01,End=2024-08-31 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE

# Check cost anomalies
aws ce get-anomalies \
  --date-interval StartDate=2024-08-01,EndDate=2024-08-31

# Review cost allocation tags
aws ce list-cost-category-definitions
```

#### Solutions

##### 1. Implement Cost Controls
```bash
# Create budget alert
aws budgets create-budget \
  --account-id ACCOUNT-ID \
  --budget '{
    "BudgetName": "SecurityServicesBudget",
    "BudgetLimit": {
      "Amount": "5000",
      "Unit": "USD"
    },
    "TimeUnit": "MONTHLY",
    "BudgetType": "COST"
  }' \
  --notifications-with-subscribers file://budget-notifications.json
```

##### 2. Optimize Storage Costs
```bash
# Implement S3 lifecycle policy
aws s3api put-bucket-lifecycle-configuration \
  --bucket security-findings-bucket \
  --lifecycle-configuration file://lifecycle-policy.json
```

```json
{
  "Rules": [
    {
      "ID": "SecurityFindingsLifecycle",
      "Status": "Enabled",
      "Filter": {"Prefix": "findings/"},
      "Transitions": [
        {
          "Days": 30,
          "StorageClass": "STANDARD_IA"
        },
        {
          "Days": 90,
          "StorageClass": "GLACIER"
        },
        {
          "Days": 365,
          "StorageClass": "DEEP_ARCHIVE"
        }
      ]
    }
  ]
}
```

## Escalation Procedures

### When to Escalate

#### Level 1 - Self-Service
- Configuration issues
- Known error conditions
- Documentation-covered problems

#### Level 2 - Team Lead
- Service outages affecting multiple accounts
- Security incidents
- Unknown error conditions

#### Level 3 - Engineering Team
- System architecture issues
- Code bugs requiring fixes
- Infrastructure-level problems

#### Level 4 - AWS Support
- AWS service issues
- Service limit increases
- Platform-level problems

### Escalation Contacts

| Level | Contact | Response Time | Escalation Criteria |
|-------|---------|---------------|-------------------|
| L1 | Self-service | Immediate | Standard operations |
| L2 | Team Lead | 30 minutes | Service degradation |
| L3 | Engineering | 2 hours | System outage |
| L4 | AWS Support | 4 hours | Platform issues |

### Information to Include

#### For All Escalations
- **Issue Description**: What is happening?
- **Business Impact**: Who/what is affected?
- **Timeline**: When did it start?
- **Steps Taken**: What troubleshooting was attempted?
- **Supporting Data**: Logs, metrics, screenshots

#### For AWS Support Cases
- **Account ID**: Affected AWS account
- **Service**: Specific AWS service
- **Region**: Affected AWS region
- **Error Messages**: Exact error text
- **Request IDs**: AWS request IDs from errors

## Preventive Measures

### Monitoring and Alerting

#### Key Metrics to Monitor
- Lambda function error rates
- Processing latency
- Cost trends
- Security finding volumes
- Compliance status

#### Recommended Alarms
```bash
# High error rate alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "LambdaHighErrorRate" \
  --alarm-description "Lambda function error rate above 5%" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Average \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=FunctionName,Value=security-findings-processor

# Cost anomaly alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "SecurityServicesCostAnomaly" \
  --alarm-description "Unusual cost increase detected" \
  --metric-name EstimatedCharges \
  --namespace AWS/Billing \
  --statistic Maximum \
  --period 86400 \
  --threshold 1000 \
  --comparison-operator GreaterThanThreshold
```

### Regular Maintenance

#### Daily Tasks
- Review dashboard for anomalies
- Check error logs
- Verify alert notifications

#### Weekly Tasks
- Analyze cost trends
- Review performance metrics
- Update documentation

#### Monthly Tasks
- Conduct disaster recovery tests
- Review and update runbooks
- Analyze security findings trends

### Documentation Updates

Keep the following documentation current:
- Configuration changes
- New known issues and solutions
- Contact information
- Escalation procedures
- Runbooks and playbooks

---

**Troubleshooting Guide Version**: 1.0  
**Last Updated**: August 27, 2025  
**Next Review**: November 27, 2025
