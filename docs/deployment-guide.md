# AWS Audit Platform - Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the AWS Audit Platform in production environments. The platform uses a hub-and-spoke architecture to monitor security across 1000+ AWS accounts.

## Prerequisites

### Required Tools
- **AWS CLI**: Version 2.0 or later
- **Terraform**: Version 1.0 or later
- **Git**: For source code management
- **Python**: 3.11 or later (for testing and validation)

### AWS Prerequisites
- **AWS Organizations**: Access to AWS Organizations for multi-account management
- **Administrative Access**: Administrative privileges in hub and spoke accounts
- **Service Limits**: Ensure service limits are adequate for your scale
- **Billing**: Billing access for cost monitoring setup

### Permissions Required
- **Organizations Admin**: Full access to AWS Organizations
- **Security Services**: Admin access to Security Hub, GuardDuty, Config, etc.
- **IAM Admin**: Ability to create and manage IAM roles and policies
- **Network Admin**: VPC and network configuration permissions

## Pre-Deployment Planning

### 1. Account Structure Planning
```
Organization Root
├── Security OU
│   └── Hub Account (Security Command Center)
├── Production OU
│   ├── Prod Account 1
│   ├── Prod Account 2
│   └── Prod Account N
├── Staging OU
│   ├── Staging Account 1
│   └── Staging Account 2
└── Development OU
    ├── Dev Account 1
    └── Dev Account 2
```

### 2. Network Architecture Planning
- **Hub Account VPC**: Centralized monitoring infrastructure
- **VPC Endpoints**: Private connectivity to AWS services
- **Cross-Account Networking**: EventBridge cross-account rules
- **DNS Configuration**: Route 53 for service discovery

### 3. Security Planning
- **KMS Key Strategy**: Separate keys per environment and service
- **IAM Role Strategy**: Cross-account roles with minimal permissions
- **Data Classification**: Sensitive data handling procedures
- **Compliance Requirements**: Specific compliance frameworks needed

## Environment Setup

### Development Environment Deployment

#### 1. Clone Repository
```bash
git clone <repository-url>
cd aws-audit-platform/aws-platform-audit
```

#### 2. Configure Development Environment
```bash
# Copy development configuration
cp config/dev.auto.tfvars.example config/dev.auto.tfvars
cp config/spoke-accounts-dev.json.example config/spoke-accounts-dev.json

# Update configuration files with your account IDs
nano config/dev.auto.tfvars
nano config/spoke-accounts-dev.json
```

#### 3. Deploy Development Hub Account
```bash
# Navigate to hub infrastructure
cd terraform/hub

# Initialize Terraform
terraform init

# Review deployment plan
terraform plan -var-file="../../config/dev.auto.tfvars"

# Deploy infrastructure
terraform apply -var-file="../../config/dev.auto.tfvars"
```

#### 4. Deploy Development Spoke Accounts
```bash
# Navigate to spoke infrastructure
cd ../spoke

# Initialize Terraform
terraform init

# For each spoke account, deploy infrastructure
terraform plan -var="hub_account_id=YOUR_HUB_ACCOUNT_ID" -var="environment=dev"
terraform apply -var="hub_account_id=YOUR_HUB_ACCOUNT_ID" -var="environment=dev"
```

### Staging Environment Deployment

#### 1. Configure Staging Environment
```bash
# Copy staging configuration
cp config/staging.auto.tfvars.example config/staging.auto.tfvars
cp config/spoke-accounts-staging.json.example config/spoke-accounts-staging.json

# Update with staging account IDs
nano config/staging.auto.tfvars
nano config/spoke-accounts-staging.json
```

#### 2. Deploy Staging Infrastructure
```bash
# Deploy hub account
cd terraform/hub
terraform workspace select staging || terraform workspace new staging
terraform plan -var-file="../../config/staging.auto.tfvars"
terraform apply -var-file="../../config/staging.auto.tfvars"

# Deploy spoke accounts
cd ../spoke
terraform workspace select staging || terraform workspace new staging
# Repeat for each staging spoke account
```

### Production Environment Deployment

#### 1. Pre-Production Checklist
- [ ] Development environment fully tested
- [ ] Staging environment validated
- [ ] Security review completed
- [ ] Performance testing passed
- [ ] Compliance validation completed
- [ ] Runbook documentation updated
- [ ] Monitoring and alerting configured
- [ ] Backup and recovery procedures tested

#### 2. Configure Production Environment
```bash
# Copy production configuration
cp config/prod.auto.tfvars.example config/prod.auto.tfvars
cp config/spoke-accounts-prod.json.example config/spoke-accounts-prod.json

# Update with production account IDs and settings
nano config/prod.auto.tfvars
nano config/spoke-accounts-prod.json
```

#### 3. Production Deployment Steps

##### Phase 1: Hub Account Deployment
```bash
cd terraform/hub
terraform workspace select production || terraform workspace new production

# Validate configuration
terraform validate
terraform plan -var-file="../../config/prod.auto.tfvars" -out=production.tfplan

# Security review of plan
terraform show -json production.tfplan | jq '.' > production-plan.json

# Deploy after approval
terraform apply production.tfplan
```

##### Phase 2: Pilot Spoke Accounts (10-20 accounts)
```bash
cd ../spoke
terraform workspace select production || terraform workspace new production

# Deploy to pilot accounts first
for account_id in $(cat ../../config/pilot-accounts.txt); do
  echo "Deploying to account: $account_id"
  terraform plan -var="hub_account_id=YOUR_HUB_ACCOUNT_ID" \
                 -var="spoke_account_id=$account_id" \
                 -var="environment=production"
  
  terraform apply -var="hub_account_id=YOUR_HUB_ACCOUNT_ID" \
                  -var="spoke_account_id=$account_id" \
                  -var="environment=production"
done
```

##### Phase 3: Validation and Testing
```bash
# Run validation tests
./run-tests.sh integration
./run-tests.sh performance

# Validate data flow
python scripts/validate-data-flow.py --environment production

# Check dashboards and alerts
python scripts/validate-dashboards.py --environment production
```

##### Phase 4: Full Production Rollout
```bash
# Deploy to all production accounts in batches
python scripts/batch-deploy.py --environment production --batch-size 50
```

## CI/CD Pipeline Setup

### GitHub Actions Configuration

#### 1. Repository Secrets Setup
```bash
# Add AWS credentials to GitHub repository secrets
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_ACCOUNT_ID_HUB
AWS_ACCOUNT_ID_SPOKE_LIST

# Add notification credentials
SLACK_WEBHOOK_URL
NOTIFICATION_EMAIL
```

#### 2. Environment-Specific Deployments
The GitHub Actions workflow automatically deploys based on branch:
- **main branch** → Production deployment
- **staging branch** → Staging deployment  
- **develop branch** → Development deployment

#### 3. Manual Deployment Triggers
```bash
# Trigger manual deployment via GitHub API
curl -X POST \
  -H "Authorization: token YOUR_GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/YOUR_ORG/aws-audit-platform/actions/workflows/deploy.yml/dispatches \
  -d '{"ref":"main","inputs":{"environment":"production"}}'
```

## Configuration Management

### Environment-Specific Configuration

#### Development Configuration
```hcl
# config/dev.auto.tfvars
hub_account_id = "999999999999"
environment = "dev"
enable_detailed_monitoring = false
spoke_account_ids = ["999999999998", "999999999997"]
notification_emails = ["dev-security@company.com"]
```

#### Staging Configuration
```hcl
# config/staging.auto.tfvars
hub_account_id = "888888888888"
environment = "staging"
enable_detailed_monitoring = true
spoke_account_ids = ["888888888887", "888888888886", "888888888885"]
notification_emails = ["staging-security@company.com"]
```

#### Production Configuration
```hcl
# config/prod.auto.tfvars
hub_account_id = "111111111111"
environment = "production"
enable_detailed_monitoring = true
enable_cost_anomaly_detection = true
# Full configuration with all production settings
```

### Spoke Account Configuration

#### Account Metadata Structure
```json
{
  "description": "Production spoke accounts",
  "environment": "prod",
  "spoke_accounts": [
    {
      "account_id": "123456789012",
      "account_name": "production-workloads",
      "owner_team": "platform-engineering",
      "business_unit": "technology",
      "compliance_requirements": ["soc2", "pci-dss"],
      "monitoring_level": "enhanced",
      "regions": ["us-east-1", "us-west-2"],
      "data_classification": "confidential"
    }
  ]
}
```

## Post-Deployment Validation

### 1. Service Health Checks
```bash
# Validate Security Hub
aws securityhub get-enabled-standards --region us-east-1

# Validate GuardDuty
aws guardduty list-detectors --region us-east-1

# Validate Config
aws configservice describe-configuration-recorders --region us-east-1

# Validate Access Analyzer
aws accessanalyzer list-analyzers --region us-east-1
```

### 2. Data Flow Validation
```bash
# Check EventBridge rules
aws events list-rules --name-prefix "security-hub"

# Validate Lambda functions
aws lambda list-functions --query 'Functions[?starts_with(FunctionName, `security-`)]'

# Check S3 data lake
aws s3 ls s3://your-security-findings-bucket/
```

### 3. Dashboard Validation
```bash
# Validate CloudWatch dashboards
aws cloudwatch list-dashboards --dashboard-name-prefix "Security"

# Check metrics
aws cloudwatch list-metrics --namespace "AWS/Security"
```

### 4. Cost Validation
```bash
# Check cost anomaly detection
aws ce get-anomaly-detectors

# Validate cost allocation tags
aws ce list-cost-category-definitions
```

## Monitoring and Maintenance

### Daily Operations
- **Health Checks**: Automated health monitoring via CloudWatch
- **Alert Review**: Daily review of security alerts and findings
- **Cost Monitoring**: Daily cost analysis and anomaly detection
- **Performance Metrics**: Dashboard review for performance issues

### Weekly Operations
- **Compliance Review**: Weekly compliance posture assessment
- **Finding Analysis**: Trend analysis of security findings
- **Performance Optimization**: Resource utilization review
- **Documentation Updates**: Keep runbooks and procedures current

### Monthly Operations
- **Security Review**: Comprehensive security posture assessment
- **Cost Optimization**: Monthly cost optimization analysis
- **Capacity Planning**: Resource scaling and capacity review
- **Disaster Recovery Testing**: Monthly DR procedure validation

### Quarterly Operations
- **Full System Audit**: Comprehensive system audit and review
- **Compliance Certification**: Quarterly compliance certification
- **Architecture Review**: System architecture and design review
- **Training Updates**: Team training and skill development

## Troubleshooting

### Common Issues and Solutions

#### 1. Cross-Account Access Issues
```bash
# Symptom: Spoke accounts not sending data to hub
# Solution: Verify IAM roles and trust relationships

# Check hub account role
aws iam get-role --role-name SecurityHubCrossAccountRole

# Verify spoke account trust
aws sts assume-role --role-arn arn:aws:iam::HUB-ACCOUNT:role/SecurityHubCrossAccountRole --role-session-name test
```

#### 2. Lambda Function Errors
```bash
# Symptom: Security findings not processing
# Solution: Check CloudWatch logs

# View recent logs
aws logs filter-log-events --log-group-name /aws/lambda/security-findings-processor --start-time $(date -d '1 hour ago' +%s)000

# Check function configuration
aws lambda get-function --function-name security-findings-processor
```

#### 3. GuardDuty Not Detecting
```bash
# Symptom: No GuardDuty findings
# Solution: Verify GuardDuty configuration

# Check detector status
aws guardduty get-detector --detector-id YOUR-DETECTOR-ID

# Verify data sources
aws guardduty get-detector --detector-id YOUR-DETECTOR-ID --query 'DataSources'
```

#### 4. Config Rules Not Evaluating
```bash
# Symptom: Config compliance not updating
# Solution: Check Config service

# Verify Config recorder
aws configservice describe-configuration-recorders

# Check delivery channel
aws configservice describe-delivery-channels

# Force rule evaluation
aws configservice start-config-rules-evaluation --config-rule-names YOUR-RULE-NAME
```

### Emergency Procedures

#### System Outage Response
1. **Assess Impact**: Determine scope and impact of outage
2. **Activate Team**: Page on-call security team
3. **Implement Workarounds**: Use backup monitoring procedures
4. **Execute Recovery**: Follow disaster recovery procedures
5. **Post-Incident Review**: Conduct thorough post-mortem

#### Security Incident Response
1. **Isolation**: Isolate affected resources
2. **Assessment**: Determine scope of security incident
3. **Containment**: Contain the security threat
4. **Investigation**: Forensic analysis and investigation
5. **Recovery**: Restore services and implement fixes
6. **Lessons Learned**: Update procedures based on incident

## Scaling Considerations

### Adding New Accounts
```bash
# 1. Update spoke account configuration
nano config/spoke-accounts-prod.json

# 2. Deploy spoke infrastructure
cd terraform/spoke
terraform plan -var="new_spoke_account_id=NEW-ACCOUNT-ID"
terraform apply -var="new_spoke_account_id=NEW-ACCOUNT-ID"

# 3. Validate new account integration
python scripts/validate-account.py --account-id NEW-ACCOUNT-ID
```

### Regional Expansion
```bash
# 1. Update regional configuration
nano config/prod.auto.tfvars
# Add new regions to backup_regions list

# 2. Deploy to new regions
terraform plan -var="primary_region=us-east-1" -var="backup_regions=[\"us-west-2\",\"eu-west-1\"]"
terraform apply
```

### Performance Optimization
- **Lambda Optimization**: Increase memory/timeout for high-volume processing
- **S3 Optimization**: Implement S3 Transfer Acceleration for global deployments
- **Database Optimization**: Consider DynamoDB for high-frequency lookups
- **Caching**: Implement CloudFront for dashboard caching

## Support and Documentation

### Getting Help
- **Internal Documentation**: This deployment guide and architecture docs
- **AWS Documentation**: AWS service-specific documentation
- **Community Support**: AWS Security forums and communities
- **Professional Services**: AWS Professional Services for complex implementations

### Useful Resources
- **AWS Security Hub User Guide**: https://docs.aws.amazon.com/securityhub/
- **GuardDuty User Guide**: https://docs.aws.amazon.com/guardduty/
- **Config Developer Guide**: https://docs.aws.amazon.com/config/
- **Terraform AWS Provider**: https://registry.terraform.io/providers/hashicorp/aws/

---

**Document Version**: 1.0  
**Last Updated**: August 27, 2025  
**Next Review**: November 27, 2025
