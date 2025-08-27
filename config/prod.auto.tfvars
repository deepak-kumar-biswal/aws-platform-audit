# ===================================================================
# AWS Platform Audit System - Hub Account Configuration (Production)
# ===================================================================
# This file contains production configuration values for the hub account
# deployment of the AWS audit platform.
# ===================================================================

# Project Configuration
project_name = "aws-audit-platform"
environment  = "prod"
region       = "us-east-1"

# Multi-region monitoring configuration
monitoring_regions = [
  "us-east-1",
  "us-east-2",
  "us-west-1", 
  "us-west-2",
  "eu-west-1",
  "eu-central-1",
  "ap-southeast-1",
  "ap-southeast-2"
]

# Spoke Account Configuration
# IMPORTANT: Update these with your actual spoke account IDs
spoke_account_ids = [
  "123456789012",
  "123456789013", 
  "123456789014",
  "123456789015"
]

# External ID for cross-account access (generate a secure random string)
external_id = "aws-audit-platform-2024-secure-id"

# Notification Configuration
notification_email  = "security-team@company.com"
security_email      = "security-alerts@company.com"
compliance_email    = "compliance-team@company.com"
operational_email   = "devops-team@company.com"

# Optional: Slack Integration
slack_webhook_url = ""  # Add your Slack webhook URL
slack_channel     = "#security-alerts"

# Optional: Microsoft Teams Integration  
teams_webhook_url = ""  # Add your Teams webhook URL

# Security Configuration
enable_guardduty_malware_protection = true
enable_s3_malware_scanning          = true
guardduty_finding_publishing_frequency = "FIFTEEN_MINUTES"
security_hub_auto_enable_controls   = true
enable_access_analyzer_unused_access = true
unused_access_age_days              = 90

# Compliance Frameworks
compliance_frameworks = [
  "cis-aws-foundations-benchmark",
  "aws-foundational-security",
  "pci-dss"
]

# Logging Configuration
log_retention_days                   = 365  # 1 year for production
enable_detailed_monitoring           = true
cloudtrail_include_management_events = true
cloudtrail_include_data_events       = true
enable_cloudtrail_insights          = true

# Cost Management
enable_cost_anomaly_detection = true
cost_anomaly_threshold       = 500   # USD
monthly_budget_limit         = 5000  # USD

# Dashboard Configuration
dashboard_auto_refresh        = 300   # 5 minutes
dashboard_time_range         = "-P1D" # 1 day
create_executive_dashboard   = true
create_operational_dashboard = true
create_compliance_dashboard  = true

# Performance Configuration
lambda_memory_size           = 1024   # MB - Higher for production
lambda_timeout              = 300    # 5 minutes
lambda_concurrent_executions = 100

# Data Retention (Production - longer retention)
s3_data_transition_ia_days        = 30   # Standard-IA after 30 days
s3_data_transition_glacier_days   = 90   # Glacier after 90 days  
s3_data_transition_deep_archive_days = 365 # Deep Archive after 1 year
s3_data_expiration_days           = 2555  # 7 years total retention

# Advanced Configuration
enable_cross_region_replication = true
backup_region                  = "us-west-2"
enable_encryption_at_rest      = true
enable_encryption_in_transit   = true
enable_vpc_flow_logs          = true

# VPC Flow Logs Configuration
vpc_flow_logs_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${windowstart} $${windowend} $${action} $${flowlogstatus}"

# Integration Configuration
enable_jira_integration       = false
jira_url                     = ""
jira_project_key             = ""
enable_servicenow_integration = false
servicenow_instance_url      = ""

# Tagging Configuration
additional_tags = {
  Environment      = "production"
  Application      = "security-audit-platform"
  DataRetention    = "7-years"
  BackupRequired   = "true"
  MonitoringLevel  = "enhanced"
  CriticalityLevel = "high"
  ComplianceScope  = "soc2-pci-hipaa"
  MaintenanceWindow = "sunday-2am-est"
}

cost_center    = "information-security"
owner_team     = "security-engineering"
business_unit  = "cybersecurity"

# Feature Flags (Production - be conservative)
enable_beta_features         = false
enable_experimental_rules    = false
enable_ai_insights          = false
enable_automated_remediation = false
