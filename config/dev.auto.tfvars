# Development Environment Configuration
# This configuration is for development/testing purposes

# Hub Account Configuration
hub_account_id = "999999999999"
environment    = "dev"

# Basic settings for development
enable_detailed_monitoring = false
enable_cost_anomaly_detection = false
enable_inspector_v2 = false
enable_macie = false

# Organization configuration
master_account_id = "999999999999"
organization_id   = "o-example123"

# Spoke accounts (reduced set for development)
spoke_account_ids = [
  "999999999998",
  "999999999997"
]

# Basic KMS configuration
kms_key_deletion_window = 7  # Shorter for dev

# S3 Configuration (reduced retention for cost savings)
s3_lifecycle_glacier_days = 90
s3_lifecycle_deep_archive_days = 365

# SNS Configuration
notification_emails = [
  "dev-security@company.com"
]

# Slack configuration (dev channel)
slack_webhook_url = "https://hooks.slack.com/services/DEV/WEBHOOK/URL"
slack_channel = "#dev-security-alerts"

# CloudWatch Configuration (basic for dev)
enable_detailed_dashboards = false
dashboard_auto_refresh = false

# EventBridge Configuration
eventbridge_custom_bus_name = "dev-security-hub"

# Lambda Configuration (smaller for dev)
lambda_memory_size = 256
lambda_timeout = 60
lambda_reserved_concurrency = 5

# Data retention (shorter for dev)
cloudwatch_logs_retention_days = 7
s3_findings_retention_days = 30

# Compliance settings (minimal for dev)
enabled_compliance_standards = [
  "aws-foundational-security"
]

# GuardDuty configuration (basic)
guardduty_malware_protection = false
guardduty_kubernetes_protection = false
guardduty_rds_protection = false
guardduty_lambda_protection = false

# Config settings (reduced for cost)
config_include_global_resource_types = false
config_delivery_frequency = "TwentyFour_Hours"

# Access Analyzer (basic)
access_analyzer_type = "ACCOUNT"

# Cost settings (basic monitoring)
cost_anomaly_threshold = 100

# Security settings (relaxed for dev)
security_score_threshold = 6.0
critical_finding_threshold = 1

# Tagging (dev environment tags)
default_tags = {
  Environment         = "dev"
  Project            = "aws-audit-platform"
  Owner              = "security-team"
  CostCenter         = "engineering"
  DataClassification = "internal"
  Compliance         = "none"
  BackupSchedule     = "none"
  MaintenanceWindow  = "anytime"
}

# Region configuration (single region for dev)
primary_region = "us-east-1"
backup_regions = []
