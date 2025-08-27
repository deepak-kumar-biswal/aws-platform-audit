# Staging Environment Configuration  
# This configuration bridges development and production

# Hub Account Configuration
hub_account_id = "888888888888"
environment    = "staging"

# Staging settings (enhanced monitoring but not full production)
enable_detailed_monitoring = true
enable_cost_anomaly_detection = true
enable_inspector_v2 = true
enable_macie = false  # Optional for staging

# Organization configuration
master_account_id = "888888888888"
organization_id   = "o-example456"

# Spoke accounts (subset for staging validation)
spoke_account_ids = [
  "888888888887",
  "888888888886", 
  "888888888885"
]

# KMS Configuration
kms_key_deletion_window = 10

# S3 Configuration (moderate retention)
s3_lifecycle_glacier_days = 180
s3_lifecycle_deep_archive_days = 730

# SNS Configuration
notification_emails = [
  "staging-security@company.com",
  "security-team-lead@company.com"
]

# Slack configuration
slack_webhook_url = "https://hooks.slack.com/services/STAGING/WEBHOOK/URL"
slack_channel = "#staging-security-alerts"

# CloudWatch Configuration
enable_detailed_dashboards = true
dashboard_auto_refresh = true

# EventBridge Configuration
eventbridge_custom_bus_name = "staging-security-hub"

# Lambda Configuration (moderate sizing)
lambda_memory_size = 512
lambda_timeout = 180
lambda_reserved_concurrency = 20

# Data retention (moderate)
cloudwatch_logs_retention_days = 30
s3_findings_retention_days = 90

# Compliance settings (subset for staging validation)
enabled_compliance_standards = [
  "aws-foundational-security",
  "cis-aws-foundations-benchmark"
]

# GuardDuty configuration (enhanced for staging)
guardduty_malware_protection = true
guardduty_kubernetes_protection = true
guardduty_rds_protection = true
guardduty_lambda_protection = false

# Config settings (standard)
config_include_global_resource_types = true
config_delivery_frequency = "Six_Hours"

# Access Analyzer (organization level for staging)
access_analyzer_type = "ORGANIZATION"

# Cost settings
cost_anomaly_threshold = 500

# Security settings (production-like)
security_score_threshold = 7.5
critical_finding_threshold = 2

# Tagging (staging environment)
default_tags = {
  Environment         = "staging"
  Project            = "aws-audit-platform"
  Owner              = "security-team"
  CostCenter         = "engineering"
  DataClassification = "internal"
  Compliance         = "testing"
  BackupSchedule     = "daily"
  MaintenanceWindow  = "weekends"
}

# Region configuration (multi-region like production)
primary_region = "us-east-1"
backup_regions = ["us-west-2"]
