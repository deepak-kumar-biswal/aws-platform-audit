# ===================================================================
# AWS Platform Audit System - Hub Account Variables
# ===================================================================
# This file defines all input variables for the hub account
# configuration of the AWS audit platform.
# ===================================================================

# ===================================================================
# Project Configuration
# ===================================================================

variable "project_name" {
  description = "Name of the project - used for resource naming and tagging"
  type        = string
  default     = "aws-audit-platform"
  
  validation {
    condition     = length(var.project_name) <= 30
    error_message = "Project name must be 30 characters or less."
  }
}

variable "environment" {
  description = "Environment name (e.g., prod, staging, dev)"
  type        = string
  default     = "prod"
  
  validation {
    condition     = contains(["prod", "staging", "dev", "test"], var.environment)
    error_message = "Environment must be one of: prod, staging, dev, test."
  }
}

variable "region" {
  description = "AWS region for hub account resources"
  type        = string
  default     = "us-east-1"
}

variable "monitoring_regions" {
  description = "List of AWS regions to monitor across all accounts"
  type        = list(string)
  default = [
    "us-east-1",
    "us-east-2", 
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1",
    "ap-southeast-2"
  ]
  
  validation {
    condition     = length(var.monitoring_regions) > 0
    error_message = "At least one monitoring region must be specified."
  }
}

# ===================================================================
# Account Configuration
# ===================================================================

variable "spoke_account_ids" {
  description = "List of AWS account IDs that will be monitored (spoke accounts)"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for account_id in var.spoke_account_ids : 
      can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "All account IDs must be 12-digit strings."
  }
}

variable "external_id" {
  description = "External ID for cross-account assume role (security best practice)"
  type        = string
  default     = ""
  sensitive   = true
  
  validation {
    condition     = length(var.external_id) >= 6
    error_message = "External ID must be at least 6 characters long."
  }
}

# ===================================================================
# Notification Configuration
# ===================================================================

variable "notification_email" {
  description = "Default email address for general notifications"
  type        = string
  default     = ""
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
    error_message = "Please provide a valid email address."
  }
}

variable "security_email" {
  description = "Email address for security-related alerts and notifications"
  type        = string
  default     = ""
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.security_email))
    error_message = "Please provide a valid security team email address."
  }
}

variable "compliance_email" {
  description = "Email address for compliance-related alerts and notifications"
  type        = string
  default     = ""
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.compliance_email))
    error_message = "Please provide a valid compliance team email address."
  }
}

variable "operational_email" {
  description = "Email address for operational alerts and system notifications"
  type        = string
  default     = ""
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.operational_email))
    error_message = "Please provide a valid operational team email address."
  }
}

# ===================================================================
# Slack Integration (Optional)
# ===================================================================

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_channel" {
  description = "Slack channel name for security notifications"
  type        = string
  default     = "#security-alerts"
}

# ===================================================================
# Microsoft Teams Integration (Optional)
# ===================================================================

variable "teams_webhook_url" {
  description = "Microsoft Teams webhook URL for notifications (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

# ===================================================================
# Security Configuration
# ===================================================================

variable "enable_guardduty_malware_protection" {
  description = "Enable GuardDuty malware protection for EC2 instances and EBS volumes"
  type        = bool
  default     = true
}

variable "enable_s3_malware_scanning" {
  description = "Enable malware scanning for S3 objects"
  type        = bool
  default     = true
}

variable "guardduty_finding_publishing_frequency" {
  description = "Frequency of publishing GuardDuty findings to CloudWatch Events"
  type        = string
  default     = "FIFTEEN_MINUTES"
  
  validation {
    condition = contains([
      "FIFTEEN_MINUTES",
      "ONE_HOUR", 
      "SIX_HOURS"
    ], var.guardduty_finding_publishing_frequency)
    error_message = "GuardDuty finding publishing frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "security_hub_auto_enable_controls" {
  description = "Automatically enable new controls in Security Hub"
  type        = bool
  default     = true
}

variable "enable_access_analyzer_unused_access" {
  description = "Enable Access Analyzer unused access analysis"
  type        = bool
  default     = true
}

variable "unused_access_age_days" {
  description = "Number of days to consider access as unused"
  type        = number
  default     = 90
  
  validation {
    condition     = var.unused_access_age_days >= 30 && var.unused_access_age_days <= 365
    error_message = "Unused access age must be between 30 and 365 days."
  }
}

# ===================================================================
# Compliance Configuration
# ===================================================================

variable "compliance_frameworks" {
  description = "List of compliance frameworks to enable"
  type        = list(string)
  default = [
    "cis-aws-foundations-benchmark",
    "aws-foundational-security",
    "pci-dss"
  ]
  
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks :
      contains([
        "cis-aws-foundations-benchmark",
        "aws-foundational-security", 
        "pci-dss",
        "nist-800-53",
        "hipaa-security"
      ], framework)
    ])
    error_message = "Invalid compliance framework specified."
  }
}

variable "custom_config_rules" {
  description = "List of custom AWS Config rules to deploy"
  type = list(object({
    name                = string
    description         = string
    source_identifier   = string
    input_parameters    = map(string)
    resource_types      = list(string)
  }))
  default = []
}

# ===================================================================
# Logging and Monitoring Configuration
# ===================================================================

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 90
  
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch Logs retention period."
  }
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring for all resources"
  type        = bool
  default     = true
}

variable "cloudtrail_include_management_events" {
  description = "Include management events in CloudTrail logging"
  type        = bool
  default     = true
}

variable "cloudtrail_include_data_events" {
  description = "Include data events in CloudTrail logging"
  type        = bool
  default     = true
}

variable "enable_cloudtrail_insights" {
  description = "Enable CloudTrail Insights for unusual activity patterns"
  type        = bool
  default     = true
}

# ===================================================================
# Cost Management Configuration
# ===================================================================

variable "enable_cost_anomaly_detection" {
  description = "Enable AWS Cost Anomaly Detection for security services"
  type        = bool
  default     = true
}

variable "cost_anomaly_threshold" {
  description = "Cost anomaly detection threshold in USD"
  type        = number
  default     = 100
  
  validation {
    condition     = var.cost_anomaly_threshold > 0
    error_message = "Cost anomaly threshold must be greater than 0."
  }
}

variable "monthly_budget_limit" {
  description = "Monthly budget limit for security services in USD"
  type        = number
  default     = 1000
  
  validation {
    condition     = var.monthly_budget_limit > 0
    error_message = "Monthly budget limit must be greater than 0."
  }
}

# ===================================================================
# Dashboard Configuration
# ===================================================================

variable "dashboard_auto_refresh" {
  description = "Auto-refresh interval for CloudWatch dashboards in seconds"
  type        = number
  default     = 300
  
  validation {
    condition     = var.dashboard_auto_refresh >= 60
    error_message = "Dashboard auto-refresh interval must be at least 60 seconds."
  }
}

variable "dashboard_time_range" {
  description = "Default time range for dashboard widgets"
  type        = string
  default     = "-P1D"
  
  validation {
    condition = contains([
      "-PT1H",   # 1 hour
      "-PT3H",   # 3 hours
      "-PT6H",   # 6 hours
      "-PT12H",  # 12 hours
      "-P1D",    # 1 day
      "-P3D",    # 3 days
      "-P1W",    # 1 week
      "-P1M"     # 1 month
    ], var.dashboard_time_range)
    error_message = "Invalid dashboard time range specified."
  }
}

variable "create_executive_dashboard" {
  description = "Create executive-level dashboard with high-level metrics"
  type        = bool
  default     = true
}

variable "create_operational_dashboard" {
  description = "Create operational dashboard with detailed metrics"
  type        = bool
  default     = true
}

variable "create_compliance_dashboard" {
  description = "Create compliance-focused dashboard"
  type        = bool
  default     = true
}

# ===================================================================
# Performance Configuration
# ===================================================================

variable "lambda_memory_size" {
  description = "Memory size for Lambda functions in MB"
  type        = number
  default     = 512
  
  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory size must be between 128 and 10240 MB."
  }
}

variable "lambda_timeout" {
  description = "Timeout for Lambda functions in seconds"
  type        = number
  default     = 300
  
  validation {
    condition     = var.lambda_timeout >= 30 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 30 and 900 seconds."
  }
}

variable "lambda_concurrent_executions" {
  description = "Reserved concurrent executions for Lambda functions"
  type        = number
  default     = 100
  
  validation {
    condition     = var.lambda_concurrent_executions >= 10
    error_message = "Lambda concurrent executions must be at least 10."
  }
}

# ===================================================================
# Data Retention Configuration
# ===================================================================

variable "s3_data_transition_ia_days" {
  description = "Days after which to transition S3 objects to IA storage"
  type        = number
  default     = 30
}

variable "s3_data_transition_glacier_days" {
  description = "Days after which to transition S3 objects to Glacier"
  type        = number
  default     = 90
}

variable "s3_data_transition_deep_archive_days" {
  description = "Days after which to transition S3 objects to Deep Archive"
  type        = number
  default     = 365
}

variable "s3_data_expiration_days" {
  description = "Days after which to delete S3 objects"
  type        = number
  default     = 2555  # 7 years
}

# ===================================================================
# Advanced Configuration
# ===================================================================

variable "enable_cross_region_replication" {
  description = "Enable cross-region replication for critical data"
  type        = bool
  default     = false
}

variable "backup_region" {
  description = "AWS region for backup and disaster recovery"
  type        = string
  default     = "us-west-2"
}

variable "enable_encryption_at_rest" {
  description = "Enable encryption at rest for all supported services"
  type        = bool
  default     = true
}

variable "enable_encryption_in_transit" {
  description = "Enforce encryption in transit for all communications"
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs collection and analysis"
  type        = bool
  default     = true
}

variable "vpc_flow_logs_format" {
  description = "VPC Flow Logs format specification"
  type        = string
  default     = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${windowstart} $${windowend} $${action} $${flowlogstatus}"
}

# ===================================================================
# Integration Configuration
# ===================================================================

variable "enable_jira_integration" {
  description = "Enable JIRA integration for security findings"
  type        = bool
  default     = false
}

variable "jira_url" {
  description = "JIRA instance URL"
  type        = string
  default     = ""
}

variable "jira_project_key" {
  description = "JIRA project key for security findings"
  type        = string
  default     = ""
}

variable "enable_servicenow_integration" {
  description = "Enable ServiceNow integration for incident management"
  type        = bool
  default     = false
}

variable "servicenow_instance_url" {
  description = "ServiceNow instance URL"
  type        = string
  default     = ""
}

# ===================================================================
# Tagging Configuration
# ===================================================================

variable "additional_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "cost_center" {
  description = "Cost center for billing and reporting"
  type        = string
  default     = "security-operations"
}

variable "owner_team" {
  description = "Team responsible for the audit platform"
  type        = string
  default     = "security-team"
}

variable "business_unit" {
  description = "Business unit owning the audit platform"
  type        = string
  default     = "information-security"
}

# ===================================================================
# Feature Flags
# ===================================================================

variable "enable_beta_features" {
  description = "Enable beta features (use with caution in production)"
  type        = bool
  default     = false
}

variable "enable_experimental_rules" {
  description = "Enable experimental compliance rules"
  type        = bool
  default     = false
}

variable "enable_ai_insights" {
  description = "Enable AI-powered security insights (when available)"
  type        = bool
  default     = false
}

variable "enable_automated_remediation" {
  description = "Enable automated remediation for low-risk findings"
  type        = bool
  default     = false
}
