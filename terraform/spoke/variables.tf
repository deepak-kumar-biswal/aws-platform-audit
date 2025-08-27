# ===================================================================
# AWS Platform Audit System - Spoke Account Variables
# ===================================================================
# This file defines all input variables for the spoke account
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
  description = "AWS region for spoke account resources"
  type        = string
  default     = "us-east-1"
}

# ===================================================================
# Hub Account Configuration
# ===================================================================

variable "hub_account_id" {
  description = "AWS Account ID of the hub account"
  type        = string
  default     = ""
  
  validation {
    condition     = var.hub_account_id == "" || can(regex("^[0-9]{12}$", var.hub_account_id))
    error_message = "Hub account ID must be a 12-digit string or empty."
  }
}

variable "hub_account_email" {
  description = "Email address associated with the hub account (for invitations)"
  type        = string
  default     = ""
  
  validation {
    condition = var.hub_account_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.hub_account_email))
    error_message = "Hub account email must be a valid email address or empty."
  }
}

variable "hub_region" {
  description = "Primary region of the hub account"
  type        = string
  default     = "us-east-1"
}

variable "hub_s3_bucket_name" {
  description = "S3 bucket name in hub account for centralized logging (if different from local)"
  type        = string
  default     = ""
}

variable "hub_sns_topic_name" {
  description = "SNS topic name in hub account for alerts"
  type        = string
  default     = ""
}

variable "external_id" {
  description = "External ID for cross-account assume role (security best practice)"
  type        = string
  default     = ""
  sensitive   = true
  
  validation {
    condition     = var.external_id == "" || length(var.external_id) >= 6
    error_message = "External ID must be at least 6 characters long or empty."
  }
}

# ===================================================================
# Security Services Configuration
# ===================================================================

variable "enable_security_hub" {
  description = "Enable AWS Security Hub in the spoke account"
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable Amazon GuardDuty in the spoke account"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config in the spoke account"
  type        = bool
  default     = true
}

variable "enable_access_analyzer" {
  description = "Enable AWS Access Analyzer in the spoke account"
  type        = bool
  default     = true
}

variable "enable_inspector" {
  description = "Enable Amazon Inspector in the spoke account"
  type        = bool
  default     = true
}

variable "enable_macie" {
  description = "Enable Amazon Macie in the spoke account"
  type        = bool
  default     = false
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs collection"
  type        = bool
  default     = true
}

# ===================================================================
# GuardDuty Configuration
# ===================================================================

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

variable "enable_guardduty_s3_protection" {
  description = "Enable GuardDuty S3 protection"
  type        = bool
  default     = true
}

variable "enable_guardduty_eks_protection" {
  description = "Enable GuardDuty EKS protection"
  type        = bool
  default     = true
}

variable "enable_guardduty_malware_protection" {
  description = "Enable GuardDuty malware protection for EC2 instances and EBS volumes"
  type        = bool
  default     = true
}

# ===================================================================
# Security Hub Configuration
# ===================================================================

variable "enable_cis_standard" {
  description = "Enable CIS AWS Foundations Benchmark standard in Security Hub"
  type        = bool
  default     = true
}

variable "enable_aws_foundational_standard" {
  description = "Enable AWS Foundational Security standard in Security Hub"
  type        = bool
  default     = true
}

variable "enable_pci_dss_standard" {
  description = "Enable PCI DSS standard in Security Hub"
  type        = bool
  default     = true
}

variable "enable_nist_standard" {
  description = "Enable NIST 800-53 standard in Security Hub (if available)"
  type        = bool
  default     = false
}

variable "enable_hipaa_standard" {
  description = "Enable HIPAA Security Rule standard in Security Hub (if available)"
  type        = bool
  default     = false
}

# ===================================================================
# Config Configuration
# ===================================================================

variable "config_recording_frequency" {
  description = "Recording frequency for AWS Config"
  type        = string
  default     = "DAILY"
  
  validation {
    condition = contains([
      "CONTINUOUS",
      "DAILY"
    ], var.config_recording_frequency)
    error_message = "Config recording frequency must be CONTINUOUS or DAILY."
  }
}

variable "config_snapshot_delivery_frequency" {
  description = "Snapshot delivery frequency for AWS Config"
  type        = string
  default     = "TwentyFour_Hours"
  
  validation {
    condition = contains([
      "One_Hour",
      "Three_Hours",
      "Six_Hours",
      "Twelve_Hours", 
      "TwentyFour_Hours"
    ], var.config_snapshot_delivery_frequency)
    error_message = "Invalid Config snapshot delivery frequency."
  }
}

variable "include_global_resources" {
  description = "Include global resource types in Config recording"
  type        = bool
  default     = true
}

variable "sensitive_resource_types" {
  description = "List of sensitive resource types for continuous recording"
  type        = list(string)
  default = [
    "AWS::IAM::User",
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::IAM::Group",
    "AWS::S3::Bucket",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::Instance",
    "AWS::RDS::DBInstance",
    "AWS::Lambda::Function"
  ]
}

# Config Conformance Packs
variable "operational_conformance_packs" {
  description = "Operational conformance packs to deploy"
  type = map(object({
    template_uri      = string
    input_parameters = map(string)
  }))
  default = {
    "operational-best-practices-for-amazon-s3" = {
      template_uri = "https://s3.us-east-1.amazonaws.com/aws-configservice-us-east-1/conformance-packs/Operational-Best-Practices-for-Amazon-S3.yaml"
      input_parameters = {}
    }
    "operational-best-practices-for-encryption-and-keys" = {
      template_uri = "https://s3.us-east-1.amazonaws.com/aws-configservice-us-east-1/conformance-packs/Operational-Best-Practices-for-Encryption-and-Keys.yaml"
      input_parameters = {}
    }
  }
}

# ===================================================================
# Access Analyzer Configuration
# ===================================================================

variable "enable_organization_analyzer" {
  description = "Enable organization-wide Access Analyzer (requires organization setup)"
  type        = bool
  default     = false
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
# Inspector Configuration
# ===================================================================

variable "inspector_resource_types" {
  description = "Resource types to enable for Amazon Inspector"
  type        = list(string)
  default     = ["ECR", "EC2"]
  
  validation {
    condition = alltrue([
      for resource_type in var.inspector_resource_types :
      contains(["ECR", "EC2", "LAMBDA"], resource_type)
    ])
    error_message = "Inspector resource types must be from: ECR, EC2, LAMBDA."
  }
}

# ===================================================================
# Macie Configuration
# ===================================================================

variable "macie_finding_publishing_frequency" {
  description = "Frequency of publishing Macie findings"
  type        = string
  default     = "FIFTEEN_MINUTES"
  
  validation {
    condition = contains([
      "FIFTEEN_MINUTES",
      "ONE_HOUR",
      "SIX_HOURS"
    ], var.macie_finding_publishing_frequency)
    error_message = "Macie finding publishing frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

# ===================================================================
# CloudTrail Configuration
# ===================================================================

variable "enable_local_cloudtrail" {
  description = "Enable local CloudTrail in the spoke account (if not using centralized CloudTrail)"
  type        = bool
  default     = false
}

variable "include_global_service_events" {
  description = "Include global service events in CloudTrail"
  type        = bool
  default     = true
}

variable "enable_multi_region_trail" {
  description = "Enable multi-region CloudTrail"
  type        = bool
  default     = true
}

variable "cloudtrail_log_group_arn" {
  description = "CloudWatch Log Group ARN for CloudTrail (optional)"
  type        = string
  default     = ""
}

variable "enable_data_events" {
  description = "Enable data events in CloudTrail"
  type        = bool
  default     = true
}

variable "data_event_selectors" {
  description = "Data event selectors for CloudTrail"
  type = list(object({
    name = string
    field_selectors = list(object({
      field  = string
      equals = list(string)
    }))
  }))
  default = [
    {
      name = "S3 Bucket Data Events"
      field_selectors = [
        {
          field  = "eventCategory"
          equals = ["Data"]
        },
        {
          field  = "resources.type"
          equals = ["AWS::S3::Object"]
        }
      ]
    }
  ]
}

# ===================================================================
# Logging Configuration
# ===================================================================

variable "enable_local_logging" {
  description = "Enable local S3 bucket for security logs (if not using hub bucket)"
  type        = bool
  default     = false
}

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

variable "log_level" {
  description = "Log level for Lambda functions and other components"
  type        = string
  default     = "INFO"
  
  validation {
    condition     = contains(["DEBUG", "INFO", "WARN", "ERROR"], var.log_level)
    error_message = "Log level must be one of: DEBUG, INFO, WARN, ERROR."
  }
}

# ===================================================================
# Lambda Configuration
# ===================================================================

variable "enable_local_processing" {
  description = "Enable local Lambda function for security processing"
  type        = bool
  default     = false
}

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

# ===================================================================
# Alerting Configuration
# ===================================================================

variable "critical_findings_threshold" {
  description = "Threshold for critical findings alarm"
  type        = number
  default     = 5
  
  validation {
    condition     = var.critical_findings_threshold >= 0
    error_message = "Critical findings threshold must be greater than or equal to 0."
  }
}

variable "high_findings_threshold" {
  description = "Threshold for high severity findings alarm"
  type        = number
  default     = 10
  
  validation {
    condition     = var.high_findings_threshold >= 0
    error_message = "High findings threshold must be greater than or equal to 0."
  }
}

# ===================================================================
# Cost Management Configuration
# ===================================================================

variable "enable_cost_optimization" {
  description = "Enable cost optimization features"
  type        = bool
  default     = true
}

variable "security_services_budget_limit" {
  description = "Monthly budget limit for security services in USD"
  type        = number
  default     = 100
  
  validation {
    condition     = var.security_services_budget_limit > 0
    error_message = "Security services budget limit must be greater than 0."
  }
}

# ===================================================================
# Networking Configuration
# ===================================================================

variable "vpc_flow_logs_format" {
  description = "VPC Flow Logs format specification"
  type        = string
  default     = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${windowstart} $${windowend} $${action} $${flowlogstatus}"
}

variable "vpc_flow_logs_max_aggregation_interval" {
  description = "Maximum aggregation interval for VPC Flow Logs in seconds"
  type        = number
  default     = 60
  
  validation {
    condition     = contains([60, 600], var.vpc_flow_logs_max_aggregation_interval)
    error_message = "VPC Flow Logs aggregation interval must be 60 or 600 seconds."
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
  description = "Team responsible for the spoke account security"
  type        = string
  default     = "security-team"
}

variable "business_unit" {
  description = "Business unit owning the spoke account"
  type        = string
  default     = "information-security"
}

variable "data_classification" {
  description = "Data classification level for the account"
  type        = string
  default     = "confidential"
  
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}

# ===================================================================
# Advanced Configuration
# ===================================================================

variable "enable_experimental_features" {
  description = "Enable experimental security features (use with caution)"
  type        = bool
  default     = false
}

variable "enable_automated_remediation" {
  description = "Enable automated remediation for low-risk findings"
  type        = bool
  default     = false
}

variable "remediation_lambda_timeout" {
  description = "Timeout for automated remediation Lambda functions in seconds"
  type        = number
  default     = 600
  
  validation {
    condition     = var.remediation_lambda_timeout >= 60 && var.remediation_lambda_timeout <= 900
    error_message = "Remediation Lambda timeout must be between 60 and 900 seconds."
  }
}

# ===================================================================
# Integration Configuration
# ===================================================================

variable "enable_ssm_integration" {
  description = "Enable AWS Systems Manager integration for compliance"
  type        = bool
  default     = true
}

variable "enable_cloudformation_drift_detection" {
  description = "Enable CloudFormation drift detection"
  type        = bool
  default     = true
}

variable "enable_trusted_advisor_integration" {
  description = "Enable AWS Trusted Advisor integration (requires Business/Enterprise support)"
  type        = bool
  default     = false
}

# ===================================================================
# Monitoring Configuration
# ===================================================================

variable "custom_metric_namespace" {
  description = "Namespace for custom CloudWatch metrics"
  type        = string
  default     = "Custom/SecurityPlatform"
}

variable "enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring with custom metrics"
  type        = bool
  default     = true
}

variable "metric_filter_patterns" {
  description = "CloudWatch Logs metric filter patterns for security events"
  type = map(object({
    pattern     = string
    metric_name = string
    namespace   = string
    value       = string
  }))
  default = {
    "root-usage" = {
      pattern     = "{ ($.userIdentity.type = \"Root\") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType != \"AwsServiceEvent\") }"
      metric_name = "RootUserUsage"
      namespace   = "Custom/SecurityPlatform"
      value       = "1"
    }
    "unauthorized-api-calls" = {
      pattern     = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
      metric_name = "UnauthorizedAPICalls"
      namespace   = "Custom/SecurityPlatform"
      value       = "1"
    }
  }
}
