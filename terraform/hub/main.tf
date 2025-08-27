# ===================================================================
# AWS Platform Audit System - Hub Account Main Configuration
# ===================================================================
# This file defines the core infrastructure for the hub account in the
# AWS audit platform, including Security Hub, centralized logging,
# dashboards, and notification systems.
# ===================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
  }
}

# ===================================================================
# Local Variables and Data Sources
# ===================================================================

locals {
  common_tags = {
    Project             = var.project_name
    Environment         = var.environment
    ManagedBy          = "Terraform"
    SecurityLevel      = "Critical"
    ComplianceFramework = "CIS-AWS-1.4"
    DataClassification = "Confidential"
    CreatedBy          = "aws-audit-platform"
    LastUpdated        = timestamp()
  }
  
  # Hub account specific configurations
  hub_account_id = data.aws_caller_identity.current.account_id
  hub_region     = data.aws_region.current.name
  
  # Generate unique naming convention
  resource_prefix = "${var.project_name}-${var.environment}"
  
  # Security Hub member accounts (spoke accounts)
  member_accounts = var.spoke_account_ids
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# ===================================================================
# Random Resources for Unique Naming
# ===================================================================

resource "random_id" "hub_suffix" {
  byte_length = 4
}

# ===================================================================
# S3 Bucket for Centralized Security Logs and Data Lake
# ===================================================================

resource "aws_s3_bucket" "security_data_lake" {
  bucket = "${local.resource_prefix}-security-data-lake-${random_id.hub_suffix.hex}"
  
  tags = merge(local.common_tags, {
    Name        = "${local.resource_prefix}-security-data-lake"
    Purpose     = "Security Data Lake"
    DataType    = "Security Logs and Findings"
    Retention   = "7-years"
  })
}

resource "aws_s3_bucket_versioning" "security_data_lake" {
  bucket = aws_s3_bucket.security_data_lake.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_data_lake" {
  bucket = aws_s3_bucket.security_data_lake.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.security_audit_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "security_data_lake" {
  bucket = aws_s3_bucket.security_data_lake.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "security_data_lake" {
  bucket = aws_s3_bucket.security_data_lake.id
  
  rule {
    id     = "security_logs_lifecycle"
    status = "Enabled"
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }
    
    expiration {
      days = 2555  # 7 years retention
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# ===================================================================
# KMS Key for Security Data Encryption
# ===================================================================

resource "aws_kms_key" "security_audit_key" {
  description         = "KMS key for AWS Security Audit Platform"
  key_usage          = "ENCRYPT_DECRYPT"
  key_spec           = "SYMMETRIC_DEFAULT"
  enable_key_rotation = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${local.hub_account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Security Hub Service"
        Effect = "Allow"
        Principal = {
          Service = "securityhub.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow GuardDuty Service"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Config Service"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-security-audit-key"
  })
}

resource "aws_kms_alias" "security_audit_key" {
  name          = "alias/${local.resource_prefix}-security-audit-key"
  target_key_id = aws_kms_key.security_audit_key.key_id
}

# ===================================================================
# Security Hub Configuration (Hub Account)
# ===================================================================

resource "aws_securityhub_account" "hub" {
  enable_default_standards = true
  
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true
  
  tags = local.common_tags
}

# Enable Security Standards
resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:${data.aws_partition.current.partition}:securityhub:${local.hub_region}:${local.hub_account_id}:standard/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.hub]
}

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:${data.aws_partition.current.partition}:securityhub:${local.hub_region}:${local.hub_account_id}:standard/aws-foundational-security/v/1.0.0"
  depends_on    = [aws_securityhub_account.hub]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  standards_arn = "arn:${data.aws_partition.current.partition}:securityhub:${local.hub_region}:${local.hub_account_id}:standard/pci-dss/v/3.2.1"
  depends_on    = [aws_securityhub_account.hub]
}

# Configure Security Hub as aggregator for multi-region
resource "aws_securityhub_finding_aggregator" "hub" {
  linking_mode      = "ALL_REGIONS"
  specified_regions = var.monitoring_regions
  
  depends_on = [aws_securityhub_account.hub]
}

# ===================================================================
# GuardDuty Configuration (Hub Account)
# ===================================================================

resource "aws_guardduty_detector" "hub" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-guardduty-detector"
  })
}

# GuardDuty S3 bucket for malware protection
resource "aws_s3_bucket" "guardduty_malware" {
  bucket = "${local.resource_prefix}-guardduty-malware-${random_id.hub_suffix.hex}"
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-guardduty-malware"
    Purpose = "GuardDuty Malware Scanning"
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_malware" {
  bucket = aws_s3_bucket.guardduty_malware.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.security_audit_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# ===================================================================
# Config Configuration (Hub Account)
# ===================================================================

resource "aws_config_configuration_recorder" "hub" {
  name     = "${local.resource_prefix}-config-recorder"
  role_arn = aws_iam_role.config_role.arn
  
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
    recording_mode {
      recording_frequency                = "DAILY"
      recording_mode_override {
        description         = "Override for EC2 instances"
        resource_types      = ["AWS::EC2::Instance"]
        recording_frequency = "CONTINUOUS"
      }
    }
  }
  
  depends_on = [aws_config_delivery_channel.hub]
}

resource "aws_config_delivery_channel" "hub" {
  name           = "${local.resource_prefix}-config-delivery-channel"
  s3_bucket_name = aws_s3_bucket.security_data_lake.bucket
  s3_key_prefix  = "config"
  
  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }
}

# ===================================================================
# Access Analyzer Configuration
# ===================================================================

resource "aws_accessanalyzer_analyzer" "hub" {
  analyzer_name = "${local.resource_prefix}-access-analyzer"
  type         = "ORGANIZATION"
  
  configuration {
    unused_access {
      unused_access_age = 30
    }
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-access-analyzer"
  })
}

# ===================================================================
# CloudTrail Configuration (Multi-Region)
# ===================================================================

resource "aws_cloudtrail" "hub_audit_trail" {
  name                          = "${local.resource_prefix}-audit-trail"
  s3_bucket_name               = aws_s3_bucket.security_data_lake.bucket
  s3_key_prefix                = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_logging               = true
  
  kms_key_id = aws_kms_key.security_audit_key.arn
  
  # Enable CloudWatch Logs integration
  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.cloudtrail.arn
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_logs_role.arn
  
  # Data events for sensitive resources
  advanced_event_selector {
    name = "S3 Bucket Data Events"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
  }
  
  advanced_event_selector {
    name = "Lambda Function Data Events"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::Lambda::Function"]
    }
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-audit-trail"
  })
  
  depends_on = [aws_s3_bucket_policy.cloudtrail_bucket_policy]
}

# CloudWatch Log Group for CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.resource_prefix}-audit-trail"
  retention_in_days = var.log_retention_days
  kms_key_id       = aws_kms_key.security_audit_key.arn
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-cloudtrail-logs"
  })
}

# ===================================================================
# Cost Anomaly Detection
# ===================================================================

resource "aws_ce_anomaly_detector" "security_cost_anomaly" {
  name         = "${local.resource_prefix}-security-cost-anomaly"
  detector_type = "DIMENSIONAL"
  
  specification = jsonencode({
    Dimension = "SERVICE"
    MatchOptions = ["EQUALS"]
    Values = [
      "Amazon GuardDuty",
      "AWS Security Hub",
      "AWS Config",
      "AWS CloudTrail",
      "Amazon Inspector"
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-security-cost-anomaly"
  })
}

resource "aws_ce_anomaly_subscription" "security_cost_anomaly" {
  name      = "${local.resource_prefix}-security-cost-anomaly-subscription"
  frequency = "DAILY"
  
  monitor_arn_list = [
    aws_ce_anomaly_detector.security_cost_anomaly.arn
  ]
  
  subscriber {
    type    = "EMAIL"
    address = var.notification_email
  }
  
  threshold_expression {
    and {
      dimension {
        key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
        values        = ["100"]
        match_options = ["GREATER_THAN_OR_EQUAL"]
      }
    }
  }
  
  tags = local.common_tags
}

# ===================================================================
# EventBridge Rules for Security Events
# ===================================================================

resource "aws_cloudwatch_event_rule" "security_hub_findings" {
  name        = "${local.resource_prefix}-security-hub-findings"
  description = "Capture Security Hub findings"
  
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
      }
    }
  })
  
  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${local.resource_prefix}-guardduty-findings"
  description = "Capture GuardDuty findings"
  
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [7.0, 8.0, 8.5, 9.0, 9.5, 10.0]  # High and Critical severity
    }
  })
  
  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "access_analyzer_findings" {
  name        = "${local.resource_prefix}-access-analyzer-findings"
  description = "Capture Access Analyzer findings"
  
  event_pattern = jsonencode({
    source      = ["aws.access-analyzer"]
    detail-type = ["Access Analyzer Finding"]
  })
  
  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "config_compliance_changes" {
  name        = "${local.resource_prefix}-config-compliance-changes"
  description = "Capture Config compliance state changes"
  
  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
  
  tags = local.common_tags
}

# ===================================================================
# SNS Topics for Notifications
# ===================================================================

resource "aws_sns_topic" "security_alerts" {
  name              = "${local.resource_prefix}-security-alerts"
  kms_master_key_id = aws_kms_key.security_audit_key.arn
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-security-alerts"
    Purpose = "Security Alerting"
  })
}

resource "aws_sns_topic" "compliance_alerts" {
  name              = "${local.resource_prefix}-compliance-alerts"
  kms_master_key_id = aws_kms_key.security_audit_key.arn
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-compliance-alerts"
    Purpose = "Compliance Alerting"
  })
}

resource "aws_sns_topic" "operational_alerts" {
  name              = "${local.resource_prefix}-operational-alerts"
  kms_master_key_id = aws_kms_key.security_audit_key.arn
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-operational-alerts"
    Purpose = "Operational Alerting"
  })
}

# SNS Topic Subscriptions
resource "aws_sns_topic_subscription" "security_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_email
}

resource "aws_sns_topic_subscription" "compliance_email" {
  topic_arn = aws_sns_topic.compliance_alerts.arn
  protocol  = "email"
  endpoint  = var.compliance_email
}

resource "aws_sns_topic_subscription" "operational_email" {
  topic_arn = aws_sns_topic.operational_alerts.arn
  protocol  = "email"
  endpoint  = var.operational_email
}

# ===================================================================
# Lambda Functions for Processing and Notifications
# ===================================================================

# Security Findings Processor Lambda
resource "aws_lambda_function" "security_findings_processor" {
  filename         = "security_findings_processor.zip"
  function_name    = "${local.resource_prefix}-security-findings-processor"
  role            = aws_iam_role.lambda_security_processor_role.arn
  handler         = "index.handler"
  runtime         = "python3.11"
  timeout         = 300
  memory_size     = 512
  
  environment {
    variables = {
      SECURITY_SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
      S3_BUCKET             = aws_s3_bucket.security_data_lake.bucket
      KMS_KEY_ID           = aws_kms_key.security_audit_key.key_id
      LOG_LEVEL            = "INFO"
    }
  }
  
  dead_letter_config {
    target_arn = aws_sqs_queue.security_dlq.arn
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-security-findings-processor"
  })
  
  depends_on = [
    aws_iam_role_policy_attachment.lambda_security_processor_policy,
    aws_cloudwatch_log_group.lambda_security_processor,
  ]
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_security_processor" {
  name              = "/aws/lambda/${local.resource_prefix}-security-findings-processor"
  retention_in_days = var.log_retention_days
  kms_key_id       = aws_kms_key.security_audit_key.arn
  
  tags = local.common_tags
}

# Dead Letter Queue for Lambda
resource "aws_sqs_queue" "security_dlq" {
  name = "${local.resource_prefix}-security-dlq"
  
  kms_master_key_id                = aws_kms_key.security_audit_key.arn
  kms_data_key_reuse_period_seconds = 300
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-security-dlq"
  })
}

# EventBridge Targets
resource "aws_cloudwatch_event_target" "security_hub_to_lambda" {
  rule      = aws_cloudwatch_event_rule.security_hub_findings.name
  target_id = "SecurityHubToLambda"
  arn       = aws_lambda_function.security_findings_processor.arn
}

resource "aws_cloudwatch_event_target" "guardduty_to_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "GuardDutyToLambda"
  arn       = aws_lambda_function.security_findings_processor.arn
}

resource "aws_cloudwatch_event_target" "access_analyzer_to_lambda" {
  rule      = aws_cloudwatch_event_rule.access_analyzer_findings.name
  target_id = "AccessAnalyzerToLambda"
  arn       = aws_lambda_function.security_findings_processor.arn
}

resource "aws_cloudwatch_event_target" "config_compliance_to_lambda" {
  rule      = aws_cloudwatch_event_rule.config_compliance_changes.name
  target_id = "ConfigComplianceToLambda"
  arn       = aws_lambda_function.security_findings_processor.arn
}

# Lambda permissions for EventBridge
resource "aws_lambda_permission" "allow_eventbridge_security_hub" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_findings_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_hub_findings.arn
}

resource "aws_lambda_permission" "allow_eventbridge_guardduty" {
  statement_id  = "AllowExecutionFromEventBridgeGuardDuty"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_findings_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}

resource "aws_lambda_permission" "allow_eventbridge_access_analyzer" {
  statement_id  = "AllowExecutionFromEventBridgeAccessAnalyzer"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_findings_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.access_analyzer_findings.arn
}

resource "aws_lambda_permission" "allow_eventbridge_config" {
  statement_id  = "AllowExecutionFromEventBridgeConfig"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_findings_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_compliance_changes.arn
}

# ===================================================================
# Outputs
# ===================================================================

output "hub_account_id" {
  description = "AWS Account ID of the hub account"
  value       = local.hub_account_id
}

output "security_data_lake_bucket" {
  description = "S3 bucket for security data lake"
  value       = aws_s3_bucket.security_data_lake.bucket
}

output "security_alerts_topic_arn" {
  description = "SNS Topic ARN for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "compliance_alerts_topic_arn" {
  description = "SNS Topic ARN for compliance alerts"
  value       = aws_sns_topic.compliance_alerts.arn
}

output "kms_key_arn" {
  description = "KMS Key ARN for security audit encryption"
  value       = aws_kms_key.security_audit_key.arn
}

output "security_hub_arn" {
  description = "Security Hub ARN"
  value       = aws_securityhub_account.hub.arn
}

output "guardduty_detector_id" {
  description = "GuardDuty Detector ID"
  value       = aws_guardduty_detector.hub.id
}

output "access_analyzer_arn" {
  description = "Access Analyzer ARN"
  value       = aws_accessanalyzer_analyzer.hub.arn
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN"
  value       = aws_cloudtrail.hub_audit_trail.arn
}
