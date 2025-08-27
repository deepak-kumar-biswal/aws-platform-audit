# ===================================================================
# AWS Platform Audit System - Spoke Account Main Configuration
# ===================================================================
# This file defines the infrastructure for spoke accounts in the
# AWS audit platform, including local security services that report
# to the hub account.
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
    AccountType        = "spoke"
    HubAccount         = var.hub_account_id
    LastUpdated        = timestamp()
  }
  
  # Spoke account specific configurations
  spoke_account_id = data.aws_caller_identity.current.account_id
  spoke_region     = data.aws_region.current.name
  
  # Generate unique naming convention
  resource_prefix = "${var.project_name}-${var.environment}-spoke"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# ===================================================================
# Random Resources for Unique Naming
# ===================================================================

resource "random_id" "spoke_suffix" {
  byte_length = 4
}

# ===================================================================
# S3 Bucket for Local Security Logs (if required)
# ===================================================================

resource "aws_s3_bucket" "spoke_security_logs" {
  count  = var.enable_local_logging ? 1 : 0
  bucket = "${local.resource_prefix}-security-logs-${random_id.spoke_suffix.hex}"
  
  tags = merge(local.common_tags, {
    Name    = "${local.resource_prefix}-security-logs"
    Purpose = "Local Security Logs"
  })
}

resource "aws_s3_bucket_versioning" "spoke_security_logs" {
  count  = var.enable_local_logging ? 1 : 0
  bucket = aws_s3_bucket.spoke_security_logs[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "spoke_security_logs" {
  count  = var.enable_local_logging ? 1 : 0
  bucket = aws_s3_bucket.spoke_security_logs[0].id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "spoke_security_logs" {
  count  = var.enable_local_logging ? 1 : 0
  bucket = aws_s3_bucket.spoke_security_logs[0].id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ===================================================================
# Security Hub Configuration (Spoke Account)
# ===================================================================

resource "aws_securityhub_account" "spoke" {
  enable_default_standards = true
  
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true
  
  tags = local.common_tags
}

# Accept invitation from hub account (if invitation exists)
resource "aws_securityhub_member" "hub_invitation" {
  count      = var.hub_account_id != "" ? 1 : 0
  account_id = var.hub_account_id
  email      = var.hub_account_email
  invite     = true
  
  depends_on = [aws_securityhub_account.spoke]
}

# Enable Security Standards in spoke account
resource "aws_securityhub_standards_subscription" "cis_spoke" {
  standards_arn = "arn:${data.aws_partition.current.partition}:securityhub:${local.spoke_region}:${local.spoke_account_id}:standard/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.spoke]
}

resource "aws_securityhub_standards_subscription" "aws_foundational_spoke" {
  standards_arn = "arn:${data.aws_partition.current.partition}:securityhub:${local.spoke_region}:${local.spoke_account_id}:standard/aws-foundational-security/v/1.0.0"
  depends_on    = [aws_securityhub_account.spoke]
}

resource "aws_securityhub_standards_subscription" "pci_dss_spoke" {
  count         = var.enable_pci_dss_standard ? 1 : 0
  standards_arn = "arn:${data.aws_partition.current.partition}:securityhub:${local.spoke_region}:${local.spoke_account_id}:standard/pci-dss/v/3.2.1"
  depends_on    = [aws_securityhub_account.spoke]
}

# ===================================================================
# GuardDuty Configuration (Spoke Account)
# ===================================================================

resource "aws_guardduty_detector" "spoke" {
  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_publishing_frequency
  
  datasources {
    s3_logs {
      enable = var.enable_guardduty_s3_protection
    }
    kubernetes {
      audit_logs {
        enable = var.enable_guardduty_eks_protection
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_guardduty_malware_protection
        }
      }
    }
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-guardduty-detector"
  })
}

# Accept GuardDuty invitation from hub account
resource "aws_guardduty_member" "hub_invitation" {
  count                      = var.hub_account_id != "" ? 1 : 0
  account_id                = var.hub_account_id
  detector_id               = aws_guardduty_detector.spoke.id
  email                     = var.hub_account_email
  invite                    = true
  disable_email_notification = true
}

# ===================================================================
# Config Configuration (Spoke Account)
# ===================================================================

resource "aws_config_configuration_recorder" "spoke" {
  name     = "${local.resource_prefix}-config-recorder"
  role_arn = aws_iam_role.config_role.arn
  
  recording_group {
    all_supported                 = true
    include_global_resource_types = var.include_global_resources
    recording_mode {
      recording_frequency                = var.config_recording_frequency
      recording_mode_override {
        description         = "Override for sensitive resources"
        resource_types      = var.sensitive_resource_types
        recording_frequency = "CONTINUOUS"
      }
    }
  }
  
  depends_on = [aws_config_delivery_channel.spoke]
}

resource "aws_config_delivery_channel" "spoke" {
  name           = "${local.resource_prefix}-config-delivery-channel"
  s3_bucket_name = var.hub_s3_bucket_name != "" ? var.hub_s3_bucket_name : aws_s3_bucket.spoke_security_logs[0].bucket
  s3_key_prefix  = "config/${local.spoke_account_id}"
  
  snapshot_delivery_properties {
    delivery_frequency = var.config_snapshot_delivery_frequency
  }
}

# Deploy Config Conformance Packs
resource "aws_config_conformance_pack" "cis_conformance_pack" {
  name = "${local.resource_prefix}-cis-conformance-pack"
  
  template_body = file("${path.module}/../../conformance-packs/cis-aws-foundations-benchmark.yaml")
  
  input_parameter {
    parameter_name   = "AccessKeysRotatedParamMaxAccessKeyAge"
    parameter_value = "90"
  }
  
  input_parameter {
    parameter_name   = "IamPasswordPolicyParamMaxPasswordAge"
    parameter_value = "90"
  }
  
  depends_on = [
    aws_config_configuration_recorder.spoke,
    aws_config_delivery_channel.spoke
  ]
  
  tags = merge(local.common_tags, {
    Name             = "${local.resource_prefix}-cis-conformance-pack"
    ConformancePack = "CIS-AWS-Foundations"
  })
}

resource "aws_config_conformance_pack" "operational_best_practices" {
  for_each = var.operational_conformance_packs
  
  name = "${local.resource_prefix}-${each.key}-conformance-pack"
  
  template_s3_uri = each.value.template_uri
  
  dynamic "input_parameter" {
    for_each = each.value.input_parameters
    content {
      parameter_name  = input_parameter.key
      parameter_value = input_parameter.value
    }
  }
  
  depends_on = [
    aws_config_configuration_recorder.spoke,
    aws_config_delivery_channel.spoke
  ]
  
  tags = merge(local.common_tags, {
    Name             = "${local.resource_prefix}-${each.key}-conformance-pack"
    ConformancePack = each.key
  })
}

# ===================================================================
# Access Analyzer Configuration (Spoke Account)
# ===================================================================

resource "aws_accessanalyzer_analyzer" "spoke" {
  analyzer_name = "${local.resource_prefix}-access-analyzer"
  type         = var.enable_organization_analyzer ? "ORGANIZATION" : "ACCOUNT"
  
  configuration {
    unused_access {
      unused_access_age = var.unused_access_age_days
    }
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-access-analyzer"
  })
}

# ===================================================================
# CloudTrail Configuration (Spoke Account)
# ===================================================================

resource "aws_cloudtrail" "spoke_audit_trail" {
  count                         = var.enable_local_cloudtrail ? 1 : 0
  name                          = "${local.resource_prefix}-audit-trail"
  s3_bucket_name               = var.hub_s3_bucket_name != "" ? var.hub_s3_bucket_name : aws_s3_bucket.spoke_security_logs[0].bucket
  s3_key_prefix                = "cloudtrail/${local.spoke_account_id}"
  include_global_service_events = var.include_global_service_events
  is_multi_region_trail        = var.enable_multi_region_trail
  enable_logging               = true
  
  # Enable CloudWatch Logs integration if specified
  dynamic "cloud_watch_logs_group_arn" {
    for_each = var.cloudtrail_log_group_arn != "" ? [1] : []
    content {
      cloud_watch_logs_group_arn = var.cloudtrail_log_group_arn
      cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_logs_role[0].arn
    }
  }
  
  # Data events for sensitive resources
  dynamic "advanced_event_selector" {
    for_each = var.enable_data_events ? var.data_event_selectors : []
    content {
      name = advanced_event_selector.value.name
      
      dynamic "field_selector" {
        for_each = advanced_event_selector.value.field_selectors
        content {
          field  = field_selector.value.field
          equals = field_selector.value.equals
        }
      }
    }
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-audit-trail"
  })
}

# ===================================================================
# Inspector Configuration (if enabled)
# ===================================================================

resource "aws_inspector2_enabler" "spoke" {
  count           = var.enable_inspector ? 1 : 0
  account_ids     = [local.spoke_account_id]
  resource_types  = var.inspector_resource_types
}

# ===================================================================
# Macie Configuration (if enabled)
# ===================================================================

resource "aws_macie2_account" "spoke" {
  count                        = var.enable_macie ? 1 : 0
  finding_publishing_frequency = var.macie_finding_publishing_frequency
  status                       = "ENABLED"
  
  tags = local.common_tags
}

# ===================================================================
# EventBridge Rules for Cross-Account Event Forwarding
# ===================================================================

resource "aws_cloudwatch_event_rule" "security_findings_to_hub" {
  name        = "${local.resource_prefix}-security-findings-to-hub"
  description = "Forward security findings to hub account"
  
  event_pattern = jsonencode({
    source = [
      "aws.securityhub",
      "aws.guardduty", 
      "aws.access-analyzer",
      "aws.config",
      "aws.inspector2",
      "aws.macie"
    ]
    detail-type = [
      "Security Hub Findings - Imported",
      "GuardDuty Finding",
      "Access Analyzer Finding", 
      "Config Rules Compliance Change",
      "Inspector2 Finding",
      "Macie Finding"
    ]
  })
  
  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "forward_to_hub" {
  rule      = aws_cloudwatch_event_rule.security_findings_to_hub.name
  target_id = "ForwardToHubAccount"
  arn       = "arn:${data.aws_partition.current.partition}:events:${local.spoke_region}:${var.hub_account_id}:event-bus/default"
  role_arn  = aws_iam_role.eventbridge_cross_account_role.arn
}

# ===================================================================
# VPC Flow Logs (if enabled)
# ===================================================================

data "aws_vpcs" "spoke_vpcs" {
  count = var.enable_vpc_flow_logs ? 1 : 0
}

resource "aws_flow_log" "spoke_vpc_flow_logs" {
  count           = var.enable_vpc_flow_logs ? length(data.aws_vpcs.spoke_vpcs[0].ids) : 0
  iam_role_arn    = aws_iam_role.flow_logs_role[0].arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs[0].arn
  traffic_type    = "ALL"
  vpc_id          = data.aws_vpcs.spoke_vpcs[0].ids[count.index]
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-vpc-flow-logs-${count.index}"
  })
}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  count             = var.enable_vpc_flow_logs ? 1 : 0
  name              = "/aws/vpc/flowlogs/${local.resource_prefix}"
  retention_in_days = var.log_retention_days
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-vpc-flow-logs"
  })
}

# ===================================================================
# Custom CloudWatch Metrics for Security Posture
# ===================================================================

resource "aws_cloudwatch_metric_alarm" "critical_security_findings" {
  alarm_name          = "${local.resource_prefix}-critical-security-findings"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CriticalFindings"
  namespace           = "Custom/SecurityPlatform"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.critical_findings_threshold
  alarm_description   = "Critical security findings detected"
  
  dimensions = {
    AccountId = local.spoke_account_id
  }
  
  alarm_actions = var.hub_account_id != "" ? [
    "arn:${data.aws_partition.current.partition}:sns:${local.spoke_region}:${var.hub_account_id}:${var.hub_sns_topic_name}"
  ] : []
  
  tags = local.common_tags
}

# ===================================================================
# Lambda Function for Local Security Processing (Optional)
# ===================================================================

resource "aws_lambda_function" "local_security_processor" {
  count         = var.enable_local_processing ? 1 : 0
  filename      = "local_security_processor.zip"
  function_name = "${local.resource_prefix}-local-security-processor"
  role          = aws_iam_role.lambda_local_processor_role[0].arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 300
  memory_size   = var.lambda_memory_size
  
  environment {
    variables = {
      HUB_ACCOUNT_ID     = var.hub_account_id
      SPOKE_ACCOUNT_ID   = local.spoke_account_id
      HUB_REGION        = var.hub_region
      LOG_LEVEL         = var.log_level
    }
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-local-security-processor"
  })
  
  depends_on = [
    aws_iam_role_policy_attachment.lambda_local_processor_basic,
    aws_cloudwatch_log_group.lambda_local_processor,
  ]
}

resource "aws_cloudwatch_log_group" "lambda_local_processor" {
  count             = var.enable_local_processing ? 1 : 0
  name              = "/aws/lambda/${local.resource_prefix}-local-security-processor"
  retention_in_days = var.log_retention_days
  
  tags = local.common_tags
}

# ===================================================================
# Outputs
# ===================================================================

output "spoke_account_id" {
  description = "AWS Account ID of the spoke account"
  value       = local.spoke_account_id
}

output "security_hub_arn" {
  description = "Security Hub ARN for spoke account"
  value       = aws_securityhub_account.spoke.arn
}

output "guardduty_detector_id" {
  description = "GuardDuty Detector ID for spoke account"
  value       = aws_guardduty_detector.spoke.id
}

output "access_analyzer_arn" {
  description = "Access Analyzer ARN for spoke account"
  value       = aws_accessanalyzer_analyzer.spoke.arn
}

output "config_recorder_name" {
  description = "Config Recorder name for spoke account"
  value       = aws_config_configuration_recorder.spoke.name
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN for spoke account (if enabled)"
  value       = var.enable_local_cloudtrail ? aws_cloudtrail.spoke_audit_trail[0].arn : null
}

output "eventbridge_rule_arn" {
  description = "EventBridge rule ARN for cross-account forwarding"
  value       = aws_cloudwatch_event_rule.security_findings_to_hub.arn
}
