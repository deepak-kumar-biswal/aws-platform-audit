# ===================================================================
# AWS Platform Audit System - Spoke Account IAM Roles and Policies
# ===================================================================
# This file defines all IAM roles, policies, and permissions required
# for the spoke account to operate in the AWS audit platform.
# ===================================================================

# ===================================================================
# Config Service Role
# ===================================================================

resource "aws_iam_role" "config_role" {
  name = "${local.resource_prefix}-config-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-config-role"
  })
}

resource "aws_iam_role_policy_attachment" "config_role_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  name = "${local.resource_prefix}-config-s3-policy"
  role = aws_iam_role.config_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = var.hub_s3_bucket_name != "" ? [
          "arn:aws:s3:::${var.hub_s3_bucket_name}"
        ] : [
          var.enable_local_logging ? aws_s3_bucket.spoke_security_logs[0].arn : ""
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:GetObjectAcl"
        ]
        Resource = var.hub_s3_bucket_name != "" ? [
          "arn:aws:s3:::${var.hub_s3_bucket_name}/config/${local.spoke_account_id}/*"
        ] : [
          var.enable_local_logging ? "${aws_s3_bucket.spoke_security_logs[0].arn}/*" : ""
        ]
      }
    ]
  })
}

# ===================================================================
# CloudTrail CloudWatch Logs Role (if local CloudTrail is enabled)
# ===================================================================

resource "aws_iam_role" "cloudtrail_logs_role" {
  count = var.enable_local_cloudtrail && var.cloudtrail_log_group_arn != "" ? 1 : 0
  name  = "${local.resource_prefix}-cloudtrail-logs-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-cloudtrail-logs-role"
  })
}

resource "aws_iam_role_policy" "cloudtrail_logs_policy" {
  count = var.enable_local_cloudtrail && var.cloudtrail_log_group_arn != "" ? 1 : 0
  name  = "${local.resource_prefix}-cloudtrail-logs-policy"
  role  = aws_iam_role.cloudtrail_logs_role[0].id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents",
          "logs:CreateLogGroup",
          "logs:CreateLogStream"
        ]
        Resource = "${var.cloudtrail_log_group_arn}:*"
      }
    ]
  })
}

# ===================================================================
# VPC Flow Logs Role (if VPC Flow Logs are enabled)
# ===================================================================

resource "aws_iam_role" "flow_logs_role" {
  count = var.enable_vpc_flow_logs ? 1 : 0
  name  = "${local.resource_prefix}-flow-logs-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-flow-logs-role"
  })
}

resource "aws_iam_role_policy" "flow_logs_policy" {
  count = var.enable_vpc_flow_logs ? 1 : 0
  name  = "${local.resource_prefix}-flow-logs-policy"
  role  = aws_iam_role.flow_logs_role[0].id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# ===================================================================
# EventBridge Cross-Account Role
# ===================================================================

resource "aws_iam_role" "eventbridge_cross_account_role" {
  name = "${local.resource_prefix}-eventbridge-cross-account-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-eventbridge-cross-account-role"
  })
}

resource "aws_iam_role_policy" "eventbridge_cross_account_policy" {
  name = "${local.resource_prefix}-eventbridge-cross-account-policy"
  role = aws_iam_role.eventbridge_cross_account_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "events:PutEvents"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:events:${local.spoke_region}:${var.hub_account_id}:event-bus/default"
      }
    ]
  })
}

# ===================================================================
# Lambda Local Security Processor Role (if enabled)
# ===================================================================

resource "aws_iam_role" "lambda_local_processor_role" {
  count = var.enable_local_processing ? 1 : 0
  name  = "${local.resource_prefix}-lambda-local-processor-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-lambda-local-processor-role"
  })
}

resource "aws_iam_role_policy_attachment" "lambda_local_processor_basic" {
  count      = var.enable_local_processing ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_local_processor_role[0].name
}

resource "aws_iam_role_policy" "lambda_local_processor_policy" {
  count = var.enable_local_processing ? 1 : 0
  name  = "${local.resource_prefix}-lambda-local-processor-policy"
  role  = aws_iam_role.lambda_local_processor_role[0].id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:BatchUpdateFindings"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:UpdateFindingsFeedback"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "access-analyzer:ListFindings",
          "access-analyzer:GetFinding"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "config:GetComplianceDetailsByConfigRule",
          "config:GetComplianceDetailsByResource",
          "config:DescribeConfigRules"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "inspector2:ListFindings",
          "inspector2:GetFinding"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "macie2:GetFindings",
          "macie2:ListFindings"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "events:PutEvents"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:events:${local.spoke_region}:${var.hub_account_id}:event-bus/default"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream", 
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ]
  })
}

# ===================================================================
# Cross-Account Role for Hub Account Access
# ===================================================================

resource "aws_iam_role" "hub_access_role" {
  name = "${local.resource_prefix}-hub-access-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${var.hub_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-hub-access-role"
  })
}

resource "aws_iam_role_policy" "hub_access_policy" {
  name = "${local.resource_prefix}-hub-access-policy"
  role = aws_iam_role.hub_access_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:BatchImportFindings",
          "securityhub:GetInsights",
          "securityhub:GetInsightResults"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:GetFindingsStatistics",
          "guardduty:ListFindings"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "access-analyzer:ListFindings",
          "access-analyzer:GetFinding"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "config:GetComplianceDetailsByConfigRule",
          "config:GetComplianceDetailsByResource",
          "config:DescribeConfigRules",
          "config:GetComplianceSummaryByConfigRule",
          "config:GetComplianceSummaryByResourceType"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "inspector2:ListFindings",
          "inspector2:GetFinding"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "macie2:GetFindings",
          "macie2:ListFindings"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribeRouteTables"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketPolicy",
          "s3:GetBucketAcl",
          "s3:GetBucketLocation",
          "s3:GetBucketLogging",
          "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketPublicAccessBlock",
          "s3:ListAllMyBuckets"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetAccountSummary",
          "iam:ListUsers",
          "iam:ListGroups",
          "iam:ListRoles",
          "iam:ListPolicies",
          "iam:GetAccountPasswordPolicy",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
          "iam:ListMFADevices"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:GetEventSelectors"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:ListKeys",
          "kms:DescribeKey",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:ListFunctions",
          "lambda:GetFunction",
          "lambda:GetPolicy"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
          "rds:DescribeDBSnapshots",
          "rds:DescribeDBClusterSnapshots"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "eks:ListClusters",
          "eks:DescribeCluster"
        ]
        Resource = "*"
      }
    ]
  })
}

# ===================================================================
# Inspector Service-Linked Role (if Inspector is enabled)
# ===================================================================

resource "aws_iam_service_linked_role" "inspector" {
  count            = var.enable_inspector ? 1 : 0
  aws_service_name = "inspector2.amazonaws.com"
  description      = "Service-linked role for Amazon Inspector"
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-inspector-service-linked-role"
  })
}

# ===================================================================
# Macie Service-Linked Role (if Macie is enabled)
# ===================================================================

resource "aws_iam_service_linked_role" "macie" {
  count            = var.enable_macie ? 1 : 0
  aws_service_name = "macie.amazonaws.com"
  description      = "Service-linked role for Amazon Macie"
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-macie-service-linked-role"
  })
}

# ===================================================================
# S3 Bucket Policy for Local Security Logs (if enabled)
# ===================================================================

resource "aws_s3_bucket_policy" "spoke_security_logs" {
  count  = var.enable_local_logging ? 1 : 0
  bucket = aws_s3_bucket.spoke_security_logs[0].id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyInsecureConnections"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.spoke_security_logs[0].arn,
          "${aws_s3_bucket.spoke_security_logs[0].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowConfigService"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "s3:GetBucketAcl",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.spoke_security_logs[0].arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = local.spoke_account_id
          }
        }
      },
      {
        Sid    = "AllowConfigServicePutObject"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.spoke_security_logs[0].arn}/config/AWSLogs/${local.spoke_account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"     = "bucket-owner-full-control"
            "AWS:SourceAccount" = local.spoke_account_id
          }
        }
      },
      {
        Sid    = "AllowCloudTrailService"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "s3:GetBucketAcl",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.spoke_security_logs[0].arn,
          "${aws_s3_bucket.spoke_security_logs[0].arn}/cloudtrail/AWSLogs/${local.spoke_account_id}/*"
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"     = "bucket-owner-full-control"
            "AWS:SourceAccount" = local.spoke_account_id
          }
        }
      },
      {
        Sid    = "AllowHubAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${var.hub_account_id}:root"
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.spoke_security_logs[0].arn,
          "${aws_s3_bucket.spoke_security_logs[0].arn}/*"
        ]
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })
}
