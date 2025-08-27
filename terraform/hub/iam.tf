# ===================================================================
# AWS Platform Audit System - Hub Account IAM Roles and Policies
# ===================================================================
# This file defines all IAM roles, policies, and permissions required
# for the hub account to operate the AWS audit platform securely.
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
        Resource = aws_s3_bucket.security_data_lake.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:GetObjectAcl"
        ]
        Resource = "${aws_s3_bucket.security_data_lake.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.security_audit_key.arn
      }
    ]
  })
}

# ===================================================================
# CloudTrail CloudWatch Logs Role
# ===================================================================

resource "aws_iam_role" "cloudtrail_logs_role" {
  name = "${local.resource_prefix}-cloudtrail-logs-role"
  
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
  name = "${local.resource_prefix}-cloudtrail-logs-policy"
  role = aws_iam_role.cloudtrail_logs_role.id
  
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
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

# ===================================================================
# Lambda Security Findings Processor Role
# ===================================================================

resource "aws_iam_role" "lambda_security_processor_role" {
  name = "${local.resource_prefix}-lambda-security-processor-role"
  
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
    Name = "${local.resource_prefix}-lambda-security-processor-role"
  })
}

resource "aws_iam_role_policy_attachment" "lambda_security_processor_basic" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_security_processor_role.name
}

resource "aws_iam_role_policy" "lambda_security_processor_policy" {
  name = "${local.resource_prefix}-lambda-security-processor-policy"
  role = aws_iam_role.lambda_security_processor_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.security_alerts.arn,
          aws_sns_topic.compliance_alerts.arn,
          aws_sns_topic.operational_alerts.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.security_data_lake.arn,
          "${aws_s3_bucket.security_data_lake.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.security_audit_key.arn
      },
      {
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:BatchUpdateFindings",
          "securityhub:UpdateFindings"
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
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.security_dlq.arn
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
# Lambda Dashboard Generator Role
# ===================================================================

resource "aws_iam_role" "lambda_dashboard_generator_role" {
  name = "${local.resource_prefix}-lambda-dashboard-generator-role"
  
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
    Name = "${local.resource_prefix}-lambda-dashboard-generator-role"
  })
}

resource "aws_iam_role_policy_attachment" "lambda_dashboard_generator_basic" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_dashboard_generator_role.name
}

resource "aws_iam_role_policy" "lambda_dashboard_generator_policy" {
  name = "${local.resource_prefix}-lambda-dashboard-generator-policy"
  role = aws_iam_role.lambda_dashboard_generator_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutDashboard",
          "cloudwatch:GetDashboard",
          "cloudwatch:ListDashboards",
          "cloudwatch:DeleteDashboard"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
          "cloudwatch:GetMetricData"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.security_data_lake.arn,
          "${aws_s3_bucket.security_data_lake.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:GetInsights",
          "securityhub:GetInsightResults"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:GetFindingsStatistics"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "access-analyzer:ListFindings"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "config:GetComplianceSummaryByConfigRule",
          "config:GetComplianceSummaryByResourceType"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.security_audit_key.arn
      }
    ]
  })
}

# ===================================================================
# Lambda Cost Analyzer Role
# ===================================================================

resource "aws_iam_role" "lambda_cost_analyzer_role" {
  name = "${local.resource_prefix}-lambda-cost-analyzer-role"
  
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
    Name = "${local.resource_prefix}-lambda-cost-analyzer-role"
  })
}

resource "aws_iam_role_policy_attachment" "lambda_cost_analyzer_basic" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_cost_analyzer_role.name
}

resource "aws_iam_role_policy" "lambda_cost_analyzer_policy" {
  name = "${local.resource_prefix}-lambda-cost-analyzer-policy"
  role = aws_iam_role.lambda_cost_analyzer_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ce:GetCostAndUsage",
          "ce:GetUsageReport",
          "ce:GetRightsizingRecommendation",
          "ce:GetReservationCoverage",
          "ce:GetReservationPurchaseRecommendation",
          "ce:GetReservationUtilization",
          "ce:ListCostCategoryDefinitions",
          "ce:GetDimensionValues",
          "ce:GetMetrics",
          "ce:GetAnomalies",
          "ce:GetAnomalyDetectors",
          "ce:GetAnomalySubscriptions"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "budgets:ViewBudget",
          "budgets:ViewBudgetPerformanceHistory"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "organizations:ListAccounts",
          "organizations:DescribeAccount",
          "organizations:ListOrganizationalUnitsForParent",
          "organizations:ListRoots"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.security_alerts.arn,
          aws_sns_topic.operational_alerts.arn
        ]
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
# Cross-Account Role for Spoke Account Access
# ===================================================================

resource "aws_iam_role" "spoke_access_role" {
  name = "${local.resource_prefix}-spoke-access-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            for account_id in var.spoke_account_ids :
            "arn:aws:iam::${account_id}:root"
          ]
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
    Name = "${local.resource_prefix}-spoke-access-role"
  })
}

resource "aws_iam_role_policy" "spoke_access_policy" {
  name = "${local.resource_prefix}-spoke-access-policy"
  role = aws_iam_role.spoke_access_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "securityhub:EnableSecurityHub",
          "securityhub:GetFindings",
          "securityhub:BatchImportFindings",
          "securityhub:CreateMembers",
          "securityhub:InviteMembers"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "guardduty:CreateDetector",
          "guardduty:InviteMembers",
          "guardduty:CreateMembers",
          "guardduty:GetFindings"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "config:PutConfigurationRecorder",
          "config:PutDeliveryChannel",
          "config:StartConfigurationRecorder"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "access-analyzer:CreateAnalyzer",
          "access-analyzer:ListFindings"
        ]
        Resource = "*"
      }
    ]
  })
}

# ===================================================================
# S3 Bucket Policy for Security Data Lake
# ===================================================================

resource "aws_s3_bucket_policy" "security_data_lake" {
  bucket = aws_s3_bucket.security_data_lake.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyInsecureConnections"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.security_data_lake.arn,
          "${aws_s3_bucket.security_data_lake.arn}/*"
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
        Resource = aws_s3_bucket.security_data_lake.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = local.hub_account_id
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
        Resource = "${aws_s3_bucket.security_data_lake.arn}/config/AWSLogs/${local.hub_account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"     = "bucket-owner-full-control"
            "AWS:SourceAccount" = local.hub_account_id
          }
        }
      },
      {
        Sid    = "AllowConfigServiceGetBucketAcl"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.security_data_lake.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = local.hub_account_id
          }
        }
      }
    ]
  })
}

# CloudTrail S3 Bucket Policy
resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.security_data_lake.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.security_data_lake.arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${local.hub_region}:${local.hub_account_id}:trail/${local.resource_prefix}-audit-trail"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.security_data_lake.arn}/cloudtrail/AWSLogs/${local.hub_account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:aws:cloudtrail:${local.hub_region}:${local.hub_account_id}:trail/${local.resource_prefix}-audit-trail"
          }
        }
      }
    ]
  })
  
  depends_on = [aws_s3_bucket_policy.security_data_lake]
}

# ===================================================================
# SNS Topic Policies
# ===================================================================

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = local.hub_account_id
          }
        }
      },
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_security_processor_role.arn
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

resource "aws_sns_topic_policy" "compliance_alerts" {
  arn = aws_sns_topic.compliance_alerts.arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.compliance_alerts.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = local.hub_account_id
          }
        }
      },
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_security_processor_role.arn
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.compliance_alerts.arn
      }
    ]
  })
}

resource "aws_sns_topic_policy" "operational_alerts" {
  arn = aws_sns_topic.operational_alerts.arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.operational_alerts.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = local.hub_account_id
          }
        }
      },
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.lambda_security_processor_role.arn,
            aws_iam_role.lambda_cost_analyzer_role.arn
          ]
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.operational_alerts.arn
      }
    ]
  })
}
