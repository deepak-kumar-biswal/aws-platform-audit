# ===================================================================
# AWS Platform Audit System - CloudWatch Dashboards
# ===================================================================
# This file creates comprehensive CloudWatch dashboards for monitoring
# security posture, compliance status, and operational metrics.
# ===================================================================

# ===================================================================
# Executive Security Dashboard
# ===================================================================

resource "aws_cloudwatch_dashboard" "executive_security" {
  count          = var.create_executive_dashboard ? 1 : 0
  dashboard_name = "${local.resource_prefix}-executive-security-dashboard"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/SecurityHub", "ComplianceScore", "ComplianceType", "CIS"],
            [".", ".", "ComplianceType", "AWS-Foundational"],
            [".", ".", "ComplianceType", "PCI-DSS"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "Compliance Score by Framework"
          period  = 300
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/SecurityHub", "Findings", "ComplianceType", "FAILED", "SeverityLabel", "CRITICAL"],
            [".", ".", "ComplianceType", "FAILED", "SeverityLabel", "HIGH"],
            [".", ".", "ComplianceType", "FAILED", "SeverityLabel", "MEDIUM"],
            [".", ".", "ComplianceType", "FAILED", "SeverityLabel", "LOW"]
          ]
          view    = "timeSeries"
          stacked = true
          region  = var.region
          title   = "Security Findings by Severity"
          period  = 300
          stat    = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 8
        height = 6
        
        properties = {
          metrics = [
            ["AWS/GuardDuty", "FindingCount", "DetectorId", aws_guardduty_detector.hub.id]
          ]
          view    = "singleValue"
          region  = var.region
          title   = "Active GuardDuty Findings"
          period  = 300
          stat    = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 6
        width  = 8
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Config", "ComplianceByConfigRule", "ConfigRuleName", "root-access-key-check", "ComplianceType", "COMPLIANT"],
            [".", ".", "ConfigRuleName", "root-access-key-check", "ComplianceType", "NON_COMPLIANT"]
          ]
          view    = "pie"
          region  = var.region
          title   = "Root Access Key Compliance"
          period  = 3600
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 6
        width  = 8
        height = 6
        
        properties = {
          metrics = [
            ["AWS/AccessAnalyzer", "FindingsCount", "AnalyzerName", aws_accessanalyzer_analyzer.hub.analyzer_name]
          ]
          view    = "singleValue"
          region  = var.region
          title   = "Access Analyzer Findings"
          period  = 3600
          stat    = "Average"
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 12
        width  = 24
        height = 6
        
        properties = {
          query   = "SOURCE '/aws/events/rule/${local.resource_prefix}-security-hub-findings' | fields @timestamp, detail.findings.Title, detail.findings.Severity.Label\n| filter detail.findings.Severity.Label in ['CRITICAL', 'HIGH']\n| sort @timestamp desc\n| limit 20"
          region  = var.region
          title   = "Recent Critical and High Severity Findings"
          view    = "table"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name        = "${local.resource_prefix}-executive-security-dashboard"
    DashboardType = "Executive"
    Purpose     = "Executive Security Overview"
  })
}

# ===================================================================
# Operational Security Dashboard
# ===================================================================

resource "aws_cloudwatch_dashboard" "operational_security" {
  count          = var.create_operational_dashboard ? 1 : 0
  dashboard_name = "${local.resource_prefix}-operational-security-dashboard"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 8
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.security_findings_processor.function_name],
            [".", "Errors", ".", "."],
            [".", "Throttles", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "Security Processor Lambda Performance"
          period  = 300
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 0
        width  = 8
        height = 6
        
        properties = {
          metrics = [
            ["AWS/SNS", "NumberOfMessagesPublished", "TopicName", aws_sns_topic.security_alerts.name],
            [".", ".", "TopicName", aws_sns_topic.compliance_alerts.name],
            [".", ".", "TopicName", aws_sns_topic.operational_alerts.name]
          ]
          view    = "timeSeries"
          stacked = true
          region  = var.region
          title   = "SNS Message Volume by Topic"
          period  = 300
          stat    = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 0
        width  = 8
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Events", "SuccessfulInvocations", "RuleName", aws_cloudwatch_event_rule.security_hub_findings.name],
            [".", ".", "RuleName", aws_cloudwatch_event_rule.guardduty_findings.name],
            [".", ".", "RuleName", aws_cloudwatch_event_rule.config_compliance_changes.name]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "EventBridge Rule Invocations"
          period  = 300
          stat    = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/S3", "BucketSizeBytes", "BucketName", aws_s3_bucket.security_data_lake.bucket, "StorageType", "StandardStorage"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "Security Data Lake Storage Usage"
          period  = 86400
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/CloudTrail", "ErrorCount", "TrailName", aws_cloudtrail.hub_audit_trail.name],
            [".", "DataEvents", ".", "."],
            [".", "ManagementEvents", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "CloudTrail Event Volume and Errors"
          period  = 300
          stat    = "Sum"
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 12
        width  = 12
        height = 6
        
        properties = {
          query   = "SOURCE '/aws/lambda/${aws_lambda_function.security_findings_processor.function_name}' | fields @timestamp, @message\n| filter @message like /ERROR/\n| sort @timestamp desc\n| limit 20"
          region  = var.region
          title   = "Security Processor Lambda Errors"
          view    = "table"
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 12
        width  = 12
        height = 6
        
        properties = {
          query   = "SOURCE '${aws_cloudwatch_log_group.cloudtrail.name}' | fields @timestamp, sourceIPAddress, eventName, userIdentity.type\n| filter errorCode exists\n| sort @timestamp desc\n| limit 20"
          region  = var.region
          title   = "CloudTrail API Errors"
          view    = "table"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name        = "${local.resource_prefix}-operational-security-dashboard"
    DashboardType = "Operational"
    Purpose     = "Operational Security Monitoring"
  })
}

# ===================================================================
# Compliance Dashboard
# ===================================================================

resource "aws_cloudwatch_dashboard" "compliance" {
  count          = var.create_compliance_dashboard ? 1 : 0
  dashboard_name = "${local.resource_prefix}-compliance-dashboard"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 8
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Config", "ComplianceByConfigRule", "ConfigRuleName", "encrypted-volumes", "ComplianceType", "COMPLIANT"],
            [".", ".", ".", ".", "ComplianceType", "NON_COMPLIANT"]
          ]
          view    = "pie"
          region  = var.region
          title   = "EBS Volume Encryption Compliance"
          period  = 3600
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 0
        width  = 8
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Config", "ComplianceByConfigRule", "ConfigRuleName", "s3-bucket-server-side-encryption-enabled", "ComplianceType", "COMPLIANT"],
            [".", ".", ".", ".", "ComplianceType", "NON_COMPLIANT"]
          ]
          view    = "pie"
          region  = var.region
          title   = "S3 Bucket Encryption Compliance"
          period  = 3600
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 0
        width  = 8
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Config", "ComplianceByConfigRule", "ConfigRuleName", "iam-password-policy", "ComplianceType", "COMPLIANT"],
            [".", ".", ".", ".", "ComplianceType", "NON_COMPLIANT"]
          ]
          view    = "pie"
          region  = var.region
          title   = "IAM Password Policy Compliance"
          period  = 3600
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Config", "ComplianceByConfigRule", "ConfigRuleName", "cloudtrail-enabled", "ComplianceType", "COMPLIANT"],
            [".", ".", "ConfigRuleName", "cloudwatch-log-group-encrypted", "ComplianceType", "COMPLIANT"],
            [".", ".", "ConfigRuleName", "vpc-flow-logs-enabled", "ComplianceType", "COMPLIANT"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "Logging and Monitoring Compliance"
          period  = 3600
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Config", "ComplianceByConfigRule", "ConfigRuleName", "security-group-ssh-restricted", "ComplianceType", "NON_COMPLIANT"],
            [".", ".", "ConfigRuleName", "security-group-rdp-restricted", "ComplianceType", "NON_COMPLIANT"],
            [".", ".", "ConfigRuleName", "s3-bucket-public-access-prohibited", "ComplianceType", "NON_COMPLIANT"]
          ]
          view    = "timeSeries"
          stacked = true
          region  = var.region
          title   = "Network Security Non-Compliance"
          period  = 3600
          stat    = "Sum"
        }
      },
      {
        type   = "text"
        x      = 0
        y      = 12
        width  = 8
        height = 4
        
        properties = {
          markdown = "## Compliance Frameworks\n\n✅ **CIS AWS Foundations v1.4**\n\n✅ **AWS Foundational Security**\n\n✅ **PCI DSS v3.2.1**\n\n⚠️ **HIPAA Security Rule** (Optional)\n\n⚠️ **NIST 800-53** (Optional)"
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 12
        width  = 8
        height = 4
        
        properties = {
          metrics = [
            ["AWS/Config", "ConfigurationRecordersCount"],
            [".", "ConfigurationRecordersCompliantCount"]
          ]
          view    = "singleValue"
          region  = var.region
          title   = "Config Recorders Status"
          period  = 3600
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 12
        width  = 8
        height = 4
        
        properties = {
          metrics = [
            ["AWS/Config", "TotalDiscoveredResources"]
          ]
          view    = "singleValue"
          region  = var.region
          title   = "Total Discovered Resources"
          period  = 3600
          stat    = "Average"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name        = "${local.resource_prefix}-compliance-dashboard"
    DashboardType = "Compliance"
    Purpose     = "Compliance Monitoring"
  })
}

# ===================================================================
# Cost and Performance Dashboard
# ===================================================================

resource "aws_cloudwatch_dashboard" "cost_performance" {
  dashboard_name = "${local.resource_prefix}-cost-performance-dashboard"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 8
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Billing", "EstimatedCharges", "ServiceName", "AmazonGuardDuty", "Currency", "USD"],
            [".", ".", "ServiceName", "AWSSecurityHub", ".", "."],
            [".", ".", "ServiceName", "AWSConfig", ".", "."],
            [".", ".", "ServiceName", "AWSCloudTrail", ".", "."]
          ]
          view    = "timeSeries"
          stacked = true
          region  = "us-east-1"  # Billing metrics are only available in us-east-1
          title   = "Security Services Cost Breakdown"
          period  = 86400
          stat    = "Maximum"
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 0
        width  = 8
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.security_findings_processor.function_name],
            [".", "Invocations", ".", "."],
            [".", "ConcurrentExecutions", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "Lambda Function Performance"
          period  = 300
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 0
        width  = 8
        height = 6
        
        properties = {
          metrics = [
            ["AWS/S3", "NumberOfObjects", "BucketName", aws_s3_bucket.security_data_lake.bucket, "StorageType", "AllStorageTypes"],
            ["AWS/S3", "BucketSizeBytes", "BucketName", aws_s3_bucket.security_data_lake.bucket, "StorageType", "StandardStorage"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "Data Lake Storage Metrics"
          period  = 86400
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["CWAgent", "proc_stat", "process_name", "security-findings-processor", "metric_type", "cpu_usage"],
            [".", ".", ".", ".", "metric_type", "memory_usage"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "Process Resource Utilization"
          period  = 300
          stat    = "Average"
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        
        properties = {
          query   = "SOURCE '/aws/cost/anomaly-detector' | fields @timestamp, anomalyScore, impact.maxImpact\n| filter anomalyScore > 50\n| sort @timestamp desc\n| limit 10"
          region  = var.region
          title   = "Cost Anomaly Detection Alerts"
          view    = "table"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name        = "${local.resource_prefix}-cost-performance-dashboard"
    DashboardType = "Cost-Performance"
    Purpose     = "Cost and Performance Monitoring"
  })
}

# ===================================================================
# Multi-Account Overview Dashboard
# ===================================================================

resource "aws_cloudwatch_dashboard" "multi_account_overview" {
  dashboard_name = "${local.resource_prefix}-multi-account-overview"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2
        
        properties = {
          markdown = "# AWS Audit Platform - Multi-Account Security Overview\n\n**Hub Account:** ${local.hub_account_id} | **Monitored Accounts:** ${length(var.spoke_account_ids)} | **Regions:** ${length(var.monitoring_regions)} | **Last Updated:** ${timestamp()}"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 2
        width  = 6
        height = 6
        
        properties = {
          metrics = [
            for account_id in var.spoke_account_ids : [
              "Custom/SecurityPlatform", "SecurityScore", "AccountId", account_id
            ]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "Security Score by Account"
          period  = 3600
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 6
        y      = 2
        width  = 6
        height = 6
        
        properties = {
          metrics = [
            for account_id in var.spoke_account_ids : [
              "Custom/SecurityPlatform", "ComplianceRatio", "AccountId", account_id
            ]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "Compliance Ratio by Account"
          period  = 3600
          stat    = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 2
        width  = 6
        height = 6
        
        properties = {
          metrics = [
            for account_id in var.spoke_account_ids : [
              "Custom/SecurityPlatform", "CriticalFindings", "AccountId", account_id
            ]
          ]
          view    = "timeSeries"
          stacked = true
          region  = var.region
          title   = "Critical Findings by Account"
          period  = 3600
          stat    = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 2
        width  = 6
        height = 6
        
        properties = {
          metrics = [
            for region in var.monitoring_regions : [
              "Custom/SecurityPlatform", "RegionalFindings", "Region", region
            ]
          ]
          view    = "timeSeries"
          stacked = true
          region  = var.region
          title   = "Findings by Region"
          period  = 3600
          stat    = "Sum"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name        = "${local.resource_prefix}-multi-account-overview"
    DashboardType = "Multi-Account"
    Purpose     = "Cross-Account Security Overview"
  })
}
