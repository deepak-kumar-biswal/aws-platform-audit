import boto3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class DashboardGenerator:
    """
    Enterprise-grade CloudWatch Dashboard Generator
    Creates dynamic dashboards for security metrics and compliance status
    """
    
    def __init__(self):
        self.cloudwatch = boto3.client('cloudwatch')
        self.organizations = boto3.client('organizations')
        
    def lambda_handler(self, event, context):
        """Main Lambda handler for dashboard generation"""
        try:
            logger.info("Starting dashboard generation process")
            
            # Generate different types of dashboards
            dashboards_created = []
            
            # Executive Dashboard
            executive_dashboard = self.create_executive_dashboard()
            dashboards_created.append(executive_dashboard)
            
            # Operational Dashboard  
            operational_dashboard = self.create_operational_dashboard()
            dashboards_created.append(operational_dashboard)
            
            # Compliance Dashboard
            compliance_dashboard = self.create_compliance_dashboard()
            dashboards_created.append(compliance_dashboard)
            
            # Account-specific dashboards
            account_dashboards = self.create_account_dashboards()
            dashboards_created.extend(account_dashboards)
            
            logger.info(f"Successfully created {len(dashboards_created)} dashboards")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': f'Successfully created {len(dashboards_created)} dashboards',
                    'dashboards': dashboards_created
                })
            }
            
        except Exception as e:
            logger.error(f"Error in dashboard generation: {str(e)}")
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'error': str(e)
                })
            }
    
    def create_executive_dashboard(self) -> str:
        """Create executive-level dashboard with high-level metrics"""
        dashboard_name = "AWS-Security-Executive-Dashboard"
        
        dashboard_body = {
            "widgets": [
                {
                    "type": "metric",
                    "x": 0, "y": 0,
                    "width": 12, "height": 6,
                    "properties": {
                        "metrics": [
                            ["AWS/SecurityHub", "Findings", "ComplianceType", "PASSED"],
                            [".", ".", ".", "FAILED"],
                            [".", ".", ".", "WARNING"]
                        ],
                        "view": "timeSeries",
                        "stacked": False,
                        "region": "us-east-1",
                        "title": "Security Hub Compliance Overview",
                        "period": 300,
                        "stat": "Sum"
                    }
                },
                {
                    "type": "metric", 
                    "x": 12, "y": 0,
                    "width": 12, "height": 6,
                    "properties": {
                        "metrics": [
                            ["AWS/GuardDuty", "FindingCount", "Severity", "High"],
                            [".", ".", ".", "Medium"],
                            [".", ".", ".", "Low"]
                        ],
                        "view": "timeSeries",
                        "stacked": True,
                        "region": "us-east-1", 
                        "title": "GuardDuty Threat Detection",
                        "period": 300,
                        "stat": "Sum"
                    }
                },
                {
                    "type": "log",
                    "x": 0, "y": 6,
                    "width": 24, "height": 6,
                    "properties": {
                        "query": "SOURCE '/aws/lambda/security-findings-processor' | fields @timestamp, account_id, severity, finding_type\n| filter severity = \"CRITICAL\" or severity = \"HIGH\"\n| sort @timestamp desc\n| limit 50",
                        "region": "us-east-1",
                        "title": "Critical Security Findings (Last 24 Hours)",
                        "view": "table"
                    }
                }
            ]
        }
        
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            logger.info(f"Created executive dashboard: {dashboard_name}")
            return dashboard_name
        except Exception as e:
            logger.error(f"Failed to create executive dashboard: {str(e)}")
            raise
    
    def create_operational_dashboard(self) -> str:
        """Create operational dashboard with detailed metrics"""
        dashboard_name = "AWS-Security-Operational-Dashboard"
        
        dashboard_body = {
            "widgets": [
                {
                    "type": "metric",
                    "x": 0, "y": 0,
                    "width": 8, "height": 6,
                    "properties": {
                        "metrics": [
                            ["AWS/Config", "ComplianceByConfigRule"],
                            ["AWS/Config", "ComplianceByResource"]
                        ],
                        "view": "timeSeries",
                        "stacked": False,
                        "region": "us-east-1",
                        "title": "Config Rule Compliance",
                        "period": 300,
                        "stat": "Average"
                    }
                },
                {
                    "type": "metric",
                    "x": 8, "y": 0, 
                    "width": 8, "height": 6,
                    "properties": {
                        "metrics": [
                            ["AWS/Inspector2", "FindingCounts", "Severity", "CRITICAL"],
                            [".", ".", ".", "HIGH"],
                            [".", ".", ".", "MEDIUM"]
                        ],
                        "view": "timeSeries",
                        "stacked": True,
                        "region": "us-east-1",
                        "title": "Inspector Vulnerability Findings",
                        "period": 300,
                        "stat": "Sum"
                    }
                },
                {
                    "type": "metric",
                    "x": 16, "y": 0,
                    "width": 8, "height": 6,
                    "properties": {
                        "metrics": [
                            ["AWS/Macie", "SensitiveDataFindings"],
                            ["AWS/AccessAnalyzer", "AnalyzerFindings"]
                        ],
                        "view": "timeSeries",
                        "stacked": False,
                        "region": "us-east-1",
                        "title": "Data Protection & Access Analysis",
                        "period": 300,
                        "stat": "Sum"
                    }
                }
            ]
        }
        
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            logger.info(f"Created operational dashboard: {dashboard_name}")
            return dashboard_name
        except Exception as e:
            logger.error(f"Failed to create operational dashboard: {str(e)}")
            raise
    
    def create_compliance_dashboard(self) -> str:
        """Create compliance-specific dashboard"""
        dashboard_name = "AWS-Security-Compliance-Dashboard"
        
        dashboard_body = {
            "widgets": [
                {
                    "type": "log",
                    "x": 0, "y": 0,
                    "width": 12, "height": 8,
                    "properties": {
                        "query": "SOURCE '/aws/lambda/security-findings-processor' | fields @timestamp, compliance_standard, compliance_status, account_id\n| filter compliance_standard like /CIS/\n| stats count() by compliance_status\n| sort count desc",
                        "region": "us-east-1",
                        "title": "CIS Compliance Status Distribution",
                        "view": "pie"
                    }
                },
                {
                    "type": "log",
                    "x": 12, "y": 0,
                    "width": 12, "height": 8,
                    "properties": {
                        "query": "SOURCE '/aws/lambda/security-findings-processor' | fields @timestamp, compliance_standard, compliance_status, account_id\n| filter compliance_standard like /PCI/\n| stats count() by compliance_status\n| sort count desc",
                        "region": "us-east-1", 
                        "title": "PCI-DSS Compliance Status Distribution",
                        "view": "pie"
                    }
                },
                {
                    "type": "log",
                    "x": 0, "y": 8,
                    "width": 24, "height": 6,
                    "properties": {
                        "query": "SOURCE '/aws/lambda/security-findings-processor' | fields @timestamp, account_id, compliance_standard, rule_name, compliance_status\n| filter compliance_status = \"FAILED\"\n| sort @timestamp desc\n| limit 100",
                        "region": "us-east-1",
                        "title": "Failed Compliance Checks (Recent)",
                        "view": "table"
                    }
                }
            ]
        }
        
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            logger.info(f"Created compliance dashboard: {dashboard_name}")
            return dashboard_name
        except Exception as e:
            logger.error(f"Failed to create compliance dashboard: {str(e)}")
            raise
    
    def create_account_dashboards(self) -> List[str]:
        """Create account-specific dashboards for top accounts by findings"""
        dashboards_created = []
        
        try:
            # Get list of accounts with most security findings
            top_accounts = self.get_top_accounts_by_findings()
            
            for account_info in top_accounts[:10]:  # Top 10 accounts
                account_id = account_info['account_id']
                dashboard_name = f"AWS-Security-Account-{account_id}"
                
                dashboard_body = {
                    "widgets": [
                        {
                            "type": "log",
                            "x": 0, "y": 0,
                            "width": 24, "height": 8,
                            "properties": {
                                "query": f"SOURCE '/aws/lambda/security-findings-processor' | fields @timestamp, severity, finding_type, resource_id\n| filter account_id = \"{account_id}\"\n| stats count() by severity\n| sort count desc",
                                "region": "us-east-1",
                                "title": f"Security Findings for Account {account_id}",
                                "view": "pie"
                            }
                        },
                        {
                            "type": "log",
                            "x": 0, "y": 8,
                            "width": 24, "height": 6,
                            "properties": {
                                "query": f"SOURCE '/aws/lambda/security-findings-processor' | fields @timestamp, severity, finding_type, resource_id, description\n| filter account_id = \"{account_id}\" and (severity = \"CRITICAL\" or severity = \"HIGH\")\n| sort @timestamp desc\n| limit 50",
                                "region": "us-east-1",
                                "title": f"Critical/High Findings for Account {account_id}",
                                "view": "table"
                            }
                        }
                    ]
                }
                
                self.cloudwatch.put_dashboard(
                    DashboardName=dashboard_name,
                    DashboardBody=json.dumps(dashboard_body)
                )
                dashboards_created.append(dashboard_name)
                logger.info(f"Created account dashboard: {dashboard_name}")
                
        except Exception as e:
            logger.error(f"Failed to create account dashboards: {str(e)}")
            
        return dashboards_created
    
    def get_top_accounts_by_findings(self) -> List[Dict[str, Any]]:
        """Get accounts with the most security findings"""
        # This would typically query CloudWatch Logs Insights or a data store
        # For now, return a mock list
        return [
            {'account_id': '123456789012', 'finding_count': 150},
            {'account_id': '123456789013', 'finding_count': 98}, 
            {'account_id': '123456789014', 'finding_count': 76},
            {'account_id': '123456789015', 'finding_count': 45}
        ]

# For Lambda deployment
dashboard_generator = DashboardGenerator()

def lambda_handler(event, context):
    """Lambda entry point"""
    return dashboard_generator.lambda_handler(event, context)
