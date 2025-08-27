import boto3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from decimal import Decimal

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class CostAnalyzer:
    """
    Enterprise-grade Cost Analyzer for Security Services
    Analyzes and optimizes costs for AWS security services across the organization
    """
    
    def __init__(self):
        self.cost_explorer = boto3.client('ce')
        self.cloudwatch = boto3.client('cloudwatch')
        self.sns = boto3.client('sns')
        self.organizations = boto3.client('organizations')
        
    def lambda_handler(self, event, context):
        """Main Lambda handler for cost analysis"""
        try:
            logger.info("Starting cost analysis process")
            
            # Analyze costs for different time periods
            analysis_results = {}
            
            # Daily cost analysis
            daily_costs = self.analyze_daily_costs()
            analysis_results['daily'] = daily_costs
            
            # Monthly cost analysis
            monthly_costs = self.analyze_monthly_costs()
            analysis_results['monthly'] = monthly_costs
            
            # Cost optimization recommendations
            optimization_recommendations = self.generate_optimization_recommendations()
            analysis_results['optimizations'] = optimization_recommendations
            
            # Cost forecasting
            cost_forecast = self.forecast_costs()
            analysis_results['forecast'] = cost_forecast
            
            # Anomaly detection
            cost_anomalies = self.detect_cost_anomalies()
            analysis_results['anomalies'] = cost_anomalies
            
            # Send alerts if necessary
            self.send_cost_alerts(analysis_results)
            
            # Publish metrics to CloudWatch
            self.publish_cost_metrics(analysis_results)
            
            logger.info("Cost analysis completed successfully")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Cost analysis completed successfully',
                    'analysis_results': analysis_results
                }, default=self.decimal_serializer)
            }
            
        except Exception as e:
            logger.error(f"Error in cost analysis: {str(e)}")
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'error': str(e)
                })
            }
    
    def analyze_daily_costs(self) -> Dict[str, Any]:
        """Analyze daily costs for security services"""
        try:
            end_date = datetime.now().strftime('%Y-%m-%d')
            start_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
            
            response = self.cost_explorer.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date,
                    'End': end_date
                },
                Granularity='DAILY',
                Metrics=['BlendedCost', 'UsageQuantity'],
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    }
                ],
                Filter={
                    'Dimensions': {
                        'Key': 'SERVICE',
                        'Values': [
                            'Amazon GuardDuty',
                            'AWS Security Hub',
                            'AWS Config',
                            'Amazon Inspector',
                            'Amazon Macie',
                            'AWS CloudTrail',
                            'Access Analyzer'
                        ]
                    }
                }
            )
            
            daily_analysis = {
                'total_cost': Decimal('0'),
                'service_breakdown': {},
                'cost_trend': []
            }
            
            for result in response['ResultsByTime']:
                date = result['TimePeriod']['Start']
                daily_cost = Decimal('0')
                
                for group in result['Groups']:
                    service = group['Keys'][0]
                    cost = Decimal(group['Metrics']['BlendedCost']['Amount'])
                    
                    if service not in daily_analysis['service_breakdown']:
                        daily_analysis['service_breakdown'][service] = Decimal('0')
                    
                    daily_analysis['service_breakdown'][service] += cost
                    daily_cost += cost
                
                daily_analysis['cost_trend'].append({
                    'date': date,
                    'cost': daily_cost
                })
                daily_analysis['total_cost'] += daily_cost
            
            logger.info(f"Daily cost analysis completed. Total cost: ${daily_analysis['total_cost']}")
            return daily_analysis
            
        except Exception as e:
            logger.error(f"Error in daily cost analysis: {str(e)}")
            return {}
    
    def analyze_monthly_costs(self) -> Dict[str, Any]:
        """Analyze monthly costs and trends"""
        try:
            end_date = datetime.now().strftime('%Y-%m-%d')
            start_date = (datetime.now() - timedelta(days=90)).strftime('%Y-%m-%d')
            
            response = self.cost_explorer.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date,
                    'End': end_date
                },
                Granularity='MONTHLY',
                Metrics=['BlendedCost', 'UsageQuantity'],
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    },
                    {
                        'Type': 'DIMENSION',
                        'Key': 'LINKED_ACCOUNT'
                    }
                ],
                Filter={
                    'Dimensions': {
                        'Key': 'SERVICE',
                        'Values': [
                            'Amazon GuardDuty',
                            'AWS Security Hub',
                            'AWS Config',
                            'Amazon Inspector',
                            'Amazon Macie',
                            'AWS CloudTrail',
                            'Access Analyzer'
                        ]
                    }
                }
            )
            
            monthly_analysis = {
                'total_cost': Decimal('0'),
                'service_breakdown': {},
                'account_breakdown': {},
                'month_over_month_growth': Decimal('0')
            }
            
            monthly_totals = []
            
            for result in response['ResultsByTime']:
                month = result['TimePeriod']['Start']
                monthly_cost = Decimal('0')
                
                for group in result['Groups']:
                    service = group['Keys'][0]
                    account = group['Keys'][1]
                    cost = Decimal(group['Metrics']['BlendedCost']['Amount'])
                    
                    # Service breakdown
                    if service not in monthly_analysis['service_breakdown']:
                        monthly_analysis['service_breakdown'][service] = Decimal('0')
                    monthly_analysis['service_breakdown'][service] += cost
                    
                    # Account breakdown
                    if account not in monthly_analysis['account_breakdown']:
                        monthly_analysis['account_breakdown'][account] = Decimal('0')
                    monthly_analysis['account_breakdown'][account] += cost
                    
                    monthly_cost += cost
                
                monthly_totals.append(monthly_cost)
                monthly_analysis['total_cost'] += monthly_cost
            
            # Calculate month-over-month growth
            if len(monthly_totals) >= 2:
                current_month = monthly_totals[-1]
                previous_month = monthly_totals[-2]
                if previous_month > 0:
                    growth = ((current_month - previous_month) / previous_month) * 100
                    monthly_analysis['month_over_month_growth'] = growth
            
            logger.info(f"Monthly cost analysis completed. Total cost: ${monthly_analysis['total_cost']}")
            return monthly_analysis
            
        except Exception as e:
            logger.error(f"Error in monthly cost analysis: {str(e)}")
            return {}
    
    def generate_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Generate cost optimization recommendations"""
        recommendations = []
        
        try:
            # Get rightsizing recommendations
            rightsizing_response = self.cost_explorer.get_rightsizing_recommendation(
                Service='AmazonEC2'
            )
            
            for recommendation in rightsizing_response.get('RightsizingRecommendations', []):
                recommendations.append({
                    'type': 'rightsizing',
                    'resource_id': recommendation.get('ResourceId'),
                    'current_instance': recommendation.get('CurrentInstance', {}).get('InstanceType'),
                    'recommended_instance': recommendation.get('RightsizingType'),
                    'estimated_monthly_savings': recommendation.get('EstimatedMonthlySavings', {}).get('Amount', '0'),
                    'confidence': recommendation.get('Confidence', 'UNKNOWN')
                })
            
            # Add custom security service recommendations
            recommendations.extend(self.get_security_service_recommendations())
            
            logger.info(f"Generated {len(recommendations)} optimization recommendations")
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating optimization recommendations: {str(e)}")
            return []
    
    def get_security_service_recommendations(self) -> List[Dict[str, Any]]:
        """Get recommendations specific to security services"""
        recommendations = []
        
        # GuardDuty optimization
        recommendations.append({
            'type': 'security_optimization',
            'service': 'GuardDuty',
            'recommendation': 'Consider enabling GuardDuty S3 protection only for critical buckets',
            'potential_savings': '20-30%',
            'impact': 'Medium'
        })
        
        # Config optimization
        recommendations.append({
            'type': 'security_optimization',
            'service': 'Config',
            'recommendation': 'Reduce Config rule evaluation frequency for non-critical resources',
            'potential_savings': '15-25%',
            'impact': 'Low'
        })
        
        # CloudTrail optimization
        recommendations.append({
            'type': 'security_optimization',
            'service': 'CloudTrail',
            'recommendation': 'Use S3 Intelligent Tiering for CloudTrail logs older than 30 days',
            'potential_savings': '40-60%',
            'impact': 'None'
        })
        
        # Inspector optimization
        recommendations.append({
            'type': 'security_optimization',
            'service': 'Inspector',
            'recommendation': 'Schedule Inspector scans during off-peak hours',
            'potential_savings': '10-15%',
            'impact': 'None'
        })
        
        return recommendations
    
    def forecast_costs(self) -> Dict[str, Any]:
        """Forecast future costs based on historical data"""
        try:
            end_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
            start_date = datetime.now().strftime('%Y-%m-%d')
            
            response = self.cost_explorer.get_cost_forecast(
                TimePeriod={
                    'Start': start_date,
                    'End': end_date
                },
                Metric='BLENDED_COST',
                Granularity='MONTHLY',
                Filter={
                    'Dimensions': {
                        'Key': 'SERVICE',
                        'Values': [
                            'Amazon GuardDuty',
                            'AWS Security Hub',
                            'AWS Config',
                            'Amazon Inspector',
                            'Amazon Macie',
                            'AWS CloudTrail'
                        ]
                    }
                }
            )
            
            forecast = {
                'forecasted_amount': Decimal(response['Total']['Amount']),
                'confidence_interval': {
                    'lower': Decimal(response['Total']['Lower']),
                    'upper': Decimal(response['Total']['Upper'])
                },
                'forecast_period': f"{start_date} to {end_date}"
            }
            
            logger.info(f"Cost forecast generated: ${forecast['forecasted_amount']}")
            return forecast
            
        except Exception as e:
            logger.error(f"Error generating cost forecast: {str(e)}")
            return {}
    
    def detect_cost_anomalies(self) -> List[Dict[str, Any]]:
        """Detect cost anomalies using AWS Cost Anomaly Detection"""
        anomalies = []
        
        try:
            # Get cost anomaly detectors
            detectors_response = self.cost_explorer.get_anomaly_detectors()
            
            for detector in detectors_response.get('AnomalyDetectors', []):
                detector_arn = detector['AnomalyDetectorArn']
                
                # Get anomalies for this detector
                anomalies_response = self.cost_explorer.get_anomalies(
                    AnomalyDetectorArn=detector_arn,
                    DateInterval={
                        'StartDate': (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'),
                        'EndDate': datetime.now().strftime('%Y-%m-%d')
                    }
                )
                
                for anomaly in anomalies_response.get('Anomalies', []):
                    anomalies.append({
                        'anomaly_id': anomaly.get('AnomalyId'),
                        'anomaly_score': anomaly.get('AnomalyScore', {}).get('MaxScore', 0),
                        'impact': anomaly.get('Impact', {}).get('MaxImpact', 0),
                        'start_date': anomaly.get('AnomalyStartDate'),
                        'end_date': anomaly.get('AnomalyEndDate'),
                        'dimension_key': anomaly.get('DimensionKey'),
                        'feedback': anomaly.get('Feedback', 'UNKNOWN')
                    })
            
            logger.info(f"Detected {len(anomalies)} cost anomalies")
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting cost anomalies: {str(e)}")
            return []
    
    def send_cost_alerts(self, analysis_results: Dict[str, Any]):
        """Send cost alerts based on thresholds"""
        try:
            # Check for high daily costs
            daily_cost = analysis_results.get('daily', {}).get('total_cost', Decimal('0'))
            if daily_cost > Decimal('1000'):  # $1000 daily threshold
                self.send_alert(
                    f"High Daily Security Cost Alert: ${daily_cost}",
                    f"Daily security services cost has exceeded $1000. Current cost: ${daily_cost}"
                )
            
            # Check for month-over-month growth
            monthly_data = analysis_results.get('monthly', {})
            growth = monthly_data.get('month_over_month_growth', Decimal('0'))
            if growth > 20:  # 20% growth threshold
                self.send_alert(
                    f"High Cost Growth Alert: {growth}%",
                    f"Security services costs have grown by {growth}% month-over-month"
                )
            
            # Check for cost anomalies
            anomalies = analysis_results.get('anomalies', [])
            high_impact_anomalies = [a for a in anomalies if float(a.get('impact', 0)) > 100]
            if high_impact_anomalies:
                self.send_alert(
                    f"Cost Anomaly Alert: {len(high_impact_anomalies)} anomalies detected",
                    f"Detected {len(high_impact_anomalies)} high-impact cost anomalies"
                )
            
        except Exception as e:
            logger.error(f"Error sending cost alerts: {str(e)}")
    
    def send_alert(self, subject: str, message: str):
        """Send alert via SNS"""
        try:
            import os
            topic_arn = os.environ.get('COST_ALERT_TOPIC_ARN')
            if topic_arn:
                self.sns.publish(
                    TopicArn=topic_arn,
                    Subject=subject,
                    Message=message
                )
                logger.info(f"Sent cost alert: {subject}")
        except Exception as e:
            logger.error(f"Error sending alert: {str(e)}")
    
    def publish_cost_metrics(self, analysis_results: Dict[str, Any]):
        """Publish cost metrics to CloudWatch"""
        try:
            namespace = 'AWS/Security/Costs'
            
            # Publish daily cost metrics
            daily_data = analysis_results.get('daily', {})
            if daily_data:
                self.cloudwatch.put_metric_data(
                    Namespace=namespace,
                    MetricData=[
                        {
                            'MetricName': 'DailySecurityCost',
                            'Value': float(daily_data.get('total_cost', 0)),
                            'Unit': 'None',
                            'Timestamp': datetime.now()
                        }
                    ]
                )
            
            # Publish service-specific metrics
            service_breakdown = daily_data.get('service_breakdown', {})
            for service, cost in service_breakdown.items():
                self.cloudwatch.put_metric_data(
                    Namespace=namespace,
                    MetricData=[
                        {
                            'MetricName': 'ServiceCost',
                            'Value': float(cost),
                            'Unit': 'None',
                            'Dimensions': [
                                {
                                    'Name': 'Service',
                                    'Value': service
                                }
                            ],
                            'Timestamp': datetime.now()
                        }
                    ]
                )
            
            logger.info("Published cost metrics to CloudWatch")
            
        except Exception as e:
            logger.error(f"Error publishing cost metrics: {str(e)}")
    
    def decimal_serializer(self, obj):
        """JSON serializer for Decimal objects"""
        if isinstance(obj, Decimal):
            return float(obj)
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

# For Lambda deployment
cost_analyzer = CostAnalyzer()

def lambda_handler(event, context):
    """Lambda entry point"""
    return cost_analyzer.lambda_handler(event, context)
