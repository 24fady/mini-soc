#!/bin/bash
# Run once from your laptop / CloudShell (needs AWS CLI credentials).
# Creates: metric filters on the app log, an SNS topic with e-mail subscription, and alarms.
set -euo pipefail
REGION="eu-central-1"        # <-- change
EMAIL="you@example.com"      # <-- change
LOG_GROUP="mini-soc/app"

aws logs create-log-group --region "$REGION" --log-group-name "$LOG_GROUP" 2>/dev/null || true

# 1) every block event becomes a metric
aws logs put-metric-filter --region "$REGION" --log-group-name "$LOG_GROUP" \
  --filter-name ip-blocked \
  --filter-pattern '{ $.event = "ip_blocked" }' \
  --metric-transformations metricName=IPBlocked,metricNamespace=MiniSOC,metricValue=1,defaultValue=0

# 2) every failed login becomes a metric
aws logs put-metric-filter --region "$REGION" --log-group-name "$LOG_GROUP" \
  --filter-name failed-login \
  --filter-pattern '{ $.event = "failed_login" }' \
  --metric-transformations metricName=FailedLogins,metricNamespace=MiniSOC,metricValue=1,defaultValue=0

# 3) SNS topic + e-mail (confirm the subscription from your inbox!)
TOPIC_ARN=$(aws sns create-topic --region "$REGION" --name mini-soc-alerts --query TopicArn --output text)
aws sns subscribe --region "$REGION" --topic-arn "$TOPIC_ARN" --protocol email --notification-endpoint "$EMAIL"

# 4) alarms
aws cloudwatch put-metric-alarm --region "$REGION" --alarm-name mini-soc-ip-blocked \
  --namespace MiniSOC --metric-name IPBlocked --statistic Sum --period 60 \
  --evaluation-periods 1 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching --alarm-actions "$TOPIC_ARN"

aws cloudwatch put-metric-alarm --region "$REGION" --alarm-name mini-soc-failed-login-spike \
  --namespace MiniSOC --metric-name FailedLogins --statistic Sum --period 60 \
  --evaluation-periods 1 --threshold 20 --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching --alarm-actions "$TOPIC_ARN"

echo "Done. Confirm the SNS subscription e-mail, then run the attack test."
