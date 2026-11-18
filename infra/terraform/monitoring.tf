# -------------------------------------------------------------------------------------------------
# Detective controls: every signature by the deployer key, and any attempt to disable or delete it,
# is alerted and archived. Relies on the account's CloudTrail management-event trail (on by default
# in AWS Organizations/Control Tower landing zones).
# -------------------------------------------------------------------------------------------------
resource "aws_sns_topic" "security_alerts" {
  name              = "${local.name}-security-alerts"
  kms_master_key_id = aws_kms_key.platform.arn
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.security_alerts_topic.json
}

data "aws_iam_policy_document" "security_alerts_topic" {
  statement {
    sid     = "AllowEventBridgePublishFromThisAccount"
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sns_topic.security_alerts.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_sns_topic_subscription" "security_alert_email" {
  for_each = toset(var.security_alert_emails)

  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_cloudwatch_event_rule" "deployer_key_activity" {
  name        = "${local.name}-deployer-key-activity"
  description = "Any use or tampering of the contract deployer KMS key."

  event_pattern = jsonencode({
    source        = ["aws.kms"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["kms.amazonaws.com"]
      eventName = [
        "Sign",
        "DisableKey",
        "ScheduleKeyDeletion",
        "PutKeyPolicy",
        "CreateGrant",
      ]
      requestParameters = {
        keyId = [aws_kms_key.deployer.arn, aws_kms_key.deployer.key_id, aws_kms_alias.deployer.name]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "deployer_key_activity_sns" {
  rule      = aws_cloudwatch_event_rule.deployer_key_activity.name
  target_id = "sns-security-alerts"
  arn       = aws_sns_topic.security_alerts.arn
}

resource "aws_cloudwatch_log_group" "deployer_key_audit" {
  name              = "/${var.project}/${var.environment}/deployer-key-audit"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.platform.arn
}

resource "aws_cloudwatch_event_target" "deployer_key_activity_logs" {
  rule      = aws_cloudwatch_event_rule.deployer_key_activity.name
  target_id = "cloudwatch-audit-log"
  arn       = aws_cloudwatch_log_group.deployer_key_audit.arn
}

# EventBridge needs a resource policy on CloudWatch Logs to deliver events.
data "aws_iam_policy_document" "eventbridge_to_logs" {
  statement {
    sid     = "EventBridgeToDeployerKeyAuditLog"
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "delivery.logs.amazonaws.com"]
    }
    resources = ["${aws_cloudwatch_log_group.deployer_key_audit.arn}:*"]
  }
}

resource "aws_cloudwatch_log_resource_policy" "eventbridge_to_logs" {
  policy_name     = "${local.name}-eventbridge-to-logs"
  policy_document = data.aws_iam_policy_document.eventbridge_to_logs.json
}
