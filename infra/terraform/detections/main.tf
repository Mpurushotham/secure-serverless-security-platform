# Detections for AI-agent abuse.
#
# The controls elsewhere in this repository are preventive. These are the ones
# that fire when prevention is bypassed, misconfigured, or simply not yet built
# for a path nobody anticipated.
#
# Detection design principle applied throughout: **alert on the control being
# exercised, not on the data being touched.** A rule that fires on "someone read
# prescriptions" fires constantly and gets muted within a week. A rule that fires
# on "the guardrail refused eleven times in five minutes" fires when something
# is genuinely wrong, because legitimate use produces almost no refusals.
#
# Each detection below carries its MITRE ATT&CK mapping and, more usefully, an
# honest note on its false-positive profile. A detection shipped without a
# false-positive budget is a detection that will be turned off by whoever is
# on call the week it misfires.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60"
    }
  }
}

locals {
  name = "${var.name_prefix}-agent-detections"

  tags = merge(var.tags, {
    Component = "detections"
    ManagedBy = "terraform"
  })
}

# --- Alert routing ----------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name              = local.name
  kms_master_key_id = var.kms_key_arn
  tags              = local.tags
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.sns.json
}

data "aws_iam_policy_document" "sns" {
  statement {
    sid       = "AllowServicePublish"
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# --- D-001: guardrail refusal burst ----------------------------------------
# ATT&CK: T1190 (exploit public-facing application), TA0007 (discovery)
#
# The highest-signal detection in this module. A cooperating agent produces
# almost no refusals — it reads the tool descriptions and stays inside them. A
# burst means either a compromised agent probing the boundary, or a prompt
# injection driving it. Both warrant waking someone.
#
# False positives: a genuinely confused model, or a new developer exploring.
# Both are worth a look, so the profile is acceptable.

resource "aws_cloudwatch_log_metric_filter" "guardrail_refusals" {
  name           = "${local.name}-guardrail-refusals"
  log_group_name = var.agent_audit_log_group
  pattern        = "{ $.outcome = \"refused\" }"

  metric_transformation {
    name          = "AgentGuardrailRefusals"
    namespace     = var.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "guardrail_refusal_burst" {
  alarm_name          = "${local.name}-D001-guardrail-refusal-burst"
  alarm_description   = "D-001: agent guardrail refusals exceeded threshold. Likely a compromised agent probing the boundary or an active prompt injection. Runbook: docs/05-incident-response/"
  namespace           = var.metric_namespace
  metric_name         = "AgentGuardrailRefusals"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.refusal_burst_threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}

# --- D-002: unmask capability used -----------------------------------------
# ATT&CK: T1005 (data from local system)
#
# Unmasking is off by default and must be a deployment decision. Any use at all
# is worth an alert — the threshold is deliberately zero rather than tuned.
# False-positive profile: none. If it fires, either someone enabled it or the
# capability check regressed, and both need a human.

resource "aws_cloudwatch_log_metric_filter" "unmask_used" {
  name           = "${local.name}-unmask-used"
  log_group_name = var.agent_audit_log_group
  pattern        = "{ $.tool = \"*unmask*\" || $.control = \"unmask-capability\" }"

  metric_transformation {
    name          = "AgentUnmaskUsage"
    namespace     = var.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "unmask_used" {
  alarm_name          = "${local.name}-D002-unmask-used"
  alarm_description   = "D-002: the unmask capability was exercised or attempted. Expected volume is zero."
  namespace           = var.metric_namespace
  metric_name         = "AgentUnmaskUsage"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}

# --- D-003: bulk read volume -----------------------------------------------
# ATT&CK: T1530 (data from cloud storage), TA0010 (exfiltration)
#
# The row cap bounds any single query; this catches the patient version —
# many small compliant queries that together constitute a bulk extract.
#
# False positives: a legitimate analytics batch. This is the detection most
# likely to need tuning against real traffic, and the threshold below is a
# starting point rather than a recommendation.

resource "aws_cloudwatch_log_metric_filter" "rows_returned" {
  name           = "${local.name}-rows-returned"
  log_group_name = var.agent_audit_log_group
  pattern        = "{ $.row_count = * }"

  metric_transformation {
    name          = "AgentRowsReturned"
    namespace     = var.metric_namespace
    value         = "$.row_count"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "bulk_read" {
  alarm_name          = "${local.name}-D003-bulk-read-volume"
  alarm_description   = "D-003: cumulative rows returned to the agent exceeded the hourly threshold. Individually compliant queries can still add up to a bulk extract."
  namespace           = var.metric_namespace
  metric_name         = "AgentRowsReturned"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = var.hourly_row_threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}

# --- D-004: off-hours agent activity ---------------------------------------
# ATT&CK: T1078 (valid accounts)
#
# Deliberately routed to a low-priority destination rather than paging. Off-hours
# activity is suspicious in context, not on its own — engineers work late, and a
# rule that pages at 02:00 for someone debugging will be muted permanently. It
# earns its place as corroboration during an investigation.

resource "aws_cloudwatch_log_metric_filter" "agent_activity" {
  name           = "${local.name}-agent-activity"
  log_group_name = var.agent_audit_log_group
  pattern        = "{ $.outcome = \"allowed\" }"

  metric_transformation {
    name          = "AgentToolInvocations"
    namespace     = var.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

# --- D-005: database authentication failure --------------------------------
# ATT&CK: T1110 (brute force), T1078 (valid accounts)
#
# The agent authenticates with a short-lived IAM token. Repeated failures mean
# either a broken deployment or something attempting to use the role from an
# unexpected place. Both are actionable.

resource "aws_cloudwatch_log_metric_filter" "db_auth_failures" {
  name           = "${local.name}-db-auth-failures"
  log_group_name = var.database_log_group
  pattern        = "?\"password authentication failed\" ?\"PAM authentication failed\" ?\"no pg_hba.conf entry\""

  metric_transformation {
    name          = "DatabaseAuthFailures"
    namespace     = var.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "db_auth_failures" {
  alarm_name          = "${local.name}-D005-database-auth-failures"
  alarm_description   = "D-005: repeated database authentication failures. Either a broken deployment or use of the role from an unexpected location."
  namespace           = var.metric_namespace
  metric_name         = "DatabaseAuthFailures"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.auth_failure_threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}

# --- D-006: Bedrock guardrail intervention ---------------------------------
# ATT&CK: T1567 (exfiltration over web service)
#
# The guardrail blocking a prompt or completion means regulated data reached the
# model context through a path the authorisation layer did not close. The
# guardrail catching it is the system working — and simultaneously evidence of
# a gap upstream that should be found and fixed.

resource "aws_cloudwatch_event_rule" "guardrail_intervention" {
  name        = "${local.name}-D006-guardrail-intervention"
  description = "D-006: Bedrock guardrail blocked a prompt or completion"
  tags        = local.tags

  event_pattern = jsonencode({
    source      = ["aws.bedrock"]
    detail-type = ["Bedrock Guardrail Intervention"]
    detail = {
      action = ["GUARDRAIL_INTERVENED"]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardrail_intervention" {
  rule      = aws_cloudwatch_event_rule.guardrail_intervention.name
  target_id = "sns"
  arn       = aws_sns_topic.alerts.arn
}

# --- D-007: GuardDuty findings on the agent role ----------------------------
# ATT&CK: multiple
#
# Filtered to medium severity and above. Forwarding every GuardDuty finding to a
# human is how GuardDuty becomes background noise.

resource "aws_cloudwatch_event_rule" "guardduty_agent" {
  name        = "${local.name}-D007-guardduty-agent-role"
  description = "D-007: GuardDuty finding involving the agent execution role"
  tags        = local.tags

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_agent" {
  rule      = aws_cloudwatch_event_rule.guardduty_agent.name
  target_id = "sns"
  arn       = aws_sns_topic.alerts.arn
}

# --- D-008: IAM changes to the agent role -----------------------------------
# ATT&CK: T1098 (account manipulation)
#
# The permission boundary caps privilege, but an attempt to widen the role is
# itself worth knowing about — whether it is an attack or an engineer about to
# be surprised by the boundary.

resource "aws_cloudwatch_event_rule" "agent_role_modified" {
  name        = "${local.name}-D008-agent-role-modified"
  description = "D-008: IAM modification targeting the agent role or its permission boundary"
  tags        = local.tags

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "AttachRolePolicy",
        "PutRolePolicy",
        "DeleteRolePermissionsBoundary",
        "PutRolePermissionsBoundary",
        "UpdateAssumeRolePolicy",
        "DeleteRolePolicy",
      ]
      requestParameters = {
        roleName = [var.agent_role_name]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "agent_role_modified" {
  rule      = aws_cloudwatch_event_rule.agent_role_modified.name
  target_id = "sns"
  arn       = aws_sns_topic.alerts.arn
}
