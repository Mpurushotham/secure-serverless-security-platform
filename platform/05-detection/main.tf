# Organization-wide detection coverage.
#
# Applied from the delegated security-tooling account, not the management
# account — that separation is finding ORG-001 and platform/01-organization
# makes it possible.
#
# Every resource here answers a specific finding, and the through-line is that
# **coverage is a fraction, never a boolean**:
#
#   * GuardDuty was enabled in both scanned regions, with nine protection plans
#     off in one and four off in the other (DET-002). "GuardDuty is on" was true
#     and told nobody anything useful. Auto-enable plus an explicit feature list
#     is what makes the answer the same in every region and every new account.
#
#   * AWS Config had 343 rules defined in one region and no recorder running in
#     either (LOG-004). Rules without a recorder evaluate nothing and report
#     nothing — the most expensive way to have no control at all. The recorder
#     is therefore created first and the rules depend on it.
#
#   * Access Analyzer had only an unused-access analyzer (DET-005). That one
#     finds privilege nobody exercises; the external-access analyzer finds
#     resources reachable from outside the organization. They are different
#     analyzers and most estates run only one of them.
#
# Region handling: these are regional services, so a single provider covers one
# region. Multi-region is the caller's job, via provider aliases or a stack per
# region — deliberately not hidden inside the module, because a module that
# quietly loops over regions makes the blast radius of an apply invisible.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  tags = merge(var.tags, {
    Component = "detection-coverage"
    ManagedBy = "terraform"
  })
}

# ---------------------------------------------------------------------------
# GuardDuty — DET-001, DET-002
# ---------------------------------------------------------------------------

resource "aws_guardduty_detector" "this" {
  enable = true
  # FIFTEEN_MINUTES rather than the six-hour default. Detection latency is part
  # of the control: a finding that arrives six hours after the credential was
  # used is a post-mortem input, not a response trigger.
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = local.tags
}

resource "aws_guardduty_detector_feature" "this" {
  for_each = var.guardduty_features

  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  status      = each.value ? "ENABLED" : "DISABLED"
}

# New accounts inherit the configuration. Without this, coverage is correct on
# the day it is applied and wrong the first time somebody creates an account.
resource "aws_guardduty_organization_configuration" "this" {
  count = var.is_delegated_administrator ? 1 : 0

  detector_id                      = aws_guardduty_detector.this.id
  auto_enable_organization_members = "ALL"
}

resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each = var.is_delegated_administrator ? var.guardduty_features : {}

  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  auto_enable = each.value ? "ALL" : "NONE"

  depends_on = [aws_guardduty_organization_configuration.this]
}

# ---------------------------------------------------------------------------
# Security Hub — DET-003, DET-004
# ---------------------------------------------------------------------------

resource "aws_securityhub_account" "this" {
  enable_default_standards = false
  # New controls in an already-enabled standard are switched on automatically.
  # The alternative is a standard that silently stops covering the things AWS
  # added after the day it was enabled.
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
}

resource "aws_securityhub_organization_admin_account" "this" {
  count = var.register_securityhub_admin ? 1 : 0

  admin_account_id = data.aws_caller_identity.current.account_id
}

resource "aws_securityhub_organization_configuration" "this" {
  count = var.is_delegated_administrator ? 1 : 0

  auto_enable           = true
  auto_enable_standards = "NONE"

  organization_configuration {
    configuration_type = "CENTRAL"
  }

  depends_on = [aws_securityhub_account.this]
}

# CIS v3.0.0, not the v1.2.0 discovery found enabled (DET-004). v1.2.0 predates
# most of the services in a modern serverless estate, so passing it says
# little about the workloads actually running.
resource "aws_securityhub_standards_subscription" "enabled" {
  for_each = var.security_standards

  standards_arn = replace(
    each.value,
    "$${region}",
    data.aws_region.current.region,
  )

  depends_on = [aws_securityhub_account.this]
}

data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# AWS Config — LOG-004
# ---------------------------------------------------------------------------

resource "aws_iam_role" "config" {
  name               = "${var.name_prefix}-config-recorder"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "config_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_delivery" {
  name   = "config-delivery"
  role   = aws_iam_role.config.id
  policy = data.aws_iam_policy_document.config_delivery.json
}

data "aws_iam_policy_document" "config_delivery" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${var.config_bucket_arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [var.config_bucket_arn]
  }
}

resource "aws_config_configuration_recorder" "this" {
  # checkov:skip=CKV2_AWS_48:Deliberate design choice, and correct at organization scale. all_supported is true; the check also wants include_global_resource_types true, but global resources (IAM users, roles, policies) are identical in every region. Recording them everywhere means paying N times to record the same entities and receiving N copies of every IAM finding. Exactly one region should set record_global_resource_types = true, which the variable documents. Setting it true here would make the module wrong wherever it is used more than once.
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported = true
    # Global resource types are recorded in one region only, or every region
    # records the same IAM entities and Config bills for each copy.
    include_global_resource_types = var.record_global_resource_types
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = var.config_bucket_name
  s3_key_prefix  = "config"
  s3_kms_key_arn = var.config_kms_key_arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.this]
}

# The resource that was missing. A recorder that exists but is not recording is
# the state discovery found, and it is indistinguishable from a healthy one on
# any dashboard that checks whether Config is "enabled".
resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

resource "aws_config_conformance_pack" "operational_best_practices" {
  count = var.conformance_pack_template_uri == null ? 0 : 1

  name            = "${var.name_prefix}-obp"
  template_s3_uri = var.conformance_pack_template_uri

  # Rules are created by the pack and evaluate nothing until the recorder is
  # running. Ordering it explicitly is what stops a fresh apply reproducing
  # LOG-004 on day one.
  depends_on = [aws_config_configuration_recorder_status.this]
}

# ---------------------------------------------------------------------------
# IAM Access Analyzer — DET-005, DET-006
# ---------------------------------------------------------------------------

# The analyzer that was missing. Finds resources — buckets, keys, roles, queues
# — reachable by a principal outside the zone of trust.
resource "aws_accessanalyzer_analyzer" "external" {
  analyzer_name = "${var.name_prefix}-external-access"
  type          = var.is_delegated_administrator ? "ORGANIZATION" : "ACCOUNT"
  tags          = local.tags
}

# The one already present. Finds privilege granted and never exercised, which
# is where least privilege is actually recovered rather than designed.
resource "aws_accessanalyzer_analyzer" "unused" {
  analyzer_name = "${var.name_prefix}-unused-access"
  type          = var.is_delegated_administrator ? "ORGANIZATION_UNUSED_ACCESS" : "ACCOUNT_UNUSED_ACCESS"

  configuration {
    unused_access {
      unused_access_age = var.unused_access_age_days
    }
  }

  tags = local.tags
}
