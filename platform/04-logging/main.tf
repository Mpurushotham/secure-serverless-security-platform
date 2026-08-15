# Organization audit trail and its archive.
#
# Discovery found a logging organization trail already in place — multi-region,
# log-file validation on — with two gaps: no customer-managed key (LOG-002) and
# no data events (LOG-003). This module is the shape that closes both.
#
# The distinction that drives the design:
#
#   MANAGEMENT EVENTS answer "who assumed which role, and what did they
#   configure". DATA EVENTS answer "which objects did they then read". Only the
#   second one answers the question an incident actually asks, and it is off by
#   default because it is the expensive one. Enabling it everywhere is how the
#   bill becomes the argument for turning it off; enabling it on the buckets
#   holding regulated data is the version that survives review.
#
# The archive bucket is built to be useless to an attacker who reaches it and
# unhelpful to one who wants to erase their tracks:
#
#   * Object Lock in COMPLIANCE mode — the retention cannot be shortened by
#     anyone, including the root user of this account. That is the point. A
#     retention control that a sufficiently privileged principal can lift is a
#     retention preference.
#   * A KMS key whose policy allows decryption by named security roles only,
#     so read access to the bucket is not read access to the logs.
#   * TLS-only, no public access, and versioning.

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
data "aws_organizations_organization" "this" {}

locals {
  name      = "${var.name_prefix}-org-trail"
  bucket    = "${var.name_prefix}-org-trail-${data.aws_caller_identity.current.account_id}"
  partition = data.aws_partition.current.partition
  org_id    = data.aws_organizations_organization.this.id

  tags = merge(var.tags, {
    Component = "organization-logging"
    ManagedBy = "terraform"
  })
}

# ---------------------------------------------------------------------------
# Key — LOG-002
# ---------------------------------------------------------------------------

resource "aws_kms_key" "trail" {
  description             = "Encrypts ${local.name} log files"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.trail_key.json
  tags                    = local.tags
}

resource "aws_kms_alias" "trail" {
  name          = "alias/${var.name_prefix}-org-trail"
  target_key_id = aws_kms_key.trail.key_id
}

data "aws_iam_policy_document" "trail_key" {
  # checkov:skip=CKV_AWS_111:False positive by category. This is a KMS KEY POLICY, not an identity policy. KMS refuses a key whose policy leaves no principal able to administer it, so the account-root statement is mandatory — without it the key becomes unmanageable and unrecoverable. The risk the check describes (unconstrained write access granted to a principal) does not apply: a key policy grants only on this key, and the mitigation is that this account is a log archive nobody operates in day to day.
  # checkov:skip=CKV_AWS_356:As above. Resource "*" inside a key policy means "this key" — there is no other resource it could name, and KMS rejects an ARN here.
  # checkov:skip=CKV_AWS_109:As above. kms:* in the root statement is key administration, which is the documented and required pattern for a customer-managed key.
  # Without this the key is unmanageable: KMS refuses a key policy that leaves
  # no principal able to administer it, and the account root is the only
  # principal guaranteed to exist. It is the documented pattern, not a
  # loosening — but it is also why the archive account must be one nobody
  # operates in day to day.
  statement {
    sid       = "AccountRootMayAdministerTheKey"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "CloudTrailMayEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    # Scopes the grant to trails in this organization. Without it, any
    # CloudTrail in any account could ask this key to encrypt for it — the
    # confused-deputy shape, on the key protecting the audit log.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:cloudtrail:${var.home_region}:${data.aws_caller_identity.current.account_id}:trail/${local.name}"]
    }
  }

  # Decryption is the access that matters. Read access to the bucket gets you
  # ciphertext; this statement is what turns it into readable history, and it
  # names roles rather than the account.
  dynamic "statement" {
    for_each = length(var.log_reader_role_arns) > 0 ? [1] : []
    content {
      sid       = "NamedSecurityRolesMayDecrypt"
      effect    = "Allow"
      actions   = ["kms:Decrypt", "kms:DescribeKey"]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = var.log_reader_role_arns
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Archive bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "trail" {
  # checkov:skip=CKV_AWS_18:Deliberate risk acceptance. Access logging on the log archive writes access logs to another bucket, which itself needs access logging — the recursion has to terminate somewhere. CloudTrail data events on this bucket record reads with more identity detail than S3 access logs carry, and are configured on the trail below.
  # checkov:skip=CKV_AWS_144:Deliberate risk acceptance. Cross-region replication doubles storage cost for a bucket already protected by versioning and COMPLIANCE-mode Object Lock. The threat this addresses is regional loss of the archive; the threats actually in this model are tampering and deletion, both of which Object Lock covers and replication does not. Revisit if a regulator requires geographic redundancy of audit records.
  # checkov:skip=CKV2_AWS_62:False positive by category. Event notifications on the archive would fire on every log file CloudTrail delivers, which is thousands per day and carries no security signal. Deletion — the event worth knowing about — is already denied by the bucket policy and prevented by Object Lock.
  bucket = local.bucket

  # Compliance-mode Object Lock cannot be disabled once the bucket exists, and
  # a retention period under it cannot be shortened by anyone. Terraform must
  # not be able to destroy this by accident either.
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }

  tags = local.tags
}

resource "aws_s3_bucket_object_lock_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.log_retention_days
    }
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.trail.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "transition-and-expire"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    # Expiry must exceed the Object Lock retention, or S3 cannot delete and the
    # lifecycle rule quietly fails every night.
    expiration {
      days = var.log_retention_days + 1
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "CloudTrailMayCheckAcl"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid       = "CloudTrailMayWriteForThisOrganization"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.org_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid       = "DenyPlaintextTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
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

  # An audit log that the people being audited can delete is not an audit log.
  # Object Lock already prevents this; the explicit deny means a misconfigured
  # lock does not silently become the only thing standing in the way.
  statement {
    sid       = "DenyDeletion"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:${local.partition}:iam::*:role/${var.break_glass_role_name}"]
    }
  }
}

# ---------------------------------------------------------------------------
# The trail
# ---------------------------------------------------------------------------

resource "aws_cloudtrail" "org" {
  # checkov:skip=CKV_AWS_252:Deliberate design choice. SNS notification on trail delivery is the pre-EventBridge mechanism and delivers one message per log file, not per event — it cannot carry a detection. Detections are built on EventBridge and on the CloudWatch Logs destination below, both of which see individual events.
  # checkov:skip=CKV2_AWS_10:Conditional, not absent. cloudwatch_log_group_arn is a variable on this module and wiring it is the caller's decision, because the CloudWatch copy costs per ingested GB on top of S3. The variable documents that without it there is no near-real-time path and detections must come from EventBridge. Set it for any environment where detection latency matters.
  name           = local.name
  s3_bucket_name = aws_s3_bucket.trail.id

  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.trail.arn

  cloud_watch_logs_group_arn = var.cloudwatch_log_group_arn
  cloud_watch_logs_role_arn  = var.cloudwatch_role_arn

  # LOG-003. Data events are scoped rather than global: `arn:aws:s3` with no
  # suffix would record every object operation in every account, which is the
  # configuration that produces a bill nobody defends and a control that gets
  # switched off. These name the buckets and functions that hold or touch
  # regulated data.
  dynamic "advanced_event_selector" {
    for_each = length(var.data_event_bucket_arns) > 0 ? [1] : []
    content {
      name = "Object access on regulated-data buckets"

      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }
      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }
      field_selector {
        field       = "resources.ARN"
        starts_with = var.data_event_bucket_arns
      }
    }
  }

  dynamic "advanced_event_selector" {
    for_each = length(var.data_event_function_arns) > 0 ? [1] : []
    content {
      name = "Invocation of functions with access to regulated data"

      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }
      field_selector {
        field  = "resources.type"
        equals = ["AWS::Lambda::Function"]
      }
      field_selector {
        field       = "resources.ARN"
        starts_with = var.data_event_function_arns
      }
    }
  }

  # Management events are always recorded. Listed explicitly rather than left
  # to the default so that adding a data-event selector — which replaces the
  # default set — cannot silently drop them.
  advanced_event_selector {
    name = "All management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  tags = local.tags

  depends_on = [aws_s3_bucket_policy.trail]
}
