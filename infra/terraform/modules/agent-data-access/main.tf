# The IAM identity the MCP server runs as.
#
# This is where "least privilege and zero trust" stops being a slogan. Three
# properties are enforced, and each closes a failure mode I have actually seen:
#
#   1. A PERMISSION BOUNDARY caps the role's maximum privilege regardless of
#      what policy anyone later attaches. Without it, "just add S3 read for the
#      new feature" is one merged PR away, and the role drifts wider every
#      quarter with nobody making a decision.
#
#   2. rds-db:connect is scoped to a specific DATABASE USER on a specific
#      CLUSTER RESOURCE ID. Not the cluster name — the resource ID. A name can
#      be recreated by someone with RDS write access; the resource ID cannot.
#      The IAM policy therefore names `mcp_readonly` and no other role, so an
#      agent that somehow obtains a password for a wider account still cannot
#      use IAM auth to reach it.
#
#   3. EXPLICIT DENIES for the paths that would undo the design. Deny wins over
#      any Allow, including one attached later by someone who did not read this
#      file.
#
# The masking salt is deliberately NOT readable by this role. That is the whole
# reason masking works: reading the masked view must not imply the ability to
# reverse it. See docs/01-threat-model.md, attack branch 2a.

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
  name = "${var.name_prefix}-agent-data-access"

  tags = merge(var.tags, {
    Component = "agent-data-access"
    ManagedBy = "terraform"
  })

  db_connect_resource = "arn:aws:rds-db:${var.region}:${var.account_id}:dbuser:${var.cluster_resource_id}/${var.database_username}"
}

# --- Permission boundary ----------------------------------------------------

data "aws_iam_policy_document" "boundary" {
  # checkov:skip=CKV_AWS_111:False positive by category. This document is a PERMISSION BOUNDARY, not a grant. A boundary defines a privilege CEILING and must enumerate actions against "*" — it grants nothing on its own; a principal receives access only where an attached policy AND this boundary both allow it. Constraining the resources here would narrow the ceiling in ways that silently break the role while making it no safer.
  # checkov:skip=CKV_AWS_107:As above — no credential exposure is granted; the boundary is intersected with the attached policy.
  # checkov:skip=CKV_AWS_109:The iam:* entry is inside a DENY statement. Checkov reads the action list without the effect. A deny on permissions management is the opposite of the risk this check describes.
  # checkov:skip=CKV_AWS_356:Boundaries are inherently unscoped by resource; see the first note.
  # The ceiling. Anything not listed here is unreachable by this role even if
  # explicitly allowed by an attached policy.
  statement {
    sid    = "MaximumPermittedActions"
    effect = "Allow"
    actions = [
      "rds-db:connect",
      "secretsmanager:GetSecretValue",
      "kms:Decrypt",
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream",
      "bedrock:ApplyGuardrail",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
    ]
    resources = ["*"]
  }

  # An agent that can rewrite IAM can grant itself anything. This is the single
  # most important deny in the file.
  statement {
    sid    = "DenyIdentitySelfModification"
    effect = "Deny"
    actions = [
      "iam:*",
      "sts:AssumeRole",
      "organizations:*",
      "account:*",
    ]
    resources = ["*"]
  }

  # Disabling the audit trail is the first move of anyone who intends to do
  # something they do not want recorded.
  statement {
    sid    = "DenyDisablingObservability"
    effect = "Deny"
    actions = [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "cloudtrail:UpdateTrail",
      "guardduty:DeleteDetector",
      "guardduty:UpdateDetector",
      "securityhub:DisableSecurityHub",
      "logs:DeleteLogGroup",
      "logs:DeleteLogStream",
      "logs:PutRetentionPolicy",
    ]
    resources = ["*"]
  }

  # The agent reads data; it must never be able to change the database's shape,
  # snapshot it, or move it somewhere with weaker controls. Snapshot creation is
  # a full-fidelity copy of Art. 9 data and is an exfiltration path that no
  # in-database control can see.
  statement {
    sid    = "DenyDataPlaneMutation"
    effect = "Deny"
    actions = [
      "rds:CreateDBSnapshot",
      "rds:CreateDBClusterSnapshot",
      "rds:CopyDBSnapshot",
      "rds:CopyDBClusterSnapshot",
      "rds:RestoreDBClusterFromSnapshot",
      "rds:ModifyDBCluster",
      "rds:ModifyDBInstance",
      "rds:DeleteDBCluster",
      "rds:DeleteDBInstance",
      "rds:ModifyDBClusterParameterGroup",
    ]
    resources = ["*"]
  }

  # Bulk data services the agent has no business touching. Reaching any of them
  # would mean data leaving the controlled path entirely.
  statement {
    sid    = "DenyBulkDataServices"
    effect = "Deny"
    actions = [
      "s3:PutObject",
      "s3:DeleteObject",
      "dynamodb:*",
      "athena:*",
      "glue:*",
      "datapipeline:*",
      "dms:*",
    ]
    resources = ["*"]
  }

  # Belt and braces with the omission of the salt from the read policy below:
  # even a future Allow cannot reach it.
  statement {
    sid       = "DenyMaskSaltAccess"
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.mask_salt_secret_arn]
  }
}

resource "aws_iam_policy" "boundary" {
  name        = "${local.name}-boundary"
  description = "Maximum privilege ceiling for the MCP agent role"
  policy      = data.aws_iam_policy_document.boundary.json
  tags        = local.tags
}

# --- Execution role ---------------------------------------------------------

data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = var.trusted_service_principals
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    # Confused-deputy protection: the role may only be assumed on behalf of the
    # specific workloads named, not any function in the account.
    dynamic "condition" {
      for_each = length(var.trusted_source_arns) > 0 ? [1] : []
      content {
        test     = "ArnLike"
        variable = "aws:SourceArn"
        values   = var.trusted_source_arns
      }
    }
  }
}

resource "aws_iam_role" "agent" {
  name                 = local.name
  description          = "MCP server execution role — read-only access to masked pharmacy data"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  permissions_boundary = aws_iam_policy.boundary.arn
  max_session_duration = var.max_session_duration
  tags                 = local.tags
}

# --- Attached policy --------------------------------------------------------

data "aws_iam_policy_document" "agent" {
  # IAM database authentication. Scoped to one database user on one cluster
  # resource ID — see the header comment for why the resource ID and not the
  # cluster name.
  statement {
    sid       = "ConnectAsReadOnlyDatabaseUser"
    effect    = "Allow"
    actions   = ["rds-db:connect"]
    resources = [local.db_connect_resource]
  }

  # Deliberately NOT including var.mask_salt_secret_arn. Its absence here is the
  # control; the deny in the boundary is the backstop.
  dynamic "statement" {
    for_each = length(var.readable_secret_arns) > 0 ? [1] : []
    content {
      sid       = "ReadOperationalSecrets"
      effect    = "Allow"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = var.readable_secret_arns
    }
  }

  dynamic "statement" {
    for_each = length(var.readable_kms_key_arns) > 0 ? [1] : []
    content {
      sid       = "DecryptWithNamedKeys"
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = var.readable_kms_key_arns
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["secretsmanager.${var.region}.amazonaws.com"]
      }
    }
  }

  # Model invocation is permitted only with the guardrail attached. This is the
  # IAM-side half of the VPC endpoint policy in modules/bedrock-guardrails: one
  # closes the network path, the other closes the identity path, so neither is
  # a single point of failure.
  dynamic "statement" {
    for_each = var.bedrock_guardrail_id != null ? [1] : []
    content {
      sid       = "InvokeModelWithGuardrailOnly"
      effect    = "Allow"
      actions   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
      resources = var.allowed_model_arns
      condition {
        test     = "StringEquals"
        variable = "bedrock:GuardrailIdentifier"
        values   = [var.bedrock_guardrail_id]
      }
    }
  }

  statement {
    sid    = "WriteOwnLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.log_group_name}:*"]
  }
}

resource "aws_iam_policy" "agent" {
  name        = "${local.name}-policy"
  description = "Read-only data access for the MCP agent"
  policy      = data.aws_iam_policy_document.agent.json
  tags        = local.tags
}

resource "aws_iam_role_policy_attachment" "agent" {
  role       = aws_iam_role.agent.name
  policy_arn = aws_iam_policy.agent.arn
}
