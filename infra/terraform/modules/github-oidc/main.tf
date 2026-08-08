# GitHub Actions -> AWS with no static credentials.
#
# This module deletes an entire class of incident. The most common cloud breach
# path is a long-lived AWS access key in a CI secret store: it never expires, it
# is copied into forks and logs, and its compromise is silent. OIDC replaces it
# with a token minted per workflow run, valid for the life of that run, bound to
# a specific repository and ref.
#
# The subject condition is the whole control, and it is the thing people get
# wrong. A trust policy scoped only to `repo:org/*` lets ANY workflow in ANY
# branch of ANY repo in that organisation assume the role — including a branch
# an attacker opened via a pull request. The conditions below pin repository,
# ref, AND environment, and the module refuses to build a wildcard-only subject.

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
  name = "${var.name_prefix}-github-oidc"

  tags = merge(var.tags, {
    Component = "github-oidc"
    ManagedBy = "terraform"
  })

  # Build one `sub` claim per allowed (repo, ref) pair. Explicit subjects rather
  # than a single wildcard: every entry is a decision a reviewer can question.
  subjects = flatten([
    for repo in var.allowed_repositories : [
      for ref in var.allowed_refs :
      "repo:${var.github_organisation}/${repo}:ref:${ref}"
    ]
  ])

  # Deployment-environment subjects, used when a job targets a GitHub
  # Environment with required reviewers. This is how a human approval gate
  # becomes an AWS authorisation condition rather than a GitHub-only setting.
  environment_subjects = [
    for pair in var.allowed_environments :
    "repo:${var.github_organisation}/${pair.repository}:environment:${pair.environment}"
  ]

  all_subjects = concat(local.subjects, local.environment_subjects)
}

# The OIDC provider is account-wide and should exist once. Set
# create_oidc_provider = false when another stack already manages it.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]

  # Thumbprints are no longer used for validation by AWS for this provider —
  # STS verifies GitHub's certificate against its trust store — but the field is
  # still required by the API. Left as GitHub's published value rather than a
  # placeholder, so it is obvious what it is if AWS reinstates the check.
  thumbprint_list = var.thumbprints

  tags = local.tags
}

locals {
  provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : var.existing_oidc_provider_arn
}

data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.provider_arn]
    }

    # Audience. Without this a token minted for a different audience could be
    # replayed here.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Subject. StringLike rather than StringEquals only because refs may contain
    # a trailing wildcard (refs/heads/release/*); the variable-level validation
    # in variables.tf refuses a bare "*" so this cannot degrade into "any repo".
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.all_subjects
    }

    # Belt and braces: even if a subject were mis-specified, the token must
    # still come from this organisation.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:repository_owner"
      values   = [var.github_organisation]
    }
  }
}

resource "aws_iam_role" "github" {
  name                 = local.name
  description          = "GitHub Actions OIDC role — no static credentials exist for this identity"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  permissions_boundary = var.permissions_boundary_arn

  # Short by default. A CI job that needs more than an hour of AWS access is
  # usually a job that should be split, and a long session is a longer window
  # for a leaked token.
  max_session_duration = var.max_session_duration

  tags = local.tags
}

# Deploy permissions are supplied by the caller rather than assumed here: what
# a pipeline may do is a per-pipeline decision, and a module that ships a
# default deploy policy encourages copying one that is too wide.
resource "aws_iam_role_policy_attachment" "supplied" {
  for_each = toset(var.policy_arns)

  role       = aws_iam_role.github.name
  policy_arn = each.value
}

# Guardrails that apply regardless of what the caller attaches.
data "aws_iam_policy_document" "guardrails" {
  statement {
    sid    = "DenyIdentitySelfModification"
    effect = "Deny"
    actions = [
      "iam:CreateUser",
      "iam:CreateAccessKey",
      "iam:AttachUserPolicy",
      "iam:PutUserPolicy",
      "iam:UpdateAssumeRolePolicy",
      "iam:DeleteRolePermissionsBoundary",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyDisablingObservability"
    effect = "Deny"
    actions = [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "guardduty:DeleteDetector",
      "securityhub:DisableSecurityHub",
      "config:DeleteConfigurationRecorder",
    ]
    resources = ["*"]
  }

  # A pipeline that can read production secrets can print them to a build log,
  # and build logs are readable by anyone with repository access.
  dynamic "statement" {
    for_each = length(var.denied_secret_arns) > 0 ? [1] : []
    content {
      sid       = "DenyProductionSecretReads"
      effect    = "Deny"
      actions   = ["secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters"]
      resources = var.denied_secret_arns
    }
  }
}

resource "aws_iam_role_policy" "guardrails" {
  name   = "ci-guardrails"
  role   = aws_iam_role.github.id
  policy = data.aws_iam_policy_document.guardrails.json
}
