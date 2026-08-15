# Organization guardrails: OUs, service control policies, resource control
# policies, and delegated administration.
#
# Written against what platform/00-discovery actually found in this
# organization, not against a generic template. Every resource here traces to a
# finding in platform/00-discovery/report/assessment.md, and the mapping is in
# README.md.
#
# The three ideas worth reading before the code:
#
#   1. AN SCP ATTACHED TO AN EMPTY OU CONSTRAINS NOTHING. Discovery found three
#      custom SCPs attached only to OUs containing no accounts (ORG-002). They
#      are not weak controls; they are absent controls that look present on a
#      console screenshot. `terraform plan` cannot detect that, so this module
#      ships a check (checks.tf) that does.
#
#   2. SCPs NEVER APPLY TO THE MANAGEMENT ACCOUNT. Four policies here are
#      attached at the root, and none of them constrains the account that can
#      create accounts, detach policies and close the organization (ORG-003).
#      No SCP can fix that — it is a property of Organizations. The treatment is
#      to hold nothing in the management account worth reaching, and to rely on
#      controls that do apply to it: root hardware MFA, centralised root
#      credential management, and a trail it cannot stop.
#
#   3. RCPs AND SCPs ANSWER DIFFERENT QUESTIONS. An SCP bounds what a principal
#      in your organization may do. An RCP bounds who may be granted access to
#      your resources — including by a resource policy written by someone whose
#      principals you do not control. Discovery found RCPs enabled and unused
#      (ORG-004), which is the common case: the feature is newer, and an
#      organization that has SCPs usually assumes it is covered.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60"
    }
  }
}

data "aws_organizations_organization" "this" {}

locals {
  # The security-tooling account administers the security services. Falls back
  # to the management account only so `terraform validate` works before one
  # exists — and checks.tf fails the plan if it is still unset, because
  # administering security services from the management account is the
  # arrangement ORG-001 exists to end.
  security_account_id = coalesce(
    var.security_tooling_account_id,
    data.aws_organizations_organization.this.master_account_id,
  )

  tags = merge(var.tags, {
    Component = "organization-guardrails"
    ManagedBy = "terraform"
  })
}

# ---------------------------------------------------------------------------
# Delegated administration — ORG-001
# ---------------------------------------------------------------------------

# Discovery found zero delegated administrators, so GuardDuty, Security Hub,
# Config, Access Analyzer, Inspector, Macie and Detective are all administered
# from the management account. AWS SRA separates these for a reason: the
# management account cannot be constrained by SCPs, so every additional
# capability placed there is capability that nothing bounds.
resource "aws_organizations_delegated_administrator" "security" {
  for_each = var.delegate_security_services ? toset(var.delegated_services) : []

  account_id        = local.security_account_id
  service_principal = each.value
}

# ---------------------------------------------------------------------------
# Service control policies
# ---------------------------------------------------------------------------

resource "aws_organizations_policy" "scp" {
  for_each = var.service_control_policies

  name        = each.key
  description = each.value.description
  type        = "SERVICE_CONTROL_POLICY"
  content = templatefile(
    "${path.module}/policies/scp/${each.value.document}",
    {
      # Every deny that protects a security control carries an exemption for
      # one named break-glass role. A guardrail with no exit is a guardrail
      # that gets removed the first time it is genuinely in the way — and it
      # gets removed under pressure, by someone who will not put it back.
      #
      # The role is named, not a wildcard: the exemption is auditable, and its
      # use is a CloudTrail event worth alerting on.
      SecurityBreakGlassRole = var.break_glass_role_name
    }
  )

  tags = merge(local.tags, {
    # What this policy would break if applied to the wrong target. Carried as a
    # tag so it is visible in the console to whoever is deciding whether to
    # detach it at 2am, not only in a file they would have to go and find.
    BreaksIfMisapplied = each.value.breaks
  })
}

resource "aws_organizations_policy_attachment" "scp" {
  # One attachment per (policy, target) pair.
  for_each = {
    for pair in flatten([
      for name, policy in var.service_control_policies : [
        for target in policy.targets : {
          key       = "${name}:${target}"
          policy    = name
          target_id = target
        }
      ]
    ]) : pair.key => pair
  }

  policy_id = aws_organizations_policy.scp[each.value.policy].id
  target_id = each.value.target_id
}

# ---------------------------------------------------------------------------
# Resource control policies — ORG-004
# ---------------------------------------------------------------------------

# RCPs were enabled on this organization and carried only the AWS-managed
# RCPFullAWSAccess, which allows everything. These close the confused-deputy
# path: a resource policy on a bucket, key or queue cannot grant access to a
# principal outside the organization, whoever writes it.
resource "aws_organizations_policy" "rcp" {
  for_each = var.resource_control_policies

  name        = each.key
  description = each.value.description
  type        = "RESOURCE_CONTROL_POLICY"
  content = templatefile(
    "${path.module}/policies/rcp/${each.value.document}",
    {
      organization_id = data.aws_organizations_organization.this.id
      # Service principals that legitimately reach resources from outside the
      # organization's principal set. Without these exemptions an RCP breaks
      # CloudTrail delivery, Config delivery and cross-service log writes —
      # which is how an RCP rollout gets reverted and never retried.
      service_principal_exemptions = jsonencode(var.rcp_service_exemptions)
    }
  )

  tags = merge(local.tags, {
    BreaksIfMisapplied = each.value.breaks
  })
}

resource "aws_organizations_policy_attachment" "rcp" {
  for_each = {
    for pair in flatten([
      for name, policy in var.resource_control_policies : [
        for target in policy.targets : {
          key       = "${name}:${target}"
          policy    = name
          target_id = target
        }
      ]
    ]) : pair.key => pair
  }

  policy_id = aws_organizations_policy.rcp[each.value.policy].id
  target_id = each.value.target_id
}
