variable "security_tooling_account_id" {
  description = <<-EOT
    Account that administers GuardDuty, Security Hub, Config, Access Analyzer,
    Inspector, Macie and Detective. Must not be the management account — see
    checks.tf. Null is permitted only so `terraform validate` runs before the
    account exists.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.security_tooling_account_id == null || can(regex("^[0-9]{12}$", var.security_tooling_account_id))
    error_message = "security_tooling_account_id must be a 12-digit AWS account ID."
  }
}

variable "delegate_security_services" {
  description = "Whether to delegate security service administration at all."
  type        = bool
  default     = true
}

variable "delegated_services" {
  description = <<-EOT
    Service principals to delegate. The default set is what discovery reported
    as having no delegated administrator (finding ORG-001).

    Order matters on first apply: Security Hub expects GuardDuty and Config to
    be delegated to the same account, and delegating one service to account A
    and another to account B produces findings that never aggregate.
  EOT
  type        = list(string)
  default = [
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "config.amazonaws.com",
    "access-analyzer.amazonaws.com",
    "inspector2.amazonaws.com",
    "macie.amazonaws.com",
    "detective.amazonaws.com",
    "auditmanager.amazonaws.com",
  ]
}

variable "service_control_policies" {
  description = <<-EOT
    SCPs to manage, keyed by policy name.

    `breaks` is required and is not documentation for its own sake: an SCP that
    nobody can describe the blast radius of gets detached under incident
    pressure and never reattached. Writing it down at authoring time is the only
    moment anyone actually knows.

    `targets` are root, OU or account IDs. An empty list is refused by checks.tf.
  EOT
  type = map(object({
    description = string
    document    = string
    breaks      = string
    targets     = list(string)
  }))
  default = {}
}

variable "resource_control_policies" {
  description = "RCPs to manage, keyed by policy name. Same shape as SCPs."
  type = map(object({
    description = string
    document    = string
    breaks      = string
    targets     = list(string)
  }))
  default = {}
}

variable "rcp_service_exemptions" {
  description = <<-EOT
    Service principals exempted from the RCP organization-boundary condition.

    These are AWS services that write to your resources on your behalf using
    their own service principal rather than a principal in your organization.
    Without the exemption, an RCP silently breaks CloudTrail delivery, Config
    delivery and access logging — which is the usual reason an RCP rollout is
    reverted within a day and never attempted again.
  EOT
  type        = list(string)
  default = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "delivery.logs.amazonaws.com",
    "logging.s3.amazonaws.com",
  ]
}

variable "break_glass_role_name" {
  description = <<-EOT
    Role name exempted from the denies that protect security controls.

    Named rather than wildcarded so the exemption is auditable and its use is a
    CloudTrail event worth alerting on. A guardrail with no exit gets removed
    the first time it is genuinely in the way — under pressure, by someone who
    will not put it back.
  EOT
  type        = string
  default     = "SecurityBreakGlass"

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.break_glass_role_name))
    error_message = "break_glass_role_name must be a valid IAM role name."
  }
}

variable "acknowledge_management_account_exemption" {
  description = <<-EOT
    Set true to acknowledge that SCPs attached at the organization root do not
    apply to the management account (finding ORG-003), and that the treatment is
    operational — run no workloads there — rather than another policy.
  EOT
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to every policy this module creates."
  type        = map(string)
  default     = {}
}
