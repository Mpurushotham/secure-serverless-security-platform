variable "name_prefix" {
  description = "Prefix for the resources this module creates."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,32}$", var.name_prefix))
    error_message = "name_prefix must be lowercase alphanumeric with hyphens, 2-33 characters."
  }
}

variable "is_delegated_administrator" {
  description = <<-EOT
    Whether this account is the delegated administrator for the organization.

    Controls whether organization-wide configuration is created and whether the
    Access Analyzer analyzers are ORGANIZATION or ACCOUNT scoped. Applying with
    this true from an account that has not been delegated fails at apply, which
    is the correct order: delegate in platform/01-organization first.
  EOT
  type        = bool
  default     = false
}

variable "register_securityhub_admin" {
  description = <<-EOT
    Whether to register this account as the Security Hub organization admin.

    Separate from is_delegated_administrator because registration is performed
    once, from the management account, while everything else here runs from the
    security account.
  EOT
  type        = bool
  default     = false
}

variable "guardduty_features" {
  description = <<-EOT
    Protection plans, and whether each is enabled.

    Every plan is listed explicitly, including the ones set to false. An omitted
    feature keeps whatever it happens to have, which is how discovery found nine
    plans off in one region and four off in another (finding DET-002) with
    nobody having decided either. A false here is a decision; an absence is not.
  EOT
  type        = map(bool)
  default = {
    S3_DATA_EVENTS         = true
    EKS_AUDIT_LOGS         = true
    EBS_MALWARE_PROTECTION = true
    RDS_LOGIN_EVENTS       = true
    LAMBDA_NETWORK_LOGS    = true
    RUNTIME_MONITORING     = true
    EKS_RUNTIME_MONITORING = false
  }
}

variable "security_standards" {
  description = <<-EOT
    Security Hub standards to enable, keyed by a short name.

    `$${region}` is substituted with the module's region. CIS is pinned to
    v3.0.0: discovery found v1.2.0 enabled (finding DET-004), which predates
    most services in a serverless estate, so passing it says little about the
    workloads actually running.
  EOT
  type        = map(string)
  default = {
    fsbp = "arn:aws:securityhub:$${region}::standards/aws-foundational-security-best-practices/v/1.0.0"
    cis3 = "arn:aws:securityhub:$${region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
  }
}

variable "config_bucket_name" {
  description = "Bucket receiving Config snapshots and history."
  type        = string
}

variable "config_bucket_arn" {
  description = "ARN of the Config delivery bucket, used to scope the recorder role."
  type        = string
}

variable "config_kms_key_arn" {
  description = "Key encrypting Config deliveries. Null uses S3 default encryption."
  type        = string
  default     = null
}

variable "record_global_resource_types" {
  description = <<-EOT
    Whether this region records global resource types (IAM users, roles,
    policies). Exactly one region in the account should set this true — every
    region recording them means paying to record the same IAM entities N times.
  EOT
  type        = bool
  default     = false
}

variable "conformance_pack_template_uri" {
  description = <<-EOT
    S3 URI of a conformance pack template. Null skips the pack.

    The pack is ordered after the recorder deliberately: rules created before a
    running recorder evaluate nothing, which is the state discovery found —
    343 rules and no recorder (finding LOG-004).
  EOT
  type        = string
  default     = null
}

variable "unused_access_age_days" {
  description = <<-EOT
    Days of non-use before Access Analyzer reports a permission as unused.

    90 matches a quarterly access-review cadence, so findings arrive in time to
    be actioned in the review rather than between two of them.
  EOT
  type        = number
  default     = 90

  validation {
    condition     = var.unused_access_age_days >= 1 && var.unused_access_age_days <= 365
    error_message = "unused_access_age_days must be between 1 and 365."
  }
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
