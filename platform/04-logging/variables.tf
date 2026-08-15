variable "name_prefix" {
  description = "Prefix for the trail, bucket and key."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,32}$", var.name_prefix))
    error_message = "name_prefix must be lowercase alphanumeric with hyphens, 2-33 characters."
  }
}

variable "home_region" {
  description = <<-EOT
    Region the trail is created in. Used to scope the KMS key policy's
    aws:SourceArn condition to this trail specifically — without it, any
    CloudTrail in any account could ask the key to encrypt on its behalf.
  EOT
  type        = string
}

variable "log_retention_days" {
  description = <<-EOT
    Object Lock retention, in days, in COMPLIANCE mode.

    Under compliance mode this cannot be shortened by anyone, including the
    account root — which is the property that makes it a control rather than a
    preference, and the reason to choose the number deliberately. The default is
    one year; regulated workloads frequently need longer, and longer is
    expensive to reverse because it cannot be.
  EOT
  type        = number
  default     = 365

  validation {
    condition     = var.log_retention_days >= 90
    error_message = "Retention below 90 days is shorter than most breach-investigation windows."
  }
}

variable "log_reader_role_arns" {
  description = <<-EOT
    Roles permitted to decrypt log files.

    Deliberately roles rather than an account: read access to the archive bucket
    yields ciphertext, and this list is what turns it into readable history.
    Empty means nobody can read the logs yet, which is a safe default for a
    module that has not been wired to a security account.
  EOT
  type        = list(string)
  default     = []
}

variable "data_event_bucket_arns" {
  description = <<-EOT
    Bucket ARN prefixes to record object-level events for (finding LOG-003).

    Scoped rather than global on purpose. `arn:aws:s3` alone records every
    object operation in every account — the configuration that produces a bill
    nobody defends and a control that gets switched off six weeks later.
  EOT
  type        = list(string)
  default     = []
}

variable "data_event_function_arns" {
  description = "Lambda ARN prefixes to record invocation events for."
  type        = list(string)
  default     = []
}

variable "cloudwatch_log_group_arn" {
  description = <<-EOT
    Optional CloudWatch Logs group for near-real-time delivery.

    S3 delivery is the durable copy but lands in batches minutes apart, which is
    too slow to drive a detection. Null means detections must be built on
    EventBridge instead.
  EOT
  type        = string
  default     = null
}

variable "cloudwatch_role_arn" {
  description = "Role CloudTrail assumes to write to CloudWatch Logs."
  type        = string
  default     = null
}

variable "break_glass_role_name" {
  description = "Role exempted from the bucket policy's deletion deny."
  type        = string
  default     = "SecurityBreakGlass"
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
