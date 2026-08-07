variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
}

variable "account_id" {
  description = "AWS account ID."
  type        = string
}

variable "region" {
  description = "AWS region."
  type        = string
}

variable "cluster_resource_id" {
  description = "Aurora cluster RESOURCE ID (not the identifier). Scoping rds-db:connect to the resource ID means the grant cannot be inherited by a different cluster recreated under the same name."
  type        = string
}

variable "database_username" {
  description = "The single database user this role may authenticate as."
  type        = string
  default     = "mcp_readonly"

  validation {
    condition     = var.database_username != "postgres" && var.database_username != "rdsadmin"
    error_message = "The agent role must never be permitted to connect as a superuser account."
  }
}

variable "mask_salt_secret_arn" {
  description = "ARN of the masking-salt secret. This role is explicitly DENIED access to it: reading the masked view must not imply the ability to reverse the mask."
  type        = string
}

variable "readable_secret_arns" {
  description = "Operational secrets this role may read. Must not include the masking salt — the deny in the permission boundary will override it if it does."
  type        = list(string)
  default     = []
}

variable "readable_kms_key_arns" {
  description = "KMS keys this role may use for decryption, restricted to use via Secrets Manager."
  type        = list(string)
  default     = []
}

variable "trusted_service_principals" {
  description = "Service principals permitted to assume this role."
  type        = list(string)
  default     = ["lambda.amazonaws.com"]
}

variable "trusted_source_arns" {
  description = "Specific workload ARNs permitted to assume the role. Empty means any workload of the trusted service in this account, which is weaker — set this in production."
  type        = list(string)
  default     = []
}

variable "max_session_duration" {
  description = "Maximum session duration in seconds. Short by default: a leaked session credential expires rather than persisting."
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_duration <= 14400
    error_message = "Sessions longer than four hours defeat the purpose of short-lived credentials."
  }
}

variable "bedrock_guardrail_id" {
  description = "Guardrail identifier. When set, model invocation is permitted only with this guardrail attached."
  type        = string
  default     = null
}

variable "allowed_model_arns" {
  description = "Foundation models this role may invoke. Wildcards here would permit invoking any model, including ones with different data-handling terms."
  type        = list(string)
  default     = []
}

variable "log_group_name" {
  description = "Log group this role may write to."
  type        = string
  default     = "/aws/lambda/mcp-agent"
}

variable "tags" {
  description = "Additional tags."
  type        = map(string)
  default     = {}
}
