variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
}

variable "account_id" {
  description = "AWS account ID."
  type        = string
}

variable "agent_audit_log_group" {
  description = "CloudWatch log group receiving the MCP server's JSONL audit records."
  type        = string
}

variable "database_log_group" {
  description = "CloudWatch log group receiving Aurora PostgreSQL logs."
  type        = string
}

variable "agent_role_name" {
  description = "Name of the agent execution role, watched for IAM modification."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key for SNS topic encryption."
  type        = string
}

variable "metric_namespace" {
  description = "CloudWatch metric namespace."
  type        = string
  default     = "AgentSecurity"
}

variable "refusal_burst_threshold" {
  description = "Guardrail refusals in 5 minutes before alerting. Low on purpose: legitimate use produces almost none, so a low threshold is high-signal rather than noisy."
  type        = number
  default     = 10
}

variable "hourly_row_threshold" {
  description = "Cumulative rows returned per hour before alerting. This is the detection most in need of tuning against real traffic — treat the default as a starting point, not a recommendation."
  type        = number
  default     = 5000
}

variable "auth_failure_threshold" {
  description = "Database authentication failures in 5 minutes before alerting."
  type        = number
  default     = 5
}

variable "tags" {
  description = "Additional tags."
  type        = map(string)
  default     = {}
}
