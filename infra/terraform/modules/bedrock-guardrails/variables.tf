variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
}

variable "account_id" {
  description = "AWS account ID; used for source-account conditions on every service principal."
  type        = string
}

variable "region" {
  description = "AWS region."
  type        = string
}

variable "vpc_id" {
  description = "VPC for the Bedrock interface endpoint."
  type        = string
  default     = null
}

variable "vpc_cidr" {
  description = "VPC CIDR permitted to reach the interface endpoint."
  type        = string
  default     = null
}

variable "private_subnet_ids" {
  description = "Subnets for the interface endpoint."
  type        = list(string)
  default     = []
}

variable "create_vpc_endpoint" {
  description = "Create a Bedrock runtime interface endpoint so inference never leaves the VPC."
  type        = bool
  default     = true
}

# ANONYMIZE rather than BLOCK for identifiers that legitimately appear in
# operational text. A control that makes the assistant unusable for support
# workflows gets switched off, and a switched-off control protects nothing.
variable "anonymized_pii_entities" {
  description = "PII entity types replaced with a placeholder."
  type        = list(string)
  default = [
    "NAME",
    "EMAIL",
    "PHONE",
    "ADDRESS",
    "AGE",
    "USERNAME",
  ]
}

# BLOCK for anything whose presence in a prompt is itself the incident.
variable "blocked_pii_entities" {
  description = "PII entity types that cause the request to be refused outright."
  type        = list(string)
  default = [
    "CREDIT_DEBIT_CARD_NUMBER",
    "CREDIT_DEBIT_CARD_CVV",
    "PASSWORD",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "INTERNATIONAL_BANK_ACCOUNT_NUMBER",
  ]
}

variable "content_filters" {
  description = "Content filter strengths by category. NONE for PROMPT_ATTACK is deliberate on a coding assistant: legitimate security work discusses injection, and a strong filter here produces constant false refusals. Injection is bounded by authorisation, not by content filtering — see docs/01-threat-model.md."
  type        = map(string)
  default = {
    HATE          = "HIGH"
    INSULTS       = "MEDIUM"
    SEXUAL        = "HIGH"
    VIOLENCE      = "MEDIUM"
    MISCONDUCT    = "MEDIUM"
    PROMPT_ATTACK = "NONE"
  }
}

variable "blocked_input_message" {
  description = "Message returned when a prompt is refused. States the reason so the caller can adapt rather than retry blindly."
  type        = string
  default     = "This request was refused because it appears to contain personal or credential data. Query the masked views instead; see the AI secure-coding policy."
}

variable "blocked_output_message" {
  description = "Message returned when a completion is refused."
  type        = string
  default     = "The response was withheld because it appeared to contain personal or credential data."
}

variable "log_retention_days" {
  description = "Retention for invocation logs. Bounded rather than indefinite: prompts may contain personal data, and GDPR Art. 5(1)(e) requires storage limitation."
  type        = number
  default     = 90

  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 400
    error_message = "Retention must be between 30 and 400 days: shorter loses incident evidence, longer is hard to justify for prompt data."
  }
}

variable "tags" {
  description = "Additional tags."
  type        = map(string)
  default     = {}
}
