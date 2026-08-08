variable "name_prefix" {
  type        = string
  description = "Prefix for resource names."
}

variable "github_organisation" {
  type        = string
  description = "GitHub organisation that owns the workflows."
}

variable "allowed_repositories" {
  type        = list(string)
  description = "Repositories permitted to assume the role. Names only, without the org prefix."

  validation {
    condition     = length(var.allowed_repositories) > 0 && !contains(var.allowed_repositories, "*")
    error_message = "List repositories explicitly. A '*' here lets any repository in the organisation assume this role, including one created by an attacker with org write access."
  }
}

variable "allowed_refs" {
  type        = list(string)
  description = "Git refs permitted to assume the role."
  default     = ["refs/heads/main"]

  validation {
    condition     = !contains(var.allowed_refs, "*") && !contains(var.allowed_refs, "refs/*")
    error_message = "A wildcard ref permits assumption from any branch, including a branch opened by a pull request from a fork. Name the refs."
  }
}

variable "allowed_environments" {
  type = list(object({
    repository  = string
    environment = string
  }))
  description = "GitHub Environments permitted to assume the role. Use this for deploys gated on required reviewers — it turns a human approval into an AWS authorisation condition rather than a GitHub-only setting."
  default     = []
}

variable "create_oidc_provider" {
  type        = bool
  description = "Create the account-wide OIDC provider. Set false if another stack already manages it — the provider is a singleton per account."
  default     = true
}

variable "existing_oidc_provider_arn" {
  type        = string
  description = "ARN of an existing GitHub OIDC provider, when create_oidc_provider is false."
  default     = null
}

variable "thumbprints" {
  type        = list(string)
  description = "OIDC thumbprints. AWS no longer validates these for the GitHub provider, but the API still requires the field."
  default     = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

variable "policy_arns" {
  type        = list(string)
  description = "Policies granting what this pipeline may actually do. Supplied by the caller: a module that ships a default deploy policy encourages copying one that is too wide."
  default     = []
}

variable "permissions_boundary_arn" {
  type        = string
  description = "Permissions boundary capping the role regardless of attached policy."
  default     = null
}

variable "denied_secret_arns" {
  type        = list(string)
  description = "Secrets this pipeline must never read. A pipeline that can read a production secret can print it to a build log."
  default     = []
}

variable "max_session_duration" {
  type        = number
  description = "Session length in seconds."
  default     = 3600

  validation {
    condition     = var.max_session_duration <= 7200
    error_message = "A CI job needing more than two hours of AWS access should be split; a long session is a longer window for a leaked token."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
