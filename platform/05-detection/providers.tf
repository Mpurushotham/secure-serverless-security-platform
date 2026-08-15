# These are ROOT configurations, not shared modules — nothing calls them with a
# `module` block, and each is applied on its own against a specific account.
# Root configurations must declare their provider, or `terraform plan` fails
# with "requires explicit configuration" and the whole directory is
# validate-only in practice.
#
# `terraform validate` does not catch this: validation succeeds without a
# provider block, so a configuration can pass every static check in CI and
# still be unplannable. That gap is why this file exists.

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy  = "terraform"
      Repository = "secure-serverless-security-platform"
    }
  }
}

variable "aws_region" {
  description = "Region this configuration is applied in."
  type        = string
  default     = "eu-north-1"
}
