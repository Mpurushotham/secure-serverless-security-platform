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
  region = var.home_region

  default_tags {
    tags = {
      ManagedBy  = "terraform"
      Repository = "secure-serverless-security-platform"
    }
  }
}

# 04-logging already takes `home_region`, which the KMS key policy uses to scope
# its aws:SourceArn condition. Deriving the provider region from it keeps one
# source of truth: a provider in one region and a key policy naming another
# produces a trail that cannot encrypt, and the error surfaces at apply.
variable "aws_region" {
  description = "Unused — the provider region is taken from home_region."
  type        = string
  default     = null
}
