# Example wiring for the guardrail module.
#
# Committed deliberately (`.gitignore` allows `example.tfvars` and ignores every
# other `*.tfvars`) because the shape of the input is the interesting part: it
# is where someone decides what each policy costs them, and that decision should
# be reviewable.
#
# Every ID below is a placeholder. Get the real ones from:
#   aws organizations list-roots
#   aws organizations list-organizational-units-for-parent --parent-id r-xxxx

security_tooling_account_id = "210987654321"

acknowledge_management_account_exemption = true

service_control_policies = {
  protect-security-controls = {
    description = "Prevent disabling detection and audit services"
    document    = "protect-security-controls.json.tftpl"
    targets     = ["r-xxxx"]
    breaks = join(" ", [
      "Any legitimate teardown of GuardDuty, Security Hub, Config, Access",
      "Analyzer, Inspector, Macie, Detective or CloudTrail — including",
      "`terraform destroy` of platform/05-detection. Use the break-glass role,",
      "which is exempted and whose assumption should alert.",
    ])
  }

  deny-leaving-organization = {
    description = "Member accounts cannot leave the organization"
    document    = "deny-leaving-organization.json.tftpl"
    targets     = ["r-xxxx"]
    breaks = join(" ", [
      "Account divestiture and any org restructure that moves an account out.",
      "Detach deliberately, move the account, reattach — a two-minute planned",
      "operation, and the alternative is an account that can silently exit",
      "every control in this directory.",
    ])
  }

  deny-root-user-actions = {
    description = "Root may only manage its own MFA and password"
    document    = "deny-root-user-actions.json.tftpl"
    targets     = ["r-xxxx"]
    breaks = join(" ", [
      "The handful of tasks that genuinely require root in a member account:",
      "closing the account, changing the support plan, and some S3/SQS policy",
      "repairs. All are rare and planned. Detach for the maintenance window.",
      "Note this does NOT constrain the management account's root — SCPs never",
      "apply there, which is finding ORG-003 and has no policy fix.",
    ])
  }

  require-imdsv2-and-encryption = {
    description = "EBS and RDS must be encrypted; EC2 must require IMDSv2"
    document    = "require-imdsv2-and-encryption.json.tftpl"
    # Attached to Workloads rather than the root: discovery found three SCPs
    # attached to OUs containing no accounts (ORG-002), so verify with
    # `aws organizations list-accounts-for-parent` before trusting this line.
    targets = ["ou-xxxx-workloads"]
    breaks = join(" ", [
      "Launching an unencrypted volume or database, and any AMI or launch",
      "template that still uses IMDSv1. Older third-party AMIs are the usual",
      "casualty. Inventory before attaching.",
    ])
  }
}

resource_control_policies = {
  enforce-organization-boundary = {
    description = "Resource policies cannot grant access outside the organization"
    document    = "enforce-organization-boundary.json.tftpl"
    targets     = ["r-xxxx"]
    breaks = join(" ", [
      "Deliberate cross-organization sharing: a bucket shared with a partner, a",
      "KMS key granting a vendor account, a role assumable by a SaaS provider.",
      "Inventory external trusts BEFORE attaching — platform/00-discovery's",
      "third_party collector lists them. Attaching this blind is how an RCP",
      "rollout breaks a vendor integration and gets reverted for good.",
    ])
  }

  require-tls = {
    description = "Deny plaintext access to data services"
    document    = "require-tls.json.tftpl"
    targets     = ["r-xxxx"]
    breaks = join(" ", [
      "Any client still speaking HTTP to S3, SQS, Secrets Manager or KMS. Rare",
      "in practice; VPC endpoints and old SDKs are where it shows up.",
    ])
  }
}
