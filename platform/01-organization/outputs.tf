output "organization_id" {
  description = "The organization these guardrails apply to."
  value       = data.aws_organizations_organization.this.id
}

output "management_account_id" {
  description = <<-EOT
    The account no SCP in this module constrains. Emitted as an output so that
    anything consuming this module has the ID it needs to exclude the management
    account from claims about SCP coverage.
  EOT
  value       = data.aws_organizations_organization.this.master_account_id
}

output "security_tooling_account_id" {
  description = "Account delegated to administer the security services."
  value       = local.security_account_id
}

output "delegated_services" {
  description = "Service principals delegated by this module."
  value       = [for d in aws_organizations_delegated_administrator.security : d.service_principal]
}

output "service_control_policy_ids" {
  description = "Managed SCP IDs, keyed by policy name."
  value       = { for name, policy in aws_organizations_policy.scp : name => policy.id }
}

output "resource_control_policy_ids" {
  description = "Managed RCP IDs, keyed by policy name."
  value       = { for name, policy in aws_organizations_policy.rcp : name => policy.id }
}

output "policy_blast_radius" {
  description = <<-EOT
    What each managed policy would break, keyed by policy name.

    Exposed as an output so an incident responder can answer "what does
    detaching this cost me" from `terraform output` rather than from the policy
    JSON, which describes what is denied and not what depends on it.
  EOT
  value = merge(
    { for name, policy in var.service_control_policies : name => policy.breaks },
    { for name, policy in var.resource_control_policies : name => policy.breaks },
  )
}
