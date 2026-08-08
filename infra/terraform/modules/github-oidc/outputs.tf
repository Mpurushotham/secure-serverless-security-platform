output "role_arn" {
  description = "Role ARN for the workflow's `role-to-assume`."
  value       = aws_iam_role.github.arn
}

output "role_name" {
  value       = aws_iam_role.github.name
  description = "Role name."
}

output "oidc_provider_arn" {
  description = "OIDC provider ARN, whether created here or supplied."
  value       = local.provider_arn
}

output "trusted_subjects" {
  description = "The exact sub claims permitted. Useful in evidence: it shows the trust is scoped to named repositories and refs rather than to an organisation wildcard."
  value       = local.all_subjects
}
