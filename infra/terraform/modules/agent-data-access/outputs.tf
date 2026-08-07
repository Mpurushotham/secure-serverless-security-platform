output "role_arn" {
  description = "Agent execution role ARN."
  value       = aws_iam_role.agent.arn
}

output "role_name" {
  description = "Agent execution role name."
  value       = aws_iam_role.agent.name
}

output "permission_boundary_arn" {
  description = "Permission boundary. Attach this to any future role that touches regulated data — it caps privilege regardless of what policy is later attached."
  value       = aws_iam_policy.boundary.arn
}

output "db_connect_resource_arn" {
  description = "The exact rds-db:connect resource this role is scoped to. Useful in evidence: it shows the grant names one database user on one cluster resource ID."
  value       = local.db_connect_resource
}
