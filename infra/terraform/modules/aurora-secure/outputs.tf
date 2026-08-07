output "cluster_identifier" {
  description = "Cluster identifier."
  value       = aws_rds_cluster.this.cluster_identifier
}

output "cluster_resource_id" {
  description = "Cluster resource ID. This is what an IAM rds-db:connect policy scopes to, not the cluster name — the resource ID survives a rename and cannot be spoofed by recreating a cluster with the same identifier."
  value       = aws_rds_cluster.this.cluster_resource_id
}

output "writer_endpoint" {
  description = "Writer endpoint."
  value       = aws_rds_cluster.this.endpoint
}

output "reader_endpoint" {
  description = "Reader endpoint. Agent and analytics traffic belongs here: a read-only workload on the writer competes with transactions it has no business affecting."
  value       = aws_rds_cluster.this.reader_endpoint
}

output "security_group_id" {
  description = "Cluster security group."
  value       = aws_security_group.aurora.id
}

output "kms_key_arn" {
  description = "KMS key protecting storage, Performance Insights, and the master secret."
  value       = aws_kms_key.aurora.arn
}

output "mask_salt_secret_arn" {
  description = "Secret holding the masking salt. The agent role is deliberately not granted read on this."
  value       = aws_secretsmanager_secret.mask_salt.arn
}

output "port" {
  description = "Database port."
  value       = aws_rds_cluster.this.port
}
