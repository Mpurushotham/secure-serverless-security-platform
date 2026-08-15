output "trail_arn" {
  description = "ARN of the organization trail."
  value       = aws_cloudtrail.org.arn
}

output "trail_name" {
  description = "Name of the organization trail."
  value       = aws_cloudtrail.org.name
}

output "archive_bucket" {
  description = "Log archive bucket name."
  value       = aws_s3_bucket.trail.id
}

output "archive_bucket_arn" {
  description = "Log archive bucket ARN."
  value       = aws_s3_bucket.trail.arn
}

output "kms_key_arn" {
  description = "Key encrypting the log files. Decryption is granted to named roles only."
  value       = aws_kms_key.trail.arn
}

output "object_lock_retention_days" {
  description = <<-EOT
    Retention under COMPLIANCE mode. Surfaced because it cannot be shortened
    later by anyone, including the account root, and a reader of this stack
    should not have to open the code to discover that.
  EOT
  value       = var.log_retention_days
}

output "data_events_enabled" {
  description = "Whether any data-event selector is configured (finding LOG-003)."
  value       = length(var.data_event_bucket_arns) > 0 || length(var.data_event_function_arns) > 0
}
