output "guardrail_id" {
  description = "Guardrail identifier. Callers must pass this on every InvokeModel; the VPC endpoint policy denies invocations that omit it."
  value       = aws_bedrock_guardrail.this.guardrail_id
}

output "guardrail_arn" {
  description = "Guardrail ARN."
  value       = aws_bedrock_guardrail.this.guardrail_arn
}

output "guardrail_version" {
  description = "Published version. Production must invoke this, never DRAFT — DRAFT is editable, so pinning to it means a console edit silently changes the control."
  value       = aws_bedrock_guardrail_version.this.version
}

output "invocation_log_group_name" {
  description = "CloudWatch log group receiving invocation logs."
  value       = aws_cloudwatch_log_group.invocations.name
}

output "invocation_log_bucket" {
  description = "S3 bucket receiving invocation logs and large payloads."
  value       = aws_s3_bucket.invocations.id
}

output "kms_key_arn" {
  description = "KMS key protecting guardrail configuration and invocation logs."
  value       = aws_kms_key.bedrock.arn
}

output "vpc_endpoint_id" {
  description = "Bedrock runtime interface endpoint, when created."
  value       = try(aws_vpc_endpoint.bedrock_runtime[0].id, null)
}
