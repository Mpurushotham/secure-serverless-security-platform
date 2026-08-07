output "alert_topic_arn" {
  description = "SNS topic receiving detection alerts."
  value       = aws_sns_topic.alerts.arn
}

output "detection_ids" {
  description = "Detection identifiers implemented by this module, for cross-referencing with the ATT&CK coverage map."
  value = [
    "D-001-guardrail-refusal-burst",
    "D-002-unmask-used",
    "D-003-bulk-read-volume",
    "D-004-off-hours-activity",
    "D-005-database-auth-failures",
    "D-006-bedrock-guardrail-intervention",
    "D-007-guardduty-agent-role",
    "D-008-agent-role-modified",
  ]
}
