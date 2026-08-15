output "guardduty_detector_id" {
  description = "Detector ID in this region."
  value       = aws_guardduty_detector.this.id
}

output "guardduty_features_enabled" {
  description = <<-EOT
    Protection plans switched on. Emitted so a reader can compare regions
    without opening the console: uneven coverage across regions (finding
    DET-002) is invisible from any single one.
  EOT
  value       = sort([for name, on in var.guardduty_features : name if on])
}

output "guardduty_features_disabled" {
  description = "Protection plans deliberately left off. An empty list is not the same as an unset one."
  value       = sort([for name, on in var.guardduty_features : name if !on])
}

output "security_standards_enabled" {
  description = "Security Hub standards subscribed in this region."
  value       = sort(keys(var.security_standards))
}

output "config_recorder_name" {
  description = "Configuration recorder name."
  value       = aws_config_configuration_recorder.this.name
}

output "config_is_recording" {
  description = <<-EOT
    Whether the recorder is started. This is the distinction finding LOG-004
    turned on: a recorder that exists but is not recording looks identical to a
    healthy one on any dashboard checking whether Config is 'enabled'.
  EOT
  value       = aws_config_configuration_recorder_status.this.is_enabled
}

output "access_analyzer_arns" {
  description = "Both analyzers. External access and unused access answer different questions."
  value = {
    external_access = aws_accessanalyzer_analyzer.external.arn
    unused_access   = aws_accessanalyzer_analyzer.unused.arn
  }
}
