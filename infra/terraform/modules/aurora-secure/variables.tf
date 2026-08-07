variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
}

variable "account_id" {
  description = "AWS account ID, used for the confused-deputy condition on the monitoring role."
  type        = string
}

variable "vpc_id" {
  description = "VPC in which the cluster is placed."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR. Egress from the cluster is restricted to this range."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets for the DB subnet group. Must not have a route to an internet gateway."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "Aurora requires subnets in at least two availability zones."
  }
}

# Note the absence of an ingress-CIDR variable. Ingress is expressible only as a
# reference to another security group, so this module has no syntax for
# 0.0.0.0/0. Removing the option is stronger than defaulting it safely.
variable "allowed_client_security_group_ids" {
  description = "Security groups permitted to reach the cluster on the database port."
  type        = list(string)
  default     = []
}

variable "database_name" {
  description = "Initial database name."
  type        = string
  default     = "pharmadb"
}

variable "master_username" {
  description = "Master username. The password is generated and rotated by RDS; it is never a Terraform input, because Terraform state is not a secret store."
  type        = string
  default     = "dbadmin"
}

variable "engine_version" {
  description = "Aurora PostgreSQL engine version."
  type        = string
  default     = "16.4"
}

variable "parameter_group_family" {
  description = "Cluster parameter group family; must match the engine major version."
  type        = string
  default     = "aurora-postgresql16"
}

variable "port" {
  description = "Database port."
  type        = number
  default     = 5432
}

variable "instance_class" {
  description = "Instance class for cluster members."
  type        = string
  default     = "db.r6g.large"
}

variable "instance_count" {
  description = "Number of cluster instances. Two or more gives a reader endpoint for analytics traffic, which is where agent queries belong."
  type        = number
  default     = 2

  validation {
    condition     = var.instance_count >= 1
    error_message = "At least one instance is required."
  }
}

variable "backup_retention_days" {
  description = "Automated backup retention."
  type        = number
  default     = 30

  validation {
    condition     = var.backup_retention_days >= 7
    error_message = "Retention below 7 days is insufficient for a regulated dataset."
  }
}

variable "backup_window" {
  description = "Preferred backup window (UTC)."
  type        = string
  default     = "02:00-03:00"
}

variable "maintenance_window" {
  description = "Preferred maintenance window (UTC)."
  type        = string
  default     = "sun:03:30-sun:04:30"
}

variable "deletion_protection" {
  description = "Deletion protection. Defaults on: an accidental destroy of a regulated dataset is not a recoverable mistake."
  type        = bool
  default     = true
}

variable "log_min_duration_ms" {
  description = "Log statements slower than this many milliseconds. Not zero: logging every statement would copy Art. 9 data into a log with weaker access controls."
  type        = number
  default     = 1000
}

variable "ca_cert_identifier" {
  description = "RDS CA bundle identifier."
  type        = string
  default     = "rds-ca-rsa2048-g1"
}

variable "apply_immediately" {
  description = "Apply changes immediately rather than in the maintenance window."
  type        = bool
  default     = false
}

variable "security_contact" {
  description = "Team or alias accountable for this cluster."
  type        = string
  default     = "security@example.com"
}

variable "tags" {
  description = "Additional tags."
  type        = map(string)
  default     = {}
}
