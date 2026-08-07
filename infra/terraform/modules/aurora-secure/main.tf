# Aurora PostgreSQL configured for regulated data (GDPR Art. 9).
#
# This module is the AWS counterpart to mcp-servers/rds_readonly_mcp/sql/. The
# SQL files hold the in-database controls (roles, RLS, masked views); this holds
# the controls the database cannot enforce about itself — encryption, network
# reachability, authentication mode, and audit log destination.
#
# The design decision that matters most here is IAM database authentication.
# With `iam_database_authentication_enabled`, the agent role has no password at
# all: it presents a short-lived token derived from its IAM identity. There is
# no long-lived credential to leak, rotate, or find in a git history — which
# removes the single most common cause of database compromise rather than
# managing it.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60"
    }
  }
}

locals {
  name = "${var.name_prefix}-aurora"

  tags = merge(var.tags, {
    Component       = "aurora-secure"
    DataClass       = "gdpr-article-9"
    ManagedBy       = "terraform"
    SecurityContact = var.security_contact
  })
}

# --- Encryption -------------------------------------------------------------
# A customer-managed key rather than the AWS-managed default, for three reasons
# that come up in every audit: rotation is provable, the key policy is auditable,
# and access can be revoked independently of the database itself.

resource "aws_kms_key" "aurora" {
  description             = "Aurora encryption at rest — ${local.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  # Multi-region is deliberately off: a key that can be replicated to another
  # region is a data-residency question, and Art. 9 data should not answer it
  # accidentally.
  multi_region = false
  tags         = local.tags

  # An explicit key policy. Without one the key inherits the default, which
  # grants the whole account and cannot be scoped or audited meaningfully.
  policy = data.aws_iam_policy_document.aurora_key.json
}

data "aws_iam_policy_document" "aurora_key" {
  # checkov:skip=CKV_AWS_109:The account-root statement is required by KMS. Omitting it makes the key permanently unmanageable — AWS documents this as mandatory.
  # checkov:skip=CKV_AWS_111:Same statement; scoping it defeats its purpose.
  # checkov:skip=CKV_AWS_356:KMS key policies are scoped by the key they attach to, not by a resource ARN in the statement.
  statement {
    sid       = "AccountRoot"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }

  statement {
    sid       = "RDSAndLogsUse"
    effect    = "Allow"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey", "kms:CreateGrant"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com", "monitoring.rds.amazonaws.com", "secretsmanager.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_kms_alias" "aurora" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.aurora.key_id
}

# --- Network ----------------------------------------------------------------

resource "aws_db_subnet_group" "this" {
  name       = local.name
  subnet_ids = var.private_subnet_ids
  tags       = local.tags
}

resource "aws_security_group" "aurora" {
  name        = "${local.name}-sg"
  description = "Aurora ingress restricted to named application security groups"
  vpc_id      = var.vpc_id
  tags        = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

# Ingress is granted only to explicitly named security groups. There is no CIDR
# variable on this module at all — not "a CIDR that defaults to something
# sensible", but no such input. An interface that cannot express 0.0.0.0/0
# cannot be misconfigured into it under deadline pressure.
resource "aws_vpc_security_group_ingress_rule" "from_app" {
  for_each = toset(var.allowed_client_security_group_ids)

  security_group_id            = aws_security_group.aurora.id
  referenced_security_group_id = each.value
  from_port                    = var.port
  to_port                      = var.port
  ip_protocol                  = "tcp"
  description                  = "PostgreSQL from ${each.value}"
}

# Egress is restricted to the VPC. An Aurora cluster has no legitimate reason to
# originate traffic to the internet; allowing it would create an exfiltration
# path that bypasses every application-layer control in this repository.
resource "aws_vpc_security_group_egress_rule" "vpc_only" {
  security_group_id = aws_security_group.aurora.id
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "-1"
  description       = "VPC-internal egress only"
}

# --- Parameter group --------------------------------------------------------
# Where the in-database security posture is pinned so it cannot be turned off
# per-session by anything short of a cluster change.

resource "aws_rds_cluster_parameter_group" "this" {
  name        = "${local.name}-cluster-params"
  family      = var.parameter_group_family
  description = "Forced TLS and audit logging for ${local.name}"
  tags        = local.tags

  # TLS is mandatory, not preferred. Without this a client can silently
  # negotiate plaintext and nothing in the application layer will notice.
  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  # pgaudit records DDL and role changes. Deliberately NOT set to log every
  # read: an audit log of queries against Art. 9 data becomes a second copy of
  # that data, held somewhere with weaker access controls than the table.
  parameter {
    name         = "shared_preload_libraries"
    value        = "pgaudit"
    apply_method = "pending-reboot"
  }

  parameter {
    name         = "pgaudit.log"
    value        = "ddl,role"
    apply_method = "pending-reboot"
  }

  parameter {
    name         = "log_min_duration_statement"
    value        = tostring(var.log_min_duration_ms)
    apply_method = "immediate"
  }

  # Connection lifecycle events are how "the agent role authenticated from an
  # unexpected place" becomes detectable at all.
  parameter {
    name         = "log_connections"
    value        = "1"
    apply_method = "immediate"
  }

  parameter {
    name         = "log_disconnections"
    value        = "1"
    apply_method = "immediate"
  }
}

# --- Cluster ----------------------------------------------------------------

resource "aws_rds_cluster" "this" {
  # checkov:skip=CKV2_AWS_27:Query logging is deliberately NOT enabled. A log of every statement against Art. 9 health data becomes a second copy of that data, in a store with weaker access controls than the table it came from. Slow-query logging (log_min_duration_statement) is enabled instead, and pgaudit records DDL and role changes — the events that matter for detection — without copying patient data into CloudWatch.
  # checkov:skip=CKV2_AWS_8:Automated backups are retained for 30 days with a mandatory final snapshot and deletion protection. An AWS Backup plan is the right next step for cross-account backup isolation, but it is a change-managed decision about where regulated data may be copied to, not a module default.
  cluster_identifier = local.name
  engine             = "aurora-postgresql"
  engine_version     = var.engine_version
  database_name      = var.database_name
  port               = var.port

  master_username = var.master_username
  # Managed by RDS in Secrets Manager and rotated by AWS. The alternative —
  # a password in a tfvars file or a Terraform variable — puts the credential
  # into state, and Terraform state is not a secret store.
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.aurora.arn

  # No password path for the application at all: the agent authenticates with a
  # short-lived IAM token. See modules/agent-data-access.
  iam_database_authentication_enabled = true

  db_subnet_group_name            = aws_db_subnet_group.this.name
  vpc_security_group_ids          = [aws_security_group.aurora.id]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.this.name

  storage_encrypted = true
  kms_key_id        = aws_kms_key.aurora.arn

  backup_retention_period      = var.backup_retention_days
  preferred_backup_window      = var.backup_window
  preferred_maintenance_window = var.maintenance_window
  copy_tags_to_snapshot        = true

  # Snapshots of Art. 9 data outlive the cluster. Retaining a final snapshot
  # means a deleted cluster does not silently take the audit trail with it.
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.name}-final"
  deletion_protection       = var.deletion_protection

  enabled_cloudwatch_logs_exports = ["postgresql"]

  # Cluster-level encryption of the log stream and Performance Insights data,
  # both of which can contain query text.
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.aurora.arn

  apply_immediately = var.apply_immediately

  tags = local.tags

  lifecycle {
    # Engine version upgrades are a change-managed event for a regulated
    # database, not something a plan should propose silently.
    ignore_changes = [engine_version]
  }
}

resource "aws_rds_cluster_instance" "this" {
  count = var.instance_count

  identifier           = "${local.name}-${count.index}"
  cluster_identifier   = aws_rds_cluster.this.id
  instance_class       = var.instance_class
  engine               = aws_rds_cluster.this.engine
  engine_version       = aws_rds_cluster.this.engine_version
  db_subnet_group_name = aws_db_subnet_group.this.name

  # The control that most often regresses. A publicly reachable database with
  # perfect in-database controls is still a publicly reachable database.
  publicly_accessible = false

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.aurora.arn
  monitoring_interval             = 30
  monitoring_role_arn             = aws_iam_role.monitoring.arn

  auto_minor_version_upgrade = true
  ca_cert_identifier         = var.ca_cert_identifier

  tags = local.tags
}

resource "aws_iam_role" "monitoring" {
  name = "${local.name}-monitoring"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
      Action    = "sts:AssumeRole"
      # Confused-deputy guard: without this, any account able to reach the RDS
      # monitoring service could induce it to assume this role.
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "monitoring" {
  role       = aws_iam_role.monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# --- Masking salt -----------------------------------------------------------
# The salt used by pharmacy.mask_token(). Kept out of the database so that read
# access to the masked view does not imply the ability to reverse it.
#
# This is the residual risk named in docs/01-threat-model.md, branch 2a: a
# deterministic mask over a small identifier space is reversible if the salt
# leaks. Hence a dedicated secret, a dedicated key, and no read grant for the
# agent role.

resource "aws_secretsmanager_secret" "mask_salt" {
  # checkov:skip=CKV2_AWS_57:Automatic rotation is deliberately off. The salt is an input to a DETERMINISTIC mask: rotating it changes every masked value, breaking joins against previously exported analytics and destroying the ability to correlate historical findings. Rotation here is an incident response action (see docs/01-threat-model.md, branch 2a), executed with a re-masking plan — not a scheduled background job.
  name                    = "${local.name}/mask-salt"
  description             = "Salt for pharmacy.mask_token(); never readable by the agent role"
  kms_key_id              = aws_kms_key.aurora.arn
  recovery_window_in_days = 30
  tags                    = local.tags
}
