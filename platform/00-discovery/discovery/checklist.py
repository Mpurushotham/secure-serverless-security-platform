"""The 25-point current-state baseline, verbatim from the engineering plan.

Transcribed from ``docs/aws_security_engineering_plan.md`` §3 Step 1 so the
report can prove it covered all twenty-five items rather than the subset that
happened to be convenient to automate.

Five of them are judgement, not observation — vulnerability process, incident
procedures, data flows, regulatory scope and the top-ten risk list. Those are
assembled from documents already in this repository. Marking them ``judgement``
keeps them visible in the coverage table instead of quietly missing.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ChecklistItem:
    number: int
    title: str
    #: Where the answer comes from when no collector produces it.
    source: str = "AWS API"


CHECKLIST: dict[int, ChecklistItem] = {
    1: ChecklistItem(1, "Inventory AWS Organizations and accounts"),
    2: ChecklistItem(2, "Identify production vs non-production accounts"),
    3: ChecklistItem(3, "Inventory internet-facing assets"),
    4: ChecklistItem(4, "Inventory IAM identities, roles and trust policies"),
    5: ChecklistItem(5, "Review root-account controls"),
    6: ChecklistItem(6, "Review IAM Identity Center / enterprise IdP integration"),
    7: ChecklistItem(7, "Review SCPs and organization policies"),
    8: ChecklistItem(8, "Review CloudTrail coverage"),
    9: ChecklistItem(9, "Review GuardDuty coverage"),
    10: ChecklistItem(10, "Review Security Hub coverage"),
    11: ChecklistItem(11, "Review AWS Config coverage"),
    12: ChecklistItem(12, "Review encryption/KMS architecture"),
    13: ChecklistItem(13, "Review S3 public-access configuration"),
    14: ChecklistItem(14, "Review VPC topology"),
    15: ChecklistItem(15, "Review security groups and network paths"),
    16: ChecklistItem(16, "Review Lambda/API Gateway architecture"),
    17: ChecklistItem(17, "Review secrets management"),
    18: ChecklistItem(18, "Review CI/CD pipelines", "repository"),
    19: ChecklistItem(19, "Review Terraform/CDK/CloudFormation repositories", "repository"),
    20: ChecklistItem(
        20, "Review vulnerability-management process",
        "readiness/05-vulnerability-management.md",
    ),
    21: ChecklistItem(21, "Review incident-response procedures", "docs/05-incident-response/"),
    22: ChecklistItem(22, "Review third-party integrations"),
    23: ChecklistItem(23, "Map important data flows", "docs/01-threat-model.md"),
    24: ChecklistItem(
        24, "Identify regulatory and contractual obligations",
        "docs/06-compliance-map.md",
    ),
    25: ChecklistItem(25, "Establish the top 10 security risks", "this report"),
}
