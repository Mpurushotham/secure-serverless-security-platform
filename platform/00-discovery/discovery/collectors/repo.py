"""Checklist 18, 19 — CI/CD pipelines and IaC repositories.

These two checklist items cannot be answered from AWS APIs. Whether a pipeline
uses OIDC or a long-lived key, whether actions are pinned, whether IaC is
scanned before it is applied — all of that lives in the repository, not in the
account. Collecting it here keeps the report complete rather than leaving two
of twenty-five items blank because they were inconvenient.

Every result from this module is marked ``source: repo`` so no reader mistakes
it for something observed in AWS.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ..session import DiscoverySession
from .base import CollectorResult, register

REPO_ROOT = Path(__file__).resolve().parents[4]

# An action pinned to a tag or branch resolves to whatever that ref points at
# today. Pinning to a 40-character commit SHA is the only form that cannot be
# changed under you after review.
_SHA_PIN = re.compile(r"@[0-9a-f]{40}$")


@register
class CicdCollector:
    name = "cicd"
    domain = "code"
    checklist = (18,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        workflows_dir = REPO_ROOT / ".github" / "workflows"
        workflows: list[dict[str, Any]] = []

        for path in sorted(workflows_dir.glob("*.y*ml")):
            try:
                document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                workflows.append({"file": path.name, "parse_error": str(exc)[:200]})
                continue

            jobs = document.get("jobs", {}) or {}
            actions: list[str] = []
            for job in jobs.values():
                for step in (job or {}).get("steps", []) or []:
                    if isinstance(step, dict) and step.get("uses"):
                        actions.append(step["uses"])

            # `on` is parsed by PyYAML 1.1 rules as the boolean True.
            triggers = document.get("on", document.get(True, {}))

            workflows.append(
                {
                    "file": path.name,
                    "name": document.get("name"),
                    "triggers": sorted(triggers) if isinstance(triggers, dict) else [str(triggers)],
                    "top_level_permissions": document.get("permissions"),
                    "job_count": len(jobs),
                    "job_names": sorted(jobs),
                    "uses_aws_oidc": any(
                        "configure-aws-credentials" in a for a in actions
                    ),
                    "requests_id_token": _requests_id_token(document, jobs),
                    "actions": sorted(set(actions)),
                    "actions_not_sha_pinned": sorted(
                        {
                            a
                            for a in actions
                            # Local actions (./path) have no ref to pin.
                            if not a.startswith("./") and not _SHA_PIN.search(a)
                        }
                    ),
                }
            )

        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            status="observed",
            note="Sourced from the repository, not from AWS",
            data={
                "source": "repo",
                "workflows": workflows,
                "workflow_count": len(workflows),
                "any_uses_aws_oidc": any(w.get("uses_aws_oidc") for w in workflows),
                "total_actions_not_sha_pinned": sorted(
                    {a for w in workflows for a in w.get("actions_not_sha_pinned", [])}
                ),
                "has_codeowners": (REPO_ROOT / ".github" / "CODEOWNERS").exists(),
                "has_dependabot": (REPO_ROOT / ".github" / "dependabot.yml").exists(),
                "has_branch_rulesets": (REPO_ROOT / ".github" / "rulesets").is_dir(),
                "has_pre_commit": (REPO_ROOT / ".pre-commit-config.yaml").exists(),
            },
        )


@register
class IacCollector:
    name = "iac"
    domain = "code"
    checklist = (19,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        terraform: list[dict[str, Any]] = []
        for main in sorted(REPO_ROOT.glob("*/terraform/**/main.tf")):
            module_dir = main.parent
            files = sorted(p.name for p in module_dir.glob("*.tf"))
            body = "\n".join(
                p.read_text(encoding="utf-8", errors="replace")
                for p in module_dir.glob("*.tf")
            )
            terraform.append(
                {
                    "path": str(module_dir.relative_to(REPO_ROOT)),
                    "files": files,
                    "resource_count": body.count("\nresource "),
                    "has_variables": "variables.tf" in files,
                    "has_outputs": "outputs.tf" in files,
                    "checkov_suppressions": body.count("checkov:skip"),
                }
            )

        cdk_apps = [
            str(p.parent.relative_to(REPO_ROOT))
            for p in sorted(REPO_ROOT.glob("*/cdk/cdk.json"))
        ] + [
            str(p.parent.relative_to(REPO_ROOT))
            for p in sorted(REPO_ROOT.glob("platform/*/cdk/cdk.json"))
        ]

        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            status="observed",
            note="Sourced from the repository, not from AWS",
            data={
                "source": "repo",
                "terraform_modules": terraform,
                "terraform_module_count": len(terraform),
                "cdk_apps": sorted(set(cdk_apps)),
                "total_checkov_suppressions": sum(
                    m["checkov_suppressions"] for m in terraform
                ),
                "has_cloudformation": bool(
                    list(REPO_ROOT.glob("**/template.yaml"))
                    + list(REPO_ROOT.glob("**/template.yml"))
                ),
            },
        )


def _requests_id_token(document: dict[str, Any], jobs: dict[str, Any]) -> bool:
    """True when any scope in the workflow requests an OIDC token."""
    def has(permissions: Any) -> bool:
        return isinstance(permissions, dict) and permissions.get("id-token") == "write"

    if has(document.get("permissions")):
        return True
    return any(has((job or {}).get("permissions")) for job in jobs.values())
