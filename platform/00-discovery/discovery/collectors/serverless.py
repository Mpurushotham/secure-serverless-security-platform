"""Checklist 6, 16 — IAM Identity Center, Lambda, and API Gateway posture.

The Lambda collector reads ``GetFunctionConfiguration``, never ``GetFunction``.
The latter returns a presigned URL to download the deployment package, which is
the application's source code — configuration is what an inventory needs, and
source code is what it must not take.
"""

from __future__ import annotations

from typing import Any

from ..session import DiscoverySession
from .base import CollectorResult, register

# Runtimes past, or close to, end of support. A function on an unsupported
# runtime stops receiving security patches for the runtime itself, which no
# amount of dependency scanning in the function's own code will catch.
DEPRECATED_RUNTIME_PREFIXES = (
    "python2", "python3.6", "python3.7", "python3.8", "python3.9",
    "nodejs10", "nodejs12", "nodejs14", "nodejs16", "nodejs18",
    "ruby2", "ruby3.2", "java8", "dotnetcore", "dotnet6", "go1.x",
)

# Environment-variable names that suggest a secret is being passed in plaintext.
# The values are never read — only the keys, which the API returns as
# configuration. That is enough to raise the question without becoming a second
# copy of the secret.
SECRET_ENV_HINTS = (
    "secret", "password", "passwd", "token", "apikey", "api_key",
    "credential", "private_key", "privatekey", "access_key", "conn_str",
    "connection_string", "dsn",
)


@register
class IdentityCenterCollector:
    name = "identity_center"
    domain = "identity"
    checklist = (6,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        for region in regions:
            client = session.client("sso-admin", region)
            instances = session.paginate(client, "list_instances", "Instances")
            if not instances:
                continue

            instance = instances[0]
            arn = instance["InstanceArn"]
            permission_sets = session.paginate(
                client, "list_permission_sets", "PermissionSets", InstanceArn=arn
            )

            described = []
            for ps_arn in permission_sets:
                detail = session.call(
                    client,
                    "describe_permission_set",
                    InstanceArn=arn,
                    PermissionSetArn=ps_arn,
                )
                if detail is None:
                    continue
                ps = detail["PermissionSet"]
                managed = session.paginate(
                    client,
                    "list_managed_policies_in_permission_set",
                    "AttachedManagedPolicies",
                    InstanceArn=arn,
                    PermissionSetArn=ps_arn,
                )
                boundary = session.call(
                    client,
                    "get_permissions_boundary_for_permission_set",
                    InstanceArn=arn,
                    PermissionSetArn=ps_arn,
                )
                described.append(
                    {
                        "name": ps.get("Name"),
                        "session_duration": ps.get("SessionDuration"),
                        "managed_policies": [p["Name"] for p in managed],
                        "has_permission_boundary": bool(boundary),
                        "grants_admin": any(
                            p["Name"] in {"AdministratorAccess", "PowerUserAccess"}
                            for p in managed
                        ),
                    }
                )

            identity_store = session.client("identitystore", region)
            users = session.paginate(
                identity_store, "list_users", "Users",
                IdentityStoreId=instance["IdentityStoreId"],
            )
            groups = session.paginate(
                identity_store, "list_groups", "Groups",
                IdentityStoreId=instance["IdentityStoreId"],
            )

            return CollectorResult(
                name=self.name,
                domain=self.domain,
                checklist=self.checklist,
                data={
                    "enabled": True,
                    "region": region,
                    "instance_arn": arn,
                    "identity_store_id": instance.get("IdentityStoreId"),
                    "permission_sets": described,
                    "user_count": len(users),
                    "group_count": len(groups),
                    "admin_permission_sets": [
                        p["name"] for p in described if p["grants_admin"]
                    ],
                },
            )

        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={"enabled": False},
            note="No IAM Identity Center instance found in any scanned region",
        )


@register
class LambdaCollector:
    name = "lambda"
    domain = "code"
    checklist = (16,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        functions: list[dict[str, Any]] = []

        for region in regions:
            client = session.client("lambda", region)
            for cfg in session.paginate(client, "list_functions", "Functions"):
                env_keys = list(
                    (cfg.get("Environment") or {}).get("Variables", {}).keys()
                )
                runtime = cfg.get("Runtime") or ""
                concurrency = session.call(
                    client,
                    "get_function_concurrency",
                    FunctionName=cfg["FunctionName"],
                )

                functions.append(
                    {
                        "name": cfg["FunctionName"],
                        "region": region,
                        "runtime": runtime,
                        "runtime_deprecated": runtime.startswith(
                            DEPRECATED_RUNTIME_PREFIXES
                        ),
                        "role": cfg.get("Role"),
                        "vpc_attached": bool((cfg.get("VpcConfig") or {}).get("VpcId")),
                        "tracing": (cfg.get("TracingConfig") or {}).get("Mode"),
                        "kms_key_arn": cfg.get("KMSKeyArn"),
                        "reserved_concurrency": (concurrency or {}).get(
                            "ReservedConcurrentExecutions"
                        ),
                        "architectures": cfg.get("Architectures", []),
                        "timeout": cfg.get("Timeout"),
                        "env_var_names": env_keys,
                        "env_vars_look_secret": [
                            k for k in env_keys if _looks_secret(k)
                        ],
                        # Without a CMK, environment variables are encrypted with
                        # an AWS-managed key: anyone with lambda:GetFunctionConfiguration
                        # can read them back in plaintext.
                        "env_encrypted_with_cmk": bool(cfg.get("KMSKeyArn")) and bool(env_keys),
                    }
                )

        shared_roles: dict[str, list[str]] = {}
        for fn in functions:
            if fn["role"]:
                shared_roles.setdefault(fn["role"], []).append(fn["name"])

        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "functions": functions,
                "total": len(functions),
                "deprecated_runtimes": [
                    f"{f['name']} ({f['runtime']})"
                    for f in functions
                    if f["runtime_deprecated"]
                ],
                "without_tracing": [
                    f["name"] for f in functions if f["tracing"] != "Active"
                ],
                "with_secret_shaped_env_vars": [
                    {"function": f["name"], "variables": f["env_vars_look_secret"]}
                    for f in functions
                    if f["env_vars_look_secret"]
                ],
                # One role shared by many functions means the blast radius of any
                # one function is the union of what all of them need.
                "shared_execution_roles": {
                    role.split("/")[-1]: names
                    for role, names in shared_roles.items()
                    if len(names) > 1
                },
            },
        )


@register
class ApiGatewayCollector:
    name = "api_gateway"
    domain = "code"
    checklist = (16,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        apis: list[dict[str, Any]] = []

        for region in regions:
            rest = session.client("apigateway", region)
            for api in session.paginate(rest, "get_rest_apis", "items"):
                api_id = api["id"]
                authorizers = session.paginate(
                    rest, "get_authorizers", "items", restApiId=api_id
                )
                stages = session.call(rest, "get_stages", restApiId=api_id) or {}

                for stage in stages.get("item", []):
                    method_settings = stage.get("methodSettings", {}) or {}
                    apis.append(
                        {
                            "api_id": api_id,
                            "name": api.get("name"),
                            "region": region,
                            "protocol": "REST",
                            "stage": stage.get("stageName"),
                            "endpoint_types": (api.get("endpointConfiguration") or {}).get(
                                "types", []
                            ),
                            "authorizers": [a.get("type") for a in authorizers],
                            "has_authorizer": bool(authorizers),
                            "web_acl_arn": stage.get("webAclArn") or None,
                            "access_logging": bool(
                                (stage.get("accessLogSettings") or {}).get("destinationArn")
                            ),
                            "tracing": stage.get("tracingEnabled", False),
                            "cache_encrypted": any(
                                s.get("cacheDataEncrypted")
                                for s in method_settings.values()
                            ),
                            "throttling": {
                                "rate": next(
                                    (
                                        s.get("throttlingRateLimit")
                                        for s in method_settings.values()
                                        if s.get("throttlingRateLimit")
                                    ),
                                    None,
                                ),
                            },
                        }
                    )

            http = session.client("apigatewayv2", region)
            for api in session.paginate(http, "get_apis", "Items"):
                api_id = api["ApiId"]
                authorizers = session.paginate(
                    http, "get_authorizers", "Items", ApiId=api_id
                )
                stages = session.paginate(http, "get_stages", "Items", ApiId=api_id)
                for stage in stages:
                    apis.append(
                        {
                            "api_id": api_id,
                            "name": api.get("Name"),
                            "region": region,
                            "protocol": api.get("ProtocolType"),
                            "stage": stage.get("StageName"),
                            "authorizers": [a.get("AuthorizerType") for a in authorizers],
                            "has_authorizer": bool(authorizers),
                            "web_acl_arn": None,
                            "access_logging": bool(
                                (stage.get("AccessLogSettings") or {}).get("DestinationArn")
                            ),
                            "auto_deploy": stage.get("AutoDeploy", False),
                        }
                    )

        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "stages": apis,
                "total": len(apis),
                "without_authorizer": [
                    f"{a['name']}/{a['stage']}" for a in apis if not a["has_authorizer"]
                ],
                "without_access_logging": [
                    f"{a['name']}/{a['stage']}" for a in apis if not a["access_logging"]
                ],
                "without_waf": [
                    f"{a['name']}/{a['stage']}"
                    for a in apis
                    if a["protocol"] == "REST" and not a["web_acl_arn"]
                ],
            },
        )


def _looks_secret(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in SECRET_ENV_HINTS)
