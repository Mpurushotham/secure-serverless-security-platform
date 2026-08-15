"""Checklist 3, 14, 15 — VPC topology, security groups, and internet exposure.

The exposure collector is the one that matters. VPC and security-group
inventories describe how the network is arranged; exposure answers the only
question an attacker asks, which is *what can I reach from outside*.
"""

from __future__ import annotations

from typing import Any

from ..session import DiscoverySession
from .base import CollectorResult, register

# Ports where an internet-facing ingress rule is a finding rather than a design.
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5439: "Redshift",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


@register
class VpcCollector:
    name = "vpc"
    domain = "infrastructure"
    checklist = (14,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        vpcs: list[dict[str, Any]] = []

        for region in regions:
            ec2 = session.client("ec2", region)
            regional_vpcs = session.paginate(ec2, "describe_vpcs", "Vpcs")
            if not regional_vpcs:
                continue

            subnets = session.paginate(ec2, "describe_subnets", "Subnets")
            flow_logs = session.paginate(ec2, "describe_flow_logs", "FlowLogs")
            endpoints = session.paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints")
            nat = session.paginate(ec2, "describe_nat_gateways", "NatGateways")
            igw = session.paginate(ec2, "describe_internet_gateways", "InternetGateways")
            peering = session.paginate(
                ec2, "describe_vpc_peering_connections", "VpcPeeringConnections"
            )

            logged = {f["ResourceId"] for f in flow_logs if f.get("FlowLogStatus") == "ACTIVE"}

            for vpc in regional_vpcs:
                vpc_id = vpc["VpcId"]
                vpc_subnets = [s for s in subnets if s["VpcId"] == vpc_id]
                vpcs.append(
                    {
                        "vpc_id": vpc_id,
                        "region": region,
                        "cidr": vpc.get("CidrBlock"),
                        "is_default": vpc.get("IsDefault", False),
                        "flow_logs_enabled": vpc_id in logged,
                        "subnet_count": len(vpc_subnets),
                        "public_subnets": [
                            s["SubnetId"]
                            for s in vpc_subnets
                            if s.get("MapPublicIpOnLaunch")
                        ],
                        "nat_gateways": len(
                            [n for n in nat if n.get("VpcId") == vpc_id
                             and n.get("State") == "available"]
                        ),
                        "internet_gateways": len(
                            [
                                g
                                for g in igw
                                if any(a.get("VpcId") == vpc_id for a in g.get("Attachments", []))
                            ]
                        ),
                        "vpc_endpoints": len(
                            [e for e in endpoints if e.get("VpcId") == vpc_id]
                        ),
                        "peering_connections": len(
                            [
                                p
                                for p in peering
                                if vpc_id
                                in {
                                    (p.get("RequesterVpcInfo") or {}).get("VpcId"),
                                    (p.get("AccepterVpcInfo") or {}).get("VpcId"),
                                }
                            ]
                        ),
                    }
                )

        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "vpcs": vpcs,
                "total": len(vpcs),
                "without_flow_logs": [
                    f"{v['region']}/{v['vpc_id']}" for v in vpcs if not v["flow_logs_enabled"]
                ],
                "default_vpcs": [
                    f"{v['region']}/{v['vpc_id']}" for v in vpcs if v["is_default"]
                ],
            },
        )


@register
class SecurityGroupCollector:
    name = "security_groups"
    domain = "infrastructure"
    checklist = (15,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        risky: list[dict[str, Any]] = []
        total = 0

        for region in regions:
            ec2 = session.client("ec2", region)
            groups = session.paginate(ec2, "describe_security_groups", "SecurityGroups")
            total += len(groups)

            for group in groups:
                for rule in group.get("IpPermissions", []):
                    open_to = [
                        r["CidrIp"]
                        for r in rule.get("IpRanges", [])
                        if r.get("CidrIp") in OPEN_CIDRS
                    ] + [
                        r["CidrIpv6"]
                        for r in rule.get("Ipv6Ranges", [])
                        if r.get("CidrIpv6") in OPEN_CIDRS
                    ]
                    if not open_to:
                        continue

                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    protocol = rule.get("IpProtocol")

                    # "-1" means every protocol and every port.
                    all_ports = protocol == "-1" or (
                        from_port == 0 and to_port == 65535
                    )
                    exposed = sorted(
                        {
                            port
                            for port in SENSITIVE_PORTS
                            if all_ports
                            or (
                                from_port is not None
                                and to_port is not None
                                and from_port <= port <= to_port
                            )
                        }
                    )

                    risky.append(
                        {
                            "group_id": group["GroupId"],
                            "group_name": group.get("GroupName"),
                            "region": region,
                            "vpc_id": group.get("VpcId"),
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "open_to": open_to,
                            "all_ports": all_ports,
                            "sensitive_ports_exposed": [
                                f"{p}/{SENSITIVE_PORTS[p]}" for p in exposed
                            ],
                        }
                    )

        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "total_groups": total,
                "internet_open_rules": risky,
                "groups_open_to_internet": sorted({r["group_id"] for r in risky}),
                "groups_exposing_sensitive_ports": sorted(
                    {r["group_id"] for r in risky if r["sensitive_ports_exposed"]}
                ),
            },
        )


@register
class ExposureCollector:
    """Checklist 3 — everything reachable from the internet."""

    name = "exposure"
    domain = "infrastructure"
    checklist = (3,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        data: dict[str, Any] = {
            "load_balancers": [],
            "elastic_ips": [],
            "public_instances": [],
            "public_databases": [],
            "api_gateways": [],
            "lambda_function_urls": [],
            "cloudfront_distributions": [],
        }

        for region in regions:
            elbv2 = session.client("elbv2", region)
            for lb in session.paginate(elbv2, "describe_load_balancers", "LoadBalancers"):
                if lb.get("Scheme") == "internet-facing":
                    data["load_balancers"].append(
                        {
                            "name": lb.get("LoadBalancerName"),
                            "region": region,
                            "type": lb.get("Type"),
                            "dns_name": lb.get("DNSName"),
                        }
                    )

            ec2 = session.client("ec2", region)
            addresses = session.call(ec2, "describe_addresses") or {}
            for address in addresses.get("Addresses", []):
                data["elastic_ips"].append(
                    {
                        "region": region,
                        "public_ip": address.get("PublicIp"),
                        "associated": bool(
                            address.get("InstanceId") or address.get("NetworkInterfaceId")
                        ),
                    }
                )

            for reservation in session.paginate(
                ec2, "describe_instances", "Reservations"
            ):
                for instance in reservation.get("Instances", []):
                    if instance.get("PublicIpAddress"):
                        data["public_instances"].append(
                            {
                                "instance_id": instance["InstanceId"],
                                "region": region,
                                "public_ip": instance["PublicIpAddress"],
                                "state": (instance.get("State") or {}).get("Name"),
                            }
                        )

            rds = session.client("rds", region)
            for db in session.paginate(rds, "describe_db_instances", "DBInstances"):
                if db.get("PubliclyAccessible"):
                    data["public_databases"].append(
                        {
                            "identifier": db.get("DBInstanceIdentifier"),
                            "region": region,
                            "engine": db.get("Engine"),
                            "encrypted": db.get("StorageEncrypted", False),
                        }
                    )

            apigw = session.client("apigateway", region)
            for api in session.paginate(apigw, "get_rest_apis", "items"):
                data["api_gateways"].append(
                    {
                        "id": api.get("id"),
                        "name": api.get("name"),
                        "region": region,
                        "protocol": "REST",
                        "endpoint_types": (api.get("endpointConfiguration") or {}).get(
                            "types", []
                        ),
                    }
                )

            apigwv2 = session.client("apigatewayv2", region)
            for api in session.paginate(apigwv2, "get_apis", "Items"):
                data["api_gateways"].append(
                    {
                        "id": api.get("ApiId"),
                        "name": api.get("Name"),
                        "region": region,
                        "protocol": api.get("ProtocolType"),
                        "endpoint": api.get("ApiEndpoint"),
                    }
                )

            lam = session.client("lambda", region)
            for cfg in session.paginate(lam, "list_functions", "Functions"):
                url = session.call(
                    lam, "get_function_url_config", FunctionName=cfg["FunctionName"]
                )
                if url:
                    data["lambda_function_urls"].append(
                        {
                            "function": cfg["FunctionName"],
                            "region": region,
                            # NONE means the URL is unauthenticated — a public
                            # endpoint bypassing API Gateway and everything
                            # attached to it.
                            "auth_type": url.get("AuthType"),
                        }
                    )

        cloudfront = session.client("cloudfront", "us-east-1")
        distributions = session.paginate(
            cloudfront, "list_distributions", "Items"
        )
        for dist in distributions or []:
            data["cloudfront_distributions"].append(
                {
                    "id": dist.get("Id"),
                    "domain": dist.get("DomainName"),
                    "enabled": dist.get("Enabled"),
                    "web_acl_id": dist.get("WebACLId") or None,
                }
            )

        data["total_internet_facing"] = sum(
            len(v) for k, v in data.items() if isinstance(v, list)
        )
        data["unauthenticated_function_urls"] = [
            u["function"] for u in data["lambda_function_urls"] if u["auth_type"] == "NONE"
        ]
        data["cloudfront_without_waf"] = [
            d["id"] for d in data["cloudfront_distributions"] if not d["web_acl_id"]
        ]

        return CollectorResult(
            name=self.name, domain=self.domain, checklist=self.checklist, data=data
        )
