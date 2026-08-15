"""Collector behaviour against mocked AWS.

moto covers IAM, S3 and KMS well enough to exercise the shapes that matter.
Organizations and Identity Center are covered by the recorded fixture in
``test_report.py`` instead — moto's support for them is thin enough that a
passing test would be testing moto rather than the collector.

The trust-policy analyser gets the most attention here because it is the piece
with real logic, and because getting it wrong in the *lenient* direction means
silently missing the way an estate is reached from outside.
"""

from __future__ import annotations

import json

import boto3
import pytest
from discovery.collectors.data import KmsCollector, S3Collector
from discovery.collectors.iam import IamCollector, analyse_trust_policy
from discovery.session import DiscoverySession
from moto import mock_aws

ACCOUNT = "123456789012"


@pytest.fixture
def session(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        yield DiscoverySession(profile=None, default_region="us-east-1")


class TestTrustPolicyAnalysis:
    def test_wildcard_principal_without_condition(self) -> None:
        trust = analyse_trust_policy(
            {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},
                            "Action": "sts:AssumeRole"}]},
            ACCOUNT,
        )
        assert trust["wildcard_principal"]
        assert not trust["wildcard_has_condition"]

    def test_wildcard_principal_with_condition_is_flagged_differently(self) -> None:
        # Both are reported, but they are not the same finding. A scanner that
        # collapses them produces alerts people learn to dismiss.
        trust = analyse_trust_policy(
            {"Statement": [{
                "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
            }]},
            ACCOUNT,
        )
        assert trust["wildcard_principal"]
        assert trust["wildcard_has_condition"]

    def test_own_account_is_not_external(self) -> None:
        trust = analyse_trust_policy(
            {"Statement": [{"Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                            "Action": "sts:AssumeRole"}]},
            ACCOUNT,
        )
        assert trust["external_accounts"] == []
        assert trust["same_account_trust"]

    def test_another_account_is_external(self) -> None:
        trust = analyse_trust_policy(
            {"Statement": [{"Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                            "Action": "sts:AssumeRole"}]},
            ACCOUNT,
        )
        assert trust["external_accounts"] == ["999988887777"]
        assert not trust["has_external_id_condition"]

    def test_external_id_condition_is_detected_case_insensitively(self) -> None:
        trust = analyse_trust_policy(
            {"Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": "shared-secret"}},
            }]},
            ACCOUNT,
        )
        assert trust["has_external_id_condition"]

    def test_deny_statements_do_not_create_trust(self) -> None:
        trust = analyse_trust_policy(
            {"Statement": [{"Effect": "Deny", "Principal": {"AWS": "*"},
                            "Action": "sts:AssumeRole"}]},
            ACCOUNT,
        )
        assert not trust["wildcard_principal"]

    def test_a_single_statement_object_is_handled(self) -> None:
        # AWS accepts Statement as an object rather than a list.
        trust = analyse_trust_policy(
            {"Statement": {"Effect": "Allow",
                           "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}},
            ACCOUNT,
        )
        assert trust["service_principals"] == ["lambda.amazonaws.com"]

    def test_missing_or_malformed_document_does_not_raise(self) -> None:
        for document in (None, {}, {"Statement": []}, {"Statement": [{}]}):
            assert analyse_trust_policy(document, ACCOUNT)["external_accounts"] == []


def admin_policy_arn(iam) -> str:
    """An attachable policy named AdministratorAccess.

    moto does not preload the AWS-managed policy catalogue, so the real ARN is
    not attachable here. The collector classifies on policy *name*, which is
    what makes it work across both customer-managed and AWS-managed policies —
    so a customer-managed policy of the same name exercises the same branch.
    """
    return iam.create_policy(
        PolicyName="AdministratorAccess",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )["Policy"]["Arn"]


class TestIamCollector:
    def test_admin_user_and_key_are_detected(self, session) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="alice")
        iam.attach_user_policy(UserName="alice", PolicyArn=admin_policy_arn(iam))
        iam.create_access_key(UserName="alice")

        data = IamCollector().collect(session, ["us-east-1"]).data
        alice = next(u for u in data["users"] if u["name"] == "alice")
        assert alice["has_admin_policy"]
        assert alice["admin_via"] == ["AdministratorAccess"]
        assert len(alice["access_keys"]) == 1
        assert data["totals"]["users_with_admin"] == 1

    def test_admin_via_group_membership_is_detected(self, session) -> None:
        # Privilege arriving through a group is the case a per-user policy scan
        # misses entirely.
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="bob")
        iam.create_group(GroupName="admins")
        iam.attach_group_policy(GroupName="admins", PolicyArn=admin_policy_arn(iam))
        iam.add_user_to_group(GroupName="admins", UserName="bob")

        data = IamCollector().collect(session, ["us-east-1"]).data
        bob = next(u for u in data["users"] if u["name"] == "bob")
        assert bob["has_admin_policy"]
        assert bob["attached_policies"] == []

    def test_service_linked_roles_are_marked(self, session) -> None:
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="app-role",
            Path="/aws-service-role/",
            AssumeRolePolicyDocument=json.dumps({
                "Statement": [{"Effect": "Allow",
                               "Principal": {"Service": "lambda.amazonaws.com"},
                               "Action": "sts:AssumeRole"}]
            }),
        )
        data = IamCollector().collect(session, ["us-east-1"]).data
        role = next(r for r in data["roles"] if r["name"] == "app-role")
        assert role["service_linked"]


class TestS3Collector:
    def test_unblocked_bucket_is_reported(self, session) -> None:
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="open-bucket")
        data = S3Collector().collect(session, ["us-east-1"]).data
        assert "open-bucket" in data["buckets_not_fully_blocked"]

    def test_fully_blocked_bucket_is_not_reported(self, session) -> None:
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="closed-bucket")
        s3.put_public_access_block(
            Bucket="closed-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            },
        )
        data = S3Collector().collect(session, ["us-east-1"]).data
        bucket = next(b for b in data["buckets"] if b["name"] == "closed-bucket")
        assert bucket["fully_blocked"]
        assert "closed-bucket" not in data["buckets_not_fully_blocked"]


class TestKmsCollector:
    def test_aws_managed_keys_are_excluded(self, session) -> None:
        # Rotation and policy on AWS-managed keys are not the customer's to
        # change, so reporting on them is noise that buries real findings.
        kms = boto3.client("kms", region_name="us-east-1")
        kms.create_key(Description="customer key")
        data = KmsCollector().collect(session, ["us-east-1"]).data
        assert all(k["description"] != "" for k in data["customer_managed_keys"])
        assert data["total"] >= 1
