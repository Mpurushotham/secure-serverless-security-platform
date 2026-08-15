"""Redaction is what makes a snapshot safe to commit to a public repository.

The properties that matter are: identifiers are gone, the same identifier maps
to the same pseudonym everywhere (or the report becomes unreadable), and the
structure survives (or the report becomes useless).
"""

from __future__ import annotations

from discovery.redact import Redactor

# Synthetic throughout. Using a real account or organization id as a test
# input would publish exactly the identifiers this module exists to remove.
ACCOUNT = "210987654321"


def redactor() -> Redactor:
    return Redactor(ACCOUNT)


class TestIdentifiersAreRemoved:
    def test_account_ids(self) -> None:
        assert ACCOUNT not in redactor().text(f"arn:aws:iam::{ACCOUNT}:role/admin")

    def test_organization_ids(self) -> None:
        out = redactor().text("o-a1b2c3d4e5 ou-a1b2-9z8y7x6w r-a1b2 p-abcd1234")
        for identifier in ("o-a1b2c3d4e5", "ou-a1b2-9z8y7x6w", "r-a1b2", "p-abcd1234"):
            assert identifier not in out

    def test_email_addresses(self) -> None:
        out = redactor().text("owner@example.com")
        assert "owner@example.com" not in out
        assert out.endswith("@redacted.invalid")

    def test_resource_ids(self) -> None:
        out = redactor().text("vpc-0123456789abcdef0 sg-0fedcba987654321f subnet-0abc1234")
        for identifier in ("vpc-0123456789abcdef0", "sg-0fedcba987654321f", "subnet-0abc1234"):
            assert identifier not in out

    def test_access_key_ids(self) -> None:
        # Should never appear in a snapshot, but a description field is free text.
        out = redactor().text("AKIAIOSFODNN7EXAMPLE and ASIAY34FZKBOKMUTVV7A")
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert "ASIAY34FZKBOKMUTVV7A" not in out


class TestUsability:
    def test_pseudonyms_are_stable_within_a_document(self) -> None:
        r = redactor()
        first = r.text(f"account {ACCOUNT}")
        second = r.text(f"arn:aws:iam::{ACCOUNT}:root")
        token = first.split()[-1]
        assert token in second, "the same account must map to the same pseudonym"

    def test_pseudonyms_are_stable_across_runs(self) -> None:
        # Otherwise the diff between two snapshots is entirely noise and nobody
        # can see what actually changed.
        assert redactor().text(ACCOUNT) == redactor().text(ACCOUNT)

    def test_distinct_identifiers_get_distinct_pseudonyms(self) -> None:
        r = redactor()
        assert r.text("210987654321") != r.text("109876543210")

    def test_structure_and_non_identifiers_survive(self) -> None:
        snapshot = {
            "assessed_account": ACCOUNT,
            "collectors": {
                "s3": {
                    "status": "observed",
                    "data": {"total": 6, "buckets_unencrypted": [], "region": "eu-north-1"},
                }
            },
        }
        out = redactor().apply(snapshot)
        assert out["collectors"]["s3"]["status"] == "observed"
        assert out["collectors"]["s3"]["data"]["total"] == 6
        assert out["collectors"]["s3"]["data"]["region"] == "eu-north-1"
        assert out["assessed_account"] != ACCOUNT

    def test_numbers_and_booleans_are_untouched(self) -> None:
        out = redactor().apply({"count": 12, "enabled": True, "ratio": 0.5, "none": None})
        assert out == {"count": 12, "enabled": True, "ratio": 0.5, "none": None}

    def test_a_twelve_digit_number_that_is_not_an_account_is_still_redacted(self) -> None:
        # Accepted false positive: there is no way to tell a bare 12-digit
        # number from an account ID, and over-redacting a count is a far
        # cheaper mistake than leaking an account.
        assert redactor().text("123456789012") != "123456789012"


def with_names(**collectors: dict) -> dict:
    return {
        "assessed_account": ACCOUNT,
        "collectors": {
            name: {"domain": "identity", "checklist": [1], "status": "observed", "data": data}
            for name, data in collectors.items()
        },
    }


class TestNameRedaction:
    def test_iam_user_names_are_pseudonymised_everywhere_they_appear(self) -> None:
        out = redactor().apply(
            with_names(iam={
                "users": [{
                    "name": "alice-admin",
                    "arn": f"arn:aws:iam::{ACCOUNT}:user/alice-admin",
                }],
                "roles": [],
            })
        )
        user = out["collectors"]["iam"]["data"]["users"][0]
        assert "alice-admin" not in user["name"]
        # And in the ARN, not only in the field it was collected from.
        assert "alice-admin" not in user["arn"]
        assert user["name"] in user["arn"]

    def test_aws_owned_names_survive(self) -> None:
        # If AdministratorAccess were pseudonymised, every IAM finding would
        # stop naming the thing that makes it a finding.
        out = redactor().apply(
            with_names(iam={
                "users": [{"name": "alice-admin", "attached_policies": ["AdministratorAccess"]}],
                "roles": [],
            })
        )
        assert out["collectors"]["iam"]["data"]["users"][0]["attached_policies"] == [
            "AdministratorAccess"
        ]

    def test_a_name_is_not_replaced_inside_a_longer_identifier(self) -> None:
        """The regression test for the bug that silently dropped four findings.

        An OU named `audit` was being substring-replaced inside
        `auditmanager.amazonaws.com`, and `security` inside
        `securityhub.amazonaws.com` — which emptied the list of services
        missing a delegated administrator and removed the finding entirely.
        """
        snapshot = with_names(
            organizations={
                "roots": [{
                    "organizational_units": [
                        {"name": "audit", "children": []},
                        {"name": "security", "children": []},
                        {"name": "distinctive-ou-name", "children": []},
                    ]
                }],
                "security_services_without_delegated_admin": [
                    "auditmanager.amazonaws.com",
                    "securityhub.amazonaws.com",
                ],
            }
        )
        out = redactor().apply(snapshot)
        services = out["collectors"]["organizations"]["data"][
            "security_services_without_delegated_admin"
        ]
        assert services == ["auditmanager.amazonaws.com", "securityhub.amazonaws.com"]

    def test_word_boundaries_prevent_partial_matches(self) -> None:
        r = redactor()
        r.apply(with_names(s3={"buckets": [{"name": "reports"}]}))
        # `reports` must not be rewritten inside `reports-archive`, which is a
        # different bucket that was never collected.
        assert r.text("reports-archive") == "reports-archive"
        assert r.text("reports") != "reports"

    def test_longest_name_wins(self) -> None:
        r = redactor()
        r.apply(with_names(s3={"buckets": [{"name": "logs-eu"}, {"name": "logs-eu-archive"}]}))
        out = r.text("logs-eu-archive")
        assert "logs-eu" not in out
        assert out == r._names["logs-eu-archive"]

    def test_generic_words_are_left_alone(self) -> None:
        r = redactor()
        r.apply(with_names(organizations={
            "roots": [{"organizational_units": [{"name": "production", "children": []}]}],
        }))
        assert r.text("production") == "production"
