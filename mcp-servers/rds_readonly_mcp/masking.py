"""PII classification for schema introspection.

Masking itself happens in the database (see `sql/02-masked-views.sql`) — by the
time a value reaches Python it has already crossed the network and landed in a
buffer, so Python is the wrong place to start protecting it.

What this module does is *classify*: when the agent introspects a table, each
column is tagged with a sensitivity class and a regulatory basis. Two reasons
that matters, neither cosmetic:

  1. The model sees which columns are sensitive and why, so its generated
     queries avoid them by construction rather than by refusal-and-retry.
  2. The classification is the input to the Art. 30 record — you cannot
     document what categories of data are processed if nothing labels them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class Sensitivity(StrEnum):
    # GDPR Art. 9 special category — health, biometrics, etc. Highest bar.
    SPECIAL_CATEGORY = "special_category"
    # Directly identifying: name, national ID, email, phone.
    DIRECT_IDENTIFIER = "direct_identifier"
    # Alone it identifies nobody; combined with two others it often does.
    QUASI_IDENTIFIER = "quasi_identifier"
    NON_SENSITIVE = "non_sensitive"


@dataclass(frozen=True)
class ColumnClassification:
    column: str
    sensitivity: Sensitivity
    basis: str


# Ordered: first match wins, most sensitive patterns first.
_RULES: list[tuple[re.Pattern[str], Sensitivity, str]] = [
    (
        re.compile(r"(medication|diagnos|prescri|dosage|health|patient|icd|atc)", re.I),
        Sensitivity.SPECIAL_CATEGORY,
        "GDPR Art. 9(1) — data concerning health",
    ),
    (
        re.compile(r"(personnummer|national_id|ssn|nin|passport)", re.I),
        Sensitivity.DIRECT_IDENTIFIER,
        "GDPR Art. 4(1) — national identification number",
    ),
    (
        re.compile(r"(email|e_mail|phone|mobile|full_name|lastname|surname|address|street)", re.I),
        Sensitivity.DIRECT_IDENTIFIER,
        "GDPR Art. 4(1) — directly identifying personal data",
    ),
    (
        re.compile(r"(hsa_id|prescriber|practitioner|clinician)", re.I),
        Sensitivity.DIRECT_IDENTIFIER,
        "GDPR Art. 4(1) — identifies the prescribing practitioner",
    ),
    (
        re.compile(r"(postal|zip|city|birth|dob|gender|age)", re.I),
        Sensitivity.QUASI_IDENTIFIER,
        "Re-identification risk in combination (k-anonymity)",
    ),
    (
        re.compile(r"(consent)", re.I),
        Sensitivity.QUASI_IDENTIFIER,
        "Lawful-basis flag — readable value becomes an oracle for filtered rows",
    ),
]


def classify_column(name: str) -> ColumnClassification:
    for pattern, sensitivity, basis in _RULES:
        if pattern.search(name):
            return ColumnClassification(name, sensitivity, basis)
    return ColumnClassification(name, Sensitivity.NON_SENSITIVE, "no rule matched")


def classify_columns(names: list[str]) -> list[ColumnClassification]:
    return [classify_column(n) for n in names]


def summarise(classifications: list[ColumnClassification]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for c in classifications:
        counts[c.sensitivity.value] = counts.get(c.sensitivity.value, 0) + 1
    return counts
