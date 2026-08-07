#!/usr/bin/env python3
"""Generate evidence/checkov-suppressions.md from the suppressions in infra/.

An undocumented `checkov:skip` is a disabled control that nobody decided to
disable. This regenerates the register from the source files themselves, so a
suppression added without a justification shows up as an empty cell rather than
disappearing into a clean scan result.

Exits non-zero if any suppression lacks a justification — the register is a
gate, not just a report.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_RE = re.compile(r"checkov:skip=([A-Z0-9_]+):(.*)")

HEADER = """# Checkov suppression register

Every `checkov:skip` in `infra/`, with the reasoning that justifies it.

An undocumented suppression is a disabled control that nobody decided to
disable. This file exists so each one can be re-argued at review time rather
than inherited — and so a reviewer can disagree with a specific line instead of
with a clean scan result.

Suppressions fall into two classes, and the distinction matters:

- **False positive** — the check misreads the construct (a permission boundary
  scored as a grant; a deny statement scored by its action list without its
  effect). Nothing is being accepted.
- **Deliberate deviation** — the check is correct about the general case and we
  are choosing otherwise, with a reason. These are risk acceptances and should
  be revisited when the context changes.
"""

FOOTER = """
## Deliberate deviations worth re-reading periodically

These are risk acceptances, not false positives.

- **`CKV2_AWS_27` (query logging off)** — logging every statement against Art. 9
  data would create a second copy of that data in a store with weaker access
  controls than the table it came from. A security benchmark and a privacy
  obligation genuinely conflict here; we resolved it toward privacy and
  compensated with pgaudit DDL/role logging plus slow-query logging.
- **`CKV_AWS_338` (90-day log retention, not one year)** — the same tension.
  Prompt logs may contain personal data, and GDPR Art. 5(1)(e) requires storage
  limitation. Long-term retention holds detections, not raw prompts.
- **`CKV_AWS_144` (no cross-region replication)** — data residency. Replicating
  Art. 9 data to a second region must be an explicit decision, never inherited
  from a module default.
- **`CKV2_AWS_57` (no automatic salt rotation)** — rotating a deterministic
  mask's salt changes every masked value and breaks joins against previously
  exported analytics. Rotation is an incident-response action with a re-masking
  plan (see `docs/01-threat-model.md`, branch 2a), not a scheduled job.
- **`CKV2_AWS_8` (no AWS Backup plan)** — the weakest justification in this file
  and the one most likely to be worth fixing. Automated backups, a mandatory
  final snapshot, and deletion protection are all in place, but cross-account
  backup isolation is a real gap rather than a false positive.
"""


def main() -> int:
    rows: list[tuple[str, int, str, str]] = []
    for path in sorted((REPO_ROOT / "infra").rglob("*.tf")):
        rel = path.relative_to(REPO_ROOT)
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = SKIP_RE.search(line)
            if match:
                rows.append((str(rel), lineno, match.group(1), match.group(2).strip()))

    unjustified = [r for r in rows if len(r[3]) < 20]

    lines = [HEADER, ""]
    lines.append(f"**{len(rows)} suppressions across {len({r[0] for r in rows})} files.**")
    lines += ["", "| Check | Location | Justification |", "|---|---|---|"]
    for path, lineno, check_id, reason in rows:
        safe = reason.replace("|", "\\|")
        lines.append(f"| `{check_id}` | `{path}:{lineno}` | {safe} |")
    lines.append(FOOTER)

    if unjustified:
        lines += ["## ⚠️ Unjustified suppressions", ""]
        lines += [f"- `{c}` at `{p}:{n}`" for p, n, c, _ in unjustified]
        lines.append("")

    out = REPO_ROOT / "evidence" / "checkov-suppressions.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")

    print(f"wrote {out.relative_to(REPO_ROOT)} — {len(rows)} suppressions")
    if unjustified:
        print(f"ERROR: {len(unjustified)} suppression(s) without a justification", file=sys.stderr)
        for path, lineno, check_id, _ in unjustified:
            print(f"  {check_id} at {path}:{lineno}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
