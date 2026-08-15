# Plan-time assertions.
#
# `terraform validate` proves the configuration parses. It says nothing about
# whether the configuration is *effective*, and the two failures this module
# exists to fix are both effectiveness failures: a policy attached where no
# account sits, and security services administered from the account no policy
# can constrain.
#
# `check` blocks report during plan without blocking apply, which is the right
# strength here — these are judgements about the shape of an organization, and
# a reviewer may have a reason. `precondition` is used instead where the
# configuration would be actively wrong.

# ---------------------------------------------------------------------------
# Delegated administration must not point back at the management account
# ---------------------------------------------------------------------------

check "delegated_admin_is_not_the_management_account" {
  assert {
    # anytrue() rather than a parenthesised `a || b` spanning lines: checkov's
    # HCL parser cannot read that form, and it fails by reporting one parsing
    # error and running ZERO checks on the file — a scanner that silently
    # covers nothing, which is worse than one that fails loudly. See the
    # parsing-error gate in the Makefile.
    condition = anytrue([
      !var.delegate_security_services,
      local.security_account_id != data.aws_organizations_organization.this.master_account_id,
    ])
    error_message = join(" ", [
      "security_tooling_account_id is unset, so delegated administration would",
      "point at the management account — which is where the services already",
      "are. This is finding ORG-001 restated, not fixed. Create a dedicated",
      "security-tooling account and set the variable, or set",
      "delegate_security_services = false and record why.",
    ])
  }
}

# ---------------------------------------------------------------------------
# Every policy must actually be attached to something
# ---------------------------------------------------------------------------

check "every_scp_has_a_target" {
  assert {
    condition = length([
      for name, policy in var.service_control_policies : name
      if length(policy.targets) == 0
    ]) == 0
    error_message = join(" ", [
      "These SCPs have no attachment target and would constrain nothing:",
      join(", ", [
        for name, policy in var.service_control_policies : name
        if length(policy.targets) == 0
      ]),
    ])
  }
}

check "every_rcp_has_a_target" {
  assert {
    condition = length([
      for name, policy in var.resource_control_policies : name
      if length(policy.targets) == 0
    ]) == 0
    error_message = join(" ", [
      "These RCPs have no attachment target and would constrain nothing:",
      join(", ", [
        for name, policy in var.resource_control_policies : name
        if length(policy.targets) == 0
      ]),
    ])
  }
}

# ---------------------------------------------------------------------------
# Root-only attachment leaves the management account uncovered
# ---------------------------------------------------------------------------

# Not an error — attaching at the root is often correct, because it covers every
# member account including ones created later. The point is that "attached at
# the root" reads like "covers everything" and does not: the management account
# is exempt from SCPs entirely. Surfacing it during plan is the only reliable
# moment to say so.
check "root_attached_policies_do_not_cover_the_management_account" {
  assert {
    condition = anytrue([
      var.acknowledge_management_account_exemption,
      length([
        for name, policy in var.service_control_policies : name
        if alltrue([for t in policy.targets : startswith(t, "r-")])
      ]) == 0,
    ])

    error_message = join(" ", [
      "These SCPs are attached only at the organization root:",
      join(", ", [
        for name, policy in var.service_control_policies : name
        if alltrue([for t in policy.targets : startswith(t, "r-")])
      ]),
      "— SCPs never apply to the management account, so none of them constrains",
      "the account that can create accounts, detach policies and leave the",
      "organization. This is ORG-003. There is no SCP that fixes it; the",
      "treatment is to run no workloads in the management account. Set",
      "acknowledge_management_account_exemption = true once that is understood.",
    ])
  }
}
