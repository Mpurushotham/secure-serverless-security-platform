# `@ssp/cdk-security`

CDK Aspects that enforce security invariants at synth time. One copy, shared by every CDK app in
this repository.

| Aspect | Fails synth when |
|---|---|
| `NoWildcardIamAspect` | An **Allow** statement uses `Action: "*"`, `service:*`, or `Resource: "*"`, in a managed policy, an attached policy, **or an inline policy on a role** |
| `RequirePermissionBoundaryAspect` | A role has no permissions boundary — and then applies one, rather than only complaining |
| `RequireLogRetentionAspect` | A log group has no retention, or retains past the ceiling for its data class |
| `RequireVpcAttachmentAspect` | A Lambda with access to regulated data has unrestricted egress |

## Why this is a package and not a file

The Aspects used to live in `infra/cdk/lib/aspects/security-aspects.ts`. Two CDK apps now need
them. Copying the file would have been faster and would have been wrong: two copies of a security
control is two controls, and the second one is always the one nobody updated.

That path still exists and re-exports from here, so nothing that imported it had to change.

## Why the repository root has a `package.json`

Every Aspect dispatches on `instanceof`:

```ts
if (!(node instanceof iam.CfnPolicy || node instanceof iam.CfnManagedPolicy)) return;
```

`instanceof` compares constructor identity, not shape. If this package and the app consuming it
ever resolve to **different copies** of `aws-cdk-lib` or `constructs` — trivially easy to cause with
a nested `node_modules`, a bare `file:` dependency, or a version conflict — every one of those
checks returns `false`. The Aspects then visit every node in the tree, match nothing, raise nothing,
and synth goes green.

That is the worst failure mode a control can have. It does not break; it **evaporates**. The
invariant tests keep passing, because they assert on the template, and the template is fine — the
Aspect simply never looked at it.

npm workspaces at the repo root fix this by construction: one hoisted `aws-cdk-lib`, one hoisted
`constructs`, one identity for every class. Install from the root, not from a workspace directory:

```bash
npm install          # at the repository root
npm ci               # in CI, at the repository root
```

## The tests are the point

`test/aspects-fire.test.ts` does not check that a compliant stack synthesises cleanly — a stack with
no Aspects at all would also do that. Each test builds a construct that **must** be rejected and
asserts the rejection.

If the packaging hazard above ever recurs, these tests fail while every other check in the
repository stays green. That is the only signal that distinguishes "the controls passed" from "the
controls were never consulted".

```bash
cd platform/lib/cdk-security && npx jest
```

## A gap these tests found

The first version of `NoWildcardIamAspect` matched only `CfnPolicy` and `CfnManagedPolicy` — the
shapes produced by `grant*()` and `addToPolicy()`. A policy document passed straight into the
constructor:

```ts
new iam.Role(this, "R", {
  assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
  inlinePolicies: { admin: /* Action: "*", Resource: "*" */ },
});
```

is emitted **inside** the `AWS::IAM::Role` resource and never becomes a `CfnPolicy` node at all. The
Aspect visited it, matched nothing, and reported success — a bypass reachable by accident, through
the most obvious API in the library.

It was caught by writing a test that asked the Aspect to prove it fires, rather than reading a clean
synth as evidence. `CfnRole.policies` is now inspected as well.

One implementation note worth keeping: `Stack.resolve(node.policies)` returns the CDK **prop** shape
(`policyDocument`), not the rendered CloudFormation shape (`PolicyDocument`). Both are accepted,
since the CFN casing is what appears when a role is built with escape hatches or raw overrides.
