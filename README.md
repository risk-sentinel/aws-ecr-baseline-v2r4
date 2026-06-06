# aws-ecr-baseline-v2r4

Tier-2 InSpec baseline implementing the **DISA Container Platform Security
Requirements Guide (SRG) V2R4** (all 188 requirements), tailored for the AWS
container platform. Amazon ECR is the primary automated-coverage focus.

## How it was built

Scaffolded from the SRG XCCDF with MITRE SAF
([`saf generate inspec_profile`](https://saf-cli.mitre.org/#inspec-profile)) —
the same stub-from-XCCDF approach used for the CIS profiles
(`tools/xccdf_to_inspec/scaffold.py`). Control IDs preserve the SRG
`SRG-APP-…-CTR-…` keys for 1:1 traceability (CCI + NIST 800-53 carried per
control), then each control is **tailored** per the AWS shared-responsibility
model — nothing is cherry-picked out; every requirement is dispositioned.

## Disposition taxonomy (`implementation_status`)

| Status | Meaning |
|---|---|
| `implemented` | Asserted against AWS (Amazon ECR registry posture) |
| `inherited` | Satisfied by the AWS-managed runtime / host / control plane (FedRAMP/DoD ATO); passes with evidence |
| `not-applicable` | Out of scope for this deployment (rendered N/A with rationale) |
| `alternative` | Governance/operational fact → SAF attestation |

## Scope

- **Account-wide ECR** assessment + registry-level configuration. Stands alone:
  `aws-ecs-fargate-baseline` separately re-validates the registry posture of the
  repos backing *its own* workloads (intentional overlap; each profile stands alone).
- Runtime/host requirements that aren't AWS-inherited are also covered in
  `cis-docker-v1.8.0`; orchestrator/workload in `aws-ecs-fargate-baseline`.

See [`docs/srg-v2r4-coverage-mapping.md`](docs/srg-v2r4-coverage-mapping.md) for the
full SRG → layer mapping and the registry control families.

## Status

Skeleton seeded from the SRG stub (188 controls, SRG-native IDs + metadata).
Tailoring is in progress — see the tracking issue. Validate locally:

```bash
docker run --rm -v "$PWD:/work" -w /work risksentinel/sparc-auditor:<tag> check .
docker run --rm -v "$PWD:/work" -w /work risksentinel/sparc-auditor:<tag> json .
# exec requires AWS credentials (-t aws://) and read-only ECR grants
```
