# Container Platform SRG V2R4 → coverage mapping

**Anchor:** DISA *Container Platform Security Requirements Guide* V2R4
(`U_Container_Platform_SRG_V2R4_Manual-xccdf.xml`, 188 requirements).

**Principle:** the SRG describes a whole *container platform*; its requirements fall on
three distinct layers, and the SRG itself separates them (it has explicit "registry",
"runtime", and "platform/orchestrator" requirements). We assess each layer in the profile
that owns that resource, rather than forcing all of it into one place:

| Layer | Profile | Owns |
|---|---|---|
| **Registry (resource)** | **`aws-ecr-baseline-v2r4`** (this repo) | the registry/image-supply requirements — account-wide |
| **Runtime / host** | `cis-docker-v1.8.0` | container runtime & host isolation (privileges, caps, seccomp, read-only, root, namespaces) |
| **Workload / orchestrator** | `aws-ecs-fargate-baseline` | image *instantiation* least-privilege, task secrets/networking, workload-scoped supply-chain (EF-1.1/1.2) |

Cross-cutting families (auth/RBAC, logging/audit, network/crypto, secrets) are sliced to
the layer whose control surface they touch — much of the account-level auth/logging slice
is already covered by `cis-aws-foundations-v7.0.0` (IAM, CloudTrail) and the secret-store
slice by `aws-secrets-baseline`.

## SRG theme distribution (188 rules)

First-match keyword buckets (indicative, not the final assignment):
registry/image **19** · runtime/isolation 34 · auth/RBAC 47 · logging/audit 33 · secrets 19
· network/crypto 15 · other 21.

Three of the 19 "registry" keyword hits are actually **runtime/cross-cutting** and are
reassigned out of this repo: `CTR-000775` (images execute least privilege → workload/runtime),
`CTR-000885` (runtime prohibits unauthorized instantiation → workload/runtime),
`CTR-000810` (audit-storage warning → cross-cutting logging). **True registry layer = 16
CTR requirements**, specified below as this repo's build scope.

---

## Registry layer — `aws-ecr-baseline-v2r4` build spec

Triple-anchor provenance per control: **SRG-APP-…-CTR + CCI + NIST 800-53 (via CCI) +
FSBP (ECR.x)**, consistent with the ecs-fargate / secrets baselines. Account-wide scope
(every in-account ECR repository + the registry-level configuration), with consumer
scoping via inputs (`applicable_partitions`, an `assessed_repositories` allow/deny, etc.)
and **fail-closed** defaults. Where AWS exposes no API for a requirement (e.g. signing
infrastructure outside ECR), use a SAF attestation, not a fabricated check.

| Family | SRG-CTR (CCI) | Check | InSpec resource | FSBP | Status today |
|---|---|---|---|---|---|
| **ECR-1 Automated scanning** | CTR-001335 (CCI-000366), CTR-001010 (CCI-001067), CTR-001125 (CCI-002605) | scan-on-push per repo + registry enhanced (Inspector) scanning enabled | `aws_ecr_repository.image_scanning_configuration`, `aws_ecr_registry_scanning` | ECR.1 | EF-1.3 **stubbed** → relocate |
| **ECR-2 Vulnerability gate** | CTR-001125 (CCI-002605), CTR-001335 | no image carries findings above tolerated severity (RA-5/SI-2) | `aws_ecr_image.image_scan_findings` | — | EF-1.7 **stubbed** → relocate |
| **ECR-3 Tag immutability** | CTR-000890 (CCI-003980) | repository tag mutability = IMMUTABLE | `aws_ecr_repository.image_tag_mutability` | ECR.2 | EF-1.4 **stubbed** → relocate |
| **ECR-4 Signing & verification** | CTR-000285 (CCI-003992), CTR-001385 (CCI-000803, FIPS SHA-2), CTR-000300 (CCI-001499/004909, trust anchors) | images are signed (cosign/notation), signature digest is SHA-2+, only approved trust anchors honored | image referrers/manifest (custom) or **SAF attestation** if signing infra is API-opaque | — | **not covered anywhere** |
| **ECR-5 Registry & repo permissions** | CTR-000090 (CCI-000213), CTR-000290 (CCI-001499/004192), CTR-000920 (CCI-001774) | least-privilege repo policy; deny-all / permit-by-exception; no public or unintended cross-account access | `aws_ecr_repository.repository_policy_text`, registry policy, public-repo check | — | **gap** |
| **ECR-6 Lifecycle & content** | CTR-001115 (CCI-002617), CTR-000320 (CCI-000381/004922), CTR-001330 (CCI-000366) | lifecycle policy prunes old/untagged images; only required images present | `aws_ecr_repository.lifecycle_policy_text` + image inventory | — | **gap** |
| **ECR-7 Encryption at rest** | (NIST SC-28; no direct CTR — derived) | repository encrypted with a KMS CMK (not just AES256) | `aws_ecr_repository.encryption_configuration` | — | **gap** |
| **ECR-8 Transport security** | CTR-000035 (CCI-000068, TLS 1.2+), CTR-001380 (CCI-000185, cert validation) | ECR enforces TLS (AWS-managed → inherited/attested); assert ECR `api`+`dkr` VPC interface endpoints keep pulls on the private network | `aws_vpc_endpoints` / cross-ref | — | inherited/attest |
| **ECR-9 Registry audit logging** | CTR-000220 (CCI-000154/004061) | ECR API actions captured by CloudTrail and shipped centrally | cross-ref `cis-aws-foundations` CloudTrail controls | — | partial (foundations) |

### Required custom resources (new in this repo)
- `aws_ecr_repository` — scan config, tag mutability, encryption, repository policy, lifecycle policy (per-repo).
- `aws_ecr_repositories` — account-wide enumeration (the scope source).
- `aws_ecr_image` — per-image scan findings (severity counts).
- `aws_ecr_registry_scanning` — registry-level enhanced/basic scanning configuration + registry policy.

These resolve via the AWS SDK (`aws-sdk-ecr`) — confirm the gem is in the scanner image
(`risksentinel/sparc-auditor`); `aws-sdk-ec2`/`cloudwatchlogs` are present, ECR likely is too.

### Scanner-role IAM (read-only)
`ecr:DescribeRepositories`, `ecr:GetRepositoryPolicy`, `ecr:GetLifecyclePolicy`,
`ecr:DescribeImages`, `ecr:DescribeImageScanFindings`, `ecr:GetRegistryScanningConfiguration`,
`ecr:GetRegistryPolicy` — to be added to the scanner role (sparc-iac), analogous to #368.

---

## Fargate stub resolution
`aws-ecs-fargate-baseline` EF-1.3 / EF-1.4 / EF-1.7 call `aws_ecr_repository` /
`aws_ecr_image` resources that are **not defined** (not custom there, not in stock
inspec-aws) → they error at exec (the profile was static-validated only). The SRG frames
these as **registry** requirements (`CTR-000890`, `CTR-001125`), so they move here as
ECR-1/2/3. Fargate **keeps EF-1.1 (digest pinning) + EF-1.2 (trusted registries)** —
genuine *workload* supply-chain checks against the task definition — and **defers registry
posture to this repo**, removing the stub instead of patching it into the wrong layer.

## Out of scope for this repo (assigned to other layers — first pass)
- Runtime/isolation (CTR runtime rules incl. -000775/-000885) → `cis-docker` + Fargate task-def runtime checks.
- Account auth/RBAC + CloudTrail logging → `cis-aws-foundations`.
- Secret store hardening → `aws-secrets-baseline`.

The full docker/fargate SRG re-anchoring is a follow-up mapping pass; this document
specifies the **registry layer** in build-ready detail.
