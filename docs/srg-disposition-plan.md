# SRG V2R4 — disposition plan (REVISED: validate-don't-inherit)

Totals: alternative 3 · implemented 150 · inherited 30 · not-applicable 5

Per the steer to maximize actual checks: AUTH/IDENTITY (IAM), AUDIT (CloudTrail), CRYPTO (ECR KMS/TLS), PATCH-image (finding-gate/lifecycle), and BUILD/SIGN (signature+SBOM) are **implemented**; only the AWS-managed microVM runtime + platform internals stay **inherited**; banner/task-def **N/A**; ISSM/org-governance **attestation**.

- **AUTH/IDENTITY** — `implemented` (54)
- **AUDIT** — `implemented` (58)
- **CRYPTO** — `implemented` (22)
- **PATCH(image)** — `implemented` (4)
- **RUNTIME** — `inherited` (8)
- **PLATFORM** — `inherited` (22)
- **BANNER** — `not-applicable` (3)
- **TASK-DEF** — `not-applicable` (2)
- **GOVERNANCE** — `alternative` (3)
