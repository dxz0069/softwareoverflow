# VulnDB Submission: A-005 Coolify Docker image reference fields allow shell command injection during deployment

## Title

Coolify Docker image reference fields allow shell command injection during deployment

## Disclosure Status

Strict 0day candidate. No matching public GitHub issue, PR, advisory, CVE, or local issue-database disclosure was identified for this specific component and sink during this run.

## Affected Vendor / Product

- Vendor / Project: `coollabsio/coolify`
- Product / Component: see affected components below

## Affected Versions / Source Snapshot

- Verified version/snapshot: `v4.x current snapshot`
- Verified commit: `922950de591b`
- Local source path: `/tmp/vuln-src/coolify`

## Vulnerability Type

OS Command Injection

## Severity

Critical

## CWE

CWE-78 OS Command Injection; CWE-20 Improper Input Validation

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (suggested 9.1, permission-dependent)`

## Affected Components

- `Coolify deployment image parsing / Docker pull command construction`
- `Docker image reference fields`

## Summary

Coolify builds shell commands from Docker image reference fields. Shell metacharacters in an image name can break out of the intended docker pull command and execute arbitrary shell commands during deployment.

## Technical Details

1. Image reference fields are normalized into production image names.
2. The resulting value is embedded into a shell command string.
3. A payload such as alpine; printf ... starts a second shell command even when docker itself is unavailable.

## Exploitability Verification

- PoC command:

```bash
python3 /tmp/vuln-pocs/coolify_docker_image_shell_injection_poc.py
```

- Verification result: PoC forms docker pull alpine; printf ... and confirms executed=true with marker_content coolify-image-ci.
- Full rerun evidence: `/tmp/vuln-pocs/a_class_0day_rerun_20260515_124431.log`

## Proof of Concept

The PoC listed above is a minimal, local exploitability check for the vulnerable sink. It avoids destructive behavior and demonstrates the security boundary violation with marker files, loopback servers, or direct policy checks.

## Impact

A user able to control deployment image references can run commands with the Coolify deployment worker/server privileges, potentially compromising hosts, secrets, registries, and deployment infrastructure.

## 0day Deduplication

Local GitHub issue DB exact/pattern searches found no matching Coolify disclosure. Web searches for Coolify DockerImageParser/docker_registry_image_name/docker pull command injection did not identify a matching public advisory/issue during this run.

Additional exclusion rule used for this submission set: findings derived from public GitHub issues, public PRs, advisories, CVEs, or already-disclosed vulnerability reports were not counted as strict 0day items.

## Remediation

Never construct docker commands through shell strings. Use argument-array process execution, validate image references against OCI grammar, and reject shell metacharacters and whitespace/control characters.
