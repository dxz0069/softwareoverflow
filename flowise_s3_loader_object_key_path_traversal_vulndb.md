# VulnDB Submission: A-001 Flowise S3 document loaders object-key path traversal leading to arbitrary local file write and unsafe recursive cleanup

## Title

Flowise S3 document loaders object-key path traversal leading to arbitrary local file write and unsafe recursive cleanup

## Disclosure Status

Strict 0day candidate. No matching public GitHub issue, PR, advisory, CVE, or local issue-database disclosure was identified for this specific component and sink during this run.

## Affected Vendor / Product

- Vendor / Project: `FlowiseAI/Flowise`
- Product / Component: see affected components below

## Affected Versions / Source Snapshot

- Verified version/snapshot: `3.1.2 current main snapshot`
- Verified commit: `9ae635b`
- Local source path: `/tmp/vuln-src/flowise`

## Vulnerability Type

Path Traversal / Arbitrary Local File Write / Unsafe Cleanup

## Severity

High

## CWE

CWE-22 Improper Limitation of a Pathname to a Restricted Directory; CWE-73 External Control of File Name or Path

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H (suggested 8.1, deployment-dependent)`

## Affected Components

- `packages/components/nodes/documentloaders/S3/S3.ts`
- `S3Directory / S3File document loader temporary-file handling`

## Summary

Flowise S3 document loaders derive local temporary file paths from attacker-controlled S3 object keys without constraining them to the intended temporary directory. Object keys containing traversal sequences can escape the loader temp directory, write arbitrary local files, and may also influence recursive cleanup behavior.

## Technical Details

1. The loader joins or resolves object-key-derived names into a local temporary path used before document parsing.
2. The key is externally controlled through S3 bucket contents or a configured S3-compatible object store.
3. No final path containment check ensures the resolved path remains below the intended temp directory before write/cleanup.

## Exploitability Verification

- PoC command:

```bash
node /tmp/vuln-pocs/flowise_s3_loader_poc.js
```

- Verification result: PoC writes ../flowise-s3-loader-vulndb-poc.txt outside the temp directory and confirms escaped=true, exists=true, and marker content flowise-s3-loader-vulndb-poc.
- Full rerun evidence: `/tmp/vuln-pocs/a_class_0day_rerun_20260515_124431.log`

## Proof of Concept

The PoC listed above is a minimal, local exploitability check for the vulnerable sink. It avoids destructive behavior and demonstrates the security boundary violation with marker files, loopback servers, or direct policy checks.

## Impact

A user able to influence object keys in a configured S3 source can cause Flowise to write files outside the loader workspace. Depending on process permissions and cleanup path, this can corrupt application files, create attacker-controlled files, or delete unintended paths.

## 0day Deduplication

Local GitHub issue DB exact/pattern searches found no matching Flowise disclosure. Web exact searches for Flowise S3Directory/S3File s3fileloader/path traversal patterns did not identify a matching public advisory/issue during this run.

Additional exclusion rule used for this submission set: findings derived from public GitHub issues, public PRs, advisories, CVEs, or already-disclosed vulnerability reports were not counted as strict 0day items.

## Remediation

Normalize each object key to a safe basename or explicitly reject absolute/traversal paths. After joining paths, resolve both base and target and enforce target.relative_to(base). Avoid recursive cleanup on paths influenced by untrusted object names.
