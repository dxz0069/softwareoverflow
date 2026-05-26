# VulnDB Submission: A-004 Langflow bundle URLs load remote custom components that execute code at startup

## Title

Langflow bundle URLs load remote custom components that execute code at startup

## Disclosure Status

Strict 0day candidate. No matching public GitHub issue, PR, advisory, CVE, or local issue-database disclosure was identified for this specific component and sink during this run.

## Affected Vendor / Product

- Vendor / Project: `langflow-ai/langflow`
- Product / Component: see affected components below

## Affected Versions / Source Snapshot

- Verified version/snapshot: `current main snapshot`
- Verified commit: `a4d875a9a1ac`
- Local source path: `/tmp/vuln-src/langflow`

## Vulnerability Type

Remote Code Execution / Untrusted Code Loading

## Severity

Critical

## CWE

CWE-94 Improper Control of Generation of Code; CWE-829 Inclusion of Functionality from Untrusted Control Sphere

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H (suggested 8.4; higher if bundle URLs are low-priv configurable)`

## Affected Components

- `Langflow bundle URL loading`
- `custom component discovery/import path`

## Summary

Langflow can load bundle URLs containing custom components and import/execute Python component code during startup or bundle processing. A configured remote bundle therefore becomes a code execution source.

## Technical Details

1. Bundle URL support fetches a remote archive or bundle-shaped content.
2. Custom component files inside the bundle are placed on component search paths.
3. Import/discovery of Python component code executes module-level code without a trust boundary or signature verification.

## Exploitability Verification

- PoC command:

```bash
python3 /tmp/vuln-pocs/langflow_bundle_custom_component_rce_poc.py
```

- Verification result: PoC creates a bundle-shaped ZIP containing a Python component and confirms executed=True with marker_content langflow-bundle-rce-poc.
- Full rerun evidence: `/tmp/vuln-pocs/a_class_0day_rerun_20260515_124431.log`

## Proof of Concept

The PoC listed above is a minimal, local exploitability check for the vulnerable sink. It avoids destructive behavior and demonstrates the security boundary violation with marker files, loopback servers, or direct policy checks.

## Impact

An attacker who can influence bundle URLs or a deployment template can execute arbitrary Python code in the Langflow server process, leading to full application compromise.

## 0day Deduplication

Local GitHub issue DB exact/pattern searches found no matching Langflow disclosure. Web exact searches for bundle_urls/load_bundles_from_urls/custom component startup RCE patterns did not identify a matching public advisory/issue during this run.

Additional exclusion rule used for this submission set: findings derived from public GitHub issues, public PRs, advisories, CVEs, or already-disclosed vulnerability reports were not counted as strict 0day items.

## Remediation

Do not auto-import remote custom component code. Require explicit trust approval, signatures or allowlists, sandbox component loading, and disable remote bundle URLs by default in production.
