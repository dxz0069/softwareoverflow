# VulnDB Submission: A-002 n8n Instance AI remote workspace filesystem tools forward absolute and traversal paths outside intended workspace root

## Title

n8n Instance AI remote workspace filesystem tools forward absolute and traversal paths outside intended workspace root

## Disclosure Status

Strict 0day candidate. No matching public GitHub issue, PR, advisory, CVE, or local issue-database disclosure was identified for this specific component and sink during this run.

## Affected Vendor / Product

- Vendor / Project: `n8n-io/n8n`
- Product / Component: see affected components below

## Affected Versions / Source Snapshot

- Verified version/snapshot: `2.21.0 current master snapshot`
- Verified commit: `6362afe4`
- Local source path: `/tmp/vuln-src/n8n`

## Vulnerability Type

Path Traversal / Workspace Sandbox Escape

## Severity

High

## CWE

CWE-22 Improper Limitation of a Pathname to a Restricted Directory; CWE-863 Incorrect Authorization

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L (suggested 8.8, sandbox-provider-permission dependent)`

## Affected Components

- `packages/@n8n/nodes-langchain/utils/agents`
- `N8nSandboxFilesystem / DaytonaFilesystem workspace file tools`

## Summary

n8n Instance AI remote workspace file tools forward absolute paths and ../ traversal paths to the remote workspace backend instead of enforcing a local workspace-root containment policy. The safer helper rejects traversal, but adapter-like forwarding paths preserve attacker-controlled path strings.

## Technical Details

1. Workspace file operations accept path strings from the agent/tool layer.
2. The vulnerable forwarding path sends ../outside.txt and /etc/poc to createFolder/uploadFile style backend calls.
3. The intended safe helper rejects traversal, demonstrating a missing enforcement point in the adapter path.

## Exploitability Verification

- PoC command:

```bash
node /tmp/vuln-pocs/n8n_workspace_adapter_forwarding_poc.js
```

- Verification result: PoC shows safeHelperResult=traversal rejected while forwardedTraversalCalls and forwardedAbsoluteCalls still contain ../outside.txt and /etc/poc.
- Full rerun evidence: `/tmp/vuln-pocs/a_class_0day_rerun_20260515_124431.log`

## Proof of Concept

The PoC listed above is a minimal, local exploitability check for the vulnerable sink. It avoids destructive behavior and demonstrates the security boundary violation with marker files, loopback servers, or direct policy checks.

## Impact

A workflow/agent path input can escape the intended workspace namespace in the remote provider, causing unauthorized file writes or reads depending on backend permissions and mounted workspace layout.

## 0day Deduplication

Local GitHub issue DB searches for N8nSandboxFilesystem/DaytonaFilesystem/workspace_write_file/path traversal/containment found no matching n8n disclosure. Web exact searches did not identify a matching public advisory/issue during this run.

Additional exclusion rule used for this submission set: findings derived from public GitHub issues, public PRs, advisories, CVEs, or already-disclosed vulnerability reports were not counted as strict 0day items.

## Remediation

Centralize workspace path validation before every backend call. Reject absolute paths, traversal, symlinks outside root, and provider-specific path escapes. Add tests proving all adapters reject ../ and absolute paths.
