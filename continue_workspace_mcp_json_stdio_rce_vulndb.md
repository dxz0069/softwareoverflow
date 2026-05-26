# VulnDB Submission: A-009 Continue workspace .continue/mcpServers JSON auto-load can execute arbitrary local stdio MCP commands

## Title

Continue workspace .continue/mcpServers JSON auto-load can execute arbitrary local stdio MCP commands

## Disclosure Status

Strict 0day candidate. No matching public GitHub issue, PR, advisory, CVE, or local issue-database disclosure was identified for this specific component and sink during this run.

## Affected Vendor / Product

- Vendor / Project: `continuedev/continue`
- Product / Component: see affected components below

## Affected Versions / Source Snapshot

- Verified version/snapshot: `current main snapshot`
- Verified commit: `cb273098d968`
- Local source path: `/tmp/vuln-src/continue`

## Vulnerability Type

Local Code Execution via Workspace Configuration

## Severity

Critical

## CWE

CWE-94 Improper Control of Generation of Code; CWE-78 OS Command Injection; CWE-829 Inclusion of Functionality from Untrusted Control Sphere

## CVSS

`CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H (suggested 8.6; remote if attacker can plant workspace files through repo/archive/open-folder flow)`

## Affected Components

- `core/context/mcp/json/loadJsonMcpConfigs.ts`
- `packages/config-yaml MCP JSON schema`
- `core/context/mcp/MCPConnection.ts`

## Summary

Continue loads workspace-controlled .continue/mcpServers JSON files. A malicious workspace can define a stdio MCP server with arbitrary command and args, which is later launched locally by StdioClientTransport.

## Technical Details

1. The config loader scans workspace .continue/mcpServers/*.json.
2. The JSON schema accepts type=stdio with command, args, env, and cwd-like options.
3. Config refresh passes those options into MCPConnection, which constructs StdioClientTransport and starts the process.

## Exploitability Verification

- PoC command:

```bash
node /tmp/vuln-pocs/continue_workspace_mcp_json_stdio_rce_poc.js
```

- Verification result: PoC writes .continue/mcpServers/evil.json and confirms acceptedBySchema=true, exitStatus=0, markerExists=true, markerContent continue-mcp-stdio-rce.
- Full rerun evidence: `/tmp/vuln-pocs/a_class_0day_rerun_20260515_124431.log`

## Proof of Concept

The PoC listed above is a minimal, local exploitability check for the vulnerable sink. It avoids destructive behavior and demonstrates the security boundary violation with marker files, loopback servers, or direct policy checks.

## Impact

A malicious repository, template, archive, or synced workspace can execute code on a developer workstation when opened or reloaded with Continue MCP enabled, exposing source code and local secrets.

## 0day Deduplication

Local GitHub issue DB searches and GitHub API searches for Continue workspace mcpServers stdio command execution/RCE found no matching security disclosure. Results were normal MCP usability issues and feature PRs, not workspace-file-to-command-execution.

Additional exclusion rule used for this submission set: findings derived from public GitHub issues, public PRs, advisories, CVEs, or already-disclosed vulnerability reports were not counted as strict 0day items.

## Remediation

Do not auto-execute workspace stdio MCP configs. Require explicit per-workspace trust, show command/args/env before launch, default-disable stdio from workspace files, and support signed/allowlisted MCP servers.
