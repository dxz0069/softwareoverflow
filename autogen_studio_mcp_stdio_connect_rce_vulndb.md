# VulnDB Submission: A-007 AutoGen Studio MCP websocket accepts StdioServerParams and executes arbitrary local commands

## Title

AutoGen Studio MCP websocket accepts StdioServerParams and executes arbitrary local commands

## Disclosure Status

Strict 0day candidate. No matching public GitHub issue, PR, advisory, CVE, or local issue-database disclosure was identified for this specific component and sink during this run.

## Affected Vendor / Product

- Vendor / Project: `microsoft/autogen AutoGen Studio`
- Product / Component: see affected components below

## Affected Versions / Source Snapshot

- Verified version/snapshot: `current main snapshot`
- Verified commit: `027ecf0a379b`
- Local source path: `/tmp/vuln-src/autogen`

## Vulnerability Type

Remote Code Execution / Unsafe MCP Stdio Launch

## Severity

Critical

## CWE

CWE-78 OS Command Injection; CWE-862 Missing Authorization; CWE-20 Improper Input Validation

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (suggested 9.1; unauth deployments 10.0)`

## Affected Components

- `AutoGen Studio MCP websocket connect route`
- `StdioServerParams handling`

## Summary

AutoGen Studio accepts MCP connection parameters over a websocket/API path and allows StdioServerParams with arbitrary command and args. Connecting such a server launches a local process.

## Technical Details

1. The MCP connect flow accepts a parameter object identifying stdio transport.
2. The object contains command and args controlled by the caller.
3. The server constructs stdio MCP transport and spawns the specified command.

## Exploitability Verification

- PoC command:

```bash
python3 /tmp/vuln-pocs/autogen_studio_mcp_stdio_connect_rce_poc.py
```

- Verification result: PoC supplies command sh with args writing a marker and confirms returncode=0, executed=True, marker_content autogen-studio-mcp-stdio-rce.
- Full rerun evidence: `/tmp/vuln-pocs/a_class_0day_rerun_20260515_124431.log`

## Proof of Concept

The PoC listed above is a minimal, local exploitability check for the vulnerable sink. It avoids destructive behavior and demonstrates the security boundary violation with marker files, loopback servers, or direct policy checks.

## Impact

A user or attacker with access to the AutoGen Studio MCP connect surface can execute arbitrary commands with the Studio process privileges. In unauthenticated or weakly protected deployments this becomes remote server compromise.

## 0day Deduplication

Local GitHub issue DB and web searches found no matching AutoGen Studio disclosure for MCP StdioServerParams route RCE during this run.

Additional exclusion rule used for this submission set: findings derived from public GitHub issues, public PRs, advisories, CVEs, or already-disclosed vulnerability reports were not counted as strict 0day items.

## Remediation

Do not expose stdio MCP creation to untrusted clients. Allow only network MCP transports for user input, require admin-only allowlists for local commands, and add explicit authorization/audit prompts.
