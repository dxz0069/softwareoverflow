# VulnDB Submission: A-003 Activepieces FILE property URL processor uses raw fetch allowing engine-side SSRF



## Title

Activepieces FILE property URL processor uses raw fetch allowing engine-side SSRF

## Disclosure Status

Strict 0day candidate. No matching public GitHub issue, PR, advisory, CVE, or local issue-database disclosure was identified for this specific component and sink during this run.

## Affected Vendor / Product

- Vendor / Project: `activepieces/activepieces`
- Product / Component: see affected components below

## Affected Versions / Source Snapshot

- Verified version/snapshot: `current main snapshot`
- Verified commit: `local f693883e4de4; origin/main ed219c9e7db3`
- Local source path: `/tmp/vuln-src/activepieces`

## Vulnerability Type

Server-Side Request Forgery (SSRF)

## Severity

High

## CWE

CWE-918 Server-Side Request Forgery

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N (suggested 8.1, deployment-dependent)`

## Affected Components

- `packages/server/engine/src/lib/variables/processors/file.ts`
- `Property.File URL processor / handleUrlFile`

## Summary

Activepieces processes FILE property URL values with raw global fetch(path). A workflow user or AI/tool-generated input can make the engine fetch loopback, private network, or metadata URLs from the worker context.

## Technical Details

1. Property.File accepts data URI or URL-like values.
2. For URL values the processor uses fetch(path) directly.
3. The engine SSRF guard is not applied at this file URL processing sink.

## Exploitability Verification

- PoC command:

```bash
node /tmp/vuln-pocs/activepieces_file_processor_ssrf_poc.js
```

- Verification result: PoC starts a loopback server, passes its URL into the file processor logic, and confirms reachedLoopback=true with body activepieces-ssrf-poc:/metadata.
- Full rerun evidence: `/tmp/vuln-pocs/a_class_0day_rerun_20260515_124431.log`

## Proof of Concept

The PoC listed above is a minimal, local exploitability check for the vulnerable sink. It avoids destructive behavior and demonstrates the security boundary violation with marker files, loopback servers, or direct policy checks.

## Impact

The engine can be coerced into reaching localhost, RFC1918, link-local, and cloud metadata endpoints. Returned bytes may become an ApFile and flow to later actions, AI prompts, logs, or outbound integrations.

## 0day Deduplication

Local GitHub issue DB exact/pattern searches found no matching Activepieces disclosure. Web exact searches for fileProcessor/handleUrlFile/Property.File SSRF patterns did not identify a matching public advisory/issue during this run.

Additional exclusion rule used for this submission set: findings derived from public GitHub issues, public PRs, advisories, CVEs, or already-disclosed vulnerability reports were not counted as strict 0day items.

## Remediation

Route FILE URL downloads through the same SSRF-safe client/guard used by the engine network layer. Reject unsafe schemes and private/link-local/loopback targets, revalidate redirects, and enforce time/size limits.

