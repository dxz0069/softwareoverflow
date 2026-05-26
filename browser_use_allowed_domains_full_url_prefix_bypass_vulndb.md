# VulnDB Submission: A-010 browser-use SecurityWatchdog full-URL allowed_domains raw prefix matching allows off-domain navigation bypass

## Title

browser-use SecurityWatchdog full-URL allowed_domains raw prefix matching allows off-domain navigation bypass

## Disclosure Status

Strict 0day candidate. No matching public GitHub issue, PR, advisory, CVE, or local issue-database disclosure was identified for this specific component and sink during this run.

## Affected Vendor / Product

- Vendor / Project: `browser-use/browser-use`
- Product / Component: see affected components below

## Affected Versions / Source Snapshot

- Verified version/snapshot: `0.12.6 current main snapshot`
- Verified commit: `933e28c599ddd74c15a48568f159da95547e40dd`
- Local source path: `/tmp/vuln-src/browser-use`

## Vulnerability Type

Authorization Bypass / URL Allowlist Bypass

## Severity

High

## CWE

CWE-284 Improper Access Control; CWE-20 Improper Input Validation; CWE-939 Improper Authorization in Handler for Custom URL Scheme

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N (suggested 8.1, depends on sensitive_data/authenticated profile use)`

## Affected Components

- `browser_use/browser/watchdogs/security_watchdog.py`
- `BrowserProfile.allowed_domains full URL pattern matching`

## Summary

browser-use SecurityWatchdog treats full URL allowed_domains patterns such as https://example.com as raw string prefixes. Attacker-controlled hosts whose URL string starts with that prefix are incorrectly allowed.

## Technical Details

1. allowed_domains documentation supports full URL entries such as https://example.com.
2. For non-glob full URL patterns, _is_url_match() returns true when url.startswith(pattern).
3. URLs like https://example.com.evil.local/ and https://example.com@evil.local/ have attacker hostnames but pass the raw prefix check.

## Exploitability Verification

- PoC command:

```bash
python3 /tmp/vuln-pocs/browser_use_allowed_domains_full_url_prefix_bypass_poc.py
```

- Verification result: PoC confirms SecurityWatchdog=True for evil_prefix_host and evil_userinfo_host while the hostname-based matcher rejects both.
- Full rerun evidence: `/tmp/vuln-pocs/a_class_0day_rerun_20260515_124431.log`

## Proof of Concept

The PoC listed above is a minimal, local exploitability check for the vulnerable sink. It avoids destructive behavior and demonstrates the security boundary violation with marker files, loopback servers, or direct policy checks.

## Impact

A prompt-injected agent or malicious page can bypass a user-configured navigation allowlist and move the browser to attacker-controlled domains. With sensitive_data or authenticated profiles this may leak credentials or page data.

## 0day Deduplication

Local GitHub issue DB found no browser-use entries. GitHub API and web searches for allowed_domains prefix/userinfo/full-URL bypass and SecurityWatchdog url.startswith(pattern) found public data:/blob: and redirect bypass issues plus related feature PRs, but no disclosure for this full-URL raw-prefix/userinfo host bypass.

Additional exclusion rule used for this submission set: findings derived from public GitHub issues, public PRs, advisories, CVEs, or already-disclosed vulnerability reports were not counted as strict 0day items.

## Remediation

Replace url.startswith(pattern) with parsed URL comparison. Compare scheme, hostname, port, and path semantics, or reuse the existing hostname-based match_url_with_domain_pattern implementation. Add tests for example.com.evil and example.com@evil.com.

