# VulnDB Submission: A-006 Open WebUI get_image_data follows redirects after URL validation causing SSRF

## Title

Open WebUI get_image_data follows redirects after URL validation causing SSRF

## Disclosure Status

Strict 0day candidate. No matching public GitHub issue, PR, advisory, CVE, or local issue-database disclosure was identified for this specific component and sink during this run.

## Affected Vendor / Product

- Vendor / Project: `open-webui/open-webui`
- Product / Component: see affected components below

## Affected Versions / Source Snapshot

- Verified version/snapshot: `current main snapshot`
- Verified commit: `3660bc00fd80`
- Local source path: `/tmp/vuln-src/open-webui`

## Vulnerability Type

Server-Side Request Forgery via Redirect

## Severity

High

## CWE

CWE-918 Server-Side Request Forgery; CWE-601 URL Redirection to Untrusted Site used for SSRF bypass

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N (suggested 8.1, deployment-dependent)`

## Affected Components

- `open_webui image/OAuth avatar helpers`
- `get_image_data URL validation and fetch path`

## Summary

Open WebUI validates the original image URL but then fetches it with redirects enabled. A public-looking URL can redirect to loopback/private/internal resources after validation.

## Technical Details

1. The original URL passes validate_url or equivalent host checks.
2. The HTTP client follows 30x redirects by default.
3. Redirect targets are not revalidated before the internal request is made.

## Exploitability Verification

- PoC command:

```bash
/tmp/aiohttp-poc-venv/bin/python /tmp/vuln-pocs/openwebui_get_image_redirect_ssrf_poc.py
```

- Verification result: PoC shows example.com redirecting to 127.0.0.1; vulnerable_loopback_hit=true. A patched no-redirect control does not hit loopback.
- Full rerun evidence: `/tmp/vuln-pocs/a_class_0day_rerun_20260515_124431.log`

## Proof of Concept

The PoC listed above is a minimal, local exploitability check for the vulnerable sink. It avoids destructive behavior and demonstrates the security boundary violation with marker files, loopback servers, or direct policy checks.

## Impact

Authenticated or reachable image/avatar flows can make the backend access internal HTTP services, cloud metadata endpoints, or loopback admin interfaces and may expose returned image-like content.

## 0day Deduplication

Local GitHub issue DB and web searches found no matching Open WebUI disclosure for get_image_data/OAuth picture URL redirect SSRF during this run.

Additional exclusion rule used for this submission set: findings derived from public GitHub issues, public PRs, advisories, CVEs, or already-disclosed vulnerability reports were not counted as strict 0day items.

## Remediation

Disable redirects for SSRF-sensitive fetches or revalidate every redirect hop with DNS/IP classification. Reject loopback, private, link-local, and metadata targets and add redirect SSRF regression tests.
