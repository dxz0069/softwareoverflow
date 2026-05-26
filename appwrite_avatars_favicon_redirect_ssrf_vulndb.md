# VulnDB Submission: A-008 Appwrite Avatars favicon endpoint follows redirects after public-domain validation causing SSRF

## Title

Appwrite Avatars favicon endpoint follows redirects after public-domain validation causing SSRF

## Disclosure Status

Strict 0day candidate. No matching public GitHub issue, PR, advisory, CVE, or local issue-database disclosure was identified for this specific component and sink during this run.

## Affected Vendor / Product

- Vendor / Project: `appwrite/appwrite`
- Product / Component: see affected components below

## Affected Versions / Source Snapshot

- Verified version/snapshot: `current main snapshot`
- Verified commit: `54693d94178e`
- Local source path: `/tmp/vuln-src/appwrite`

## Vulnerability Type

Server-Side Request Forgery via Redirect

## Severity

High

## CWE

CWE-918 Server-Side Request Forgery; CWE-601 URL Redirection to Untrusted Site used for SSRF bypass

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N (suggested 8.1, depends on auth mode and exposed session/key use)`

## Affected Components

- `src/Appwrite/Platform/Modules/Avatars/Http/Favicon/Get.php`
- `utopia-php/fetch redirect handling`

## Summary

Appwrite /v1/avatars/favicon validates the original URL host and selected favicon host with public-domain checks, but fetches with redirects enabled. Redirect targets are not revalidated, enabling SSRF to internal resources.

## Technical Details

1. The endpoint accepts a url parameter and checks Domain(host)->isKnown().
2. Both the initial page fetch and subsequent favicon fetch setAllowRedirects(true) with max redirects.
3. utopia-php/fetch maps this to cURL follow-location behavior, so a public host can redirect to loopback/private targets.

## Exploitability Verification

- PoC command:

```bash
python3 /tmp/vuln-pocs/appwrite_favicon_redirect_ssrf_poc.py
```

- Verification result: PoC redirects a public-host-shaped favicon request to 127.0.0.1 and confirms internal_hit=true with internal_body INTERNAL-FAVICON-SECRET.
- Full rerun evidence: `/tmp/vuln-pocs/a_class_0day_rerun_20260515_124431.log`

## Proof of Concept

The PoC listed above is a minimal, local exploitability check for the vulnerable sink. It avoids destructive behavior and demonstrates the security boundary violation with marker files, loopback servers, or direct policy checks.

## Impact

API clients with access to the favicon endpoint can cause Appwrite to probe or retrieve content from internal HTTP services, metadata endpoints, or loopback applications.

## 0day Deduplication

Local GitHub issue DB found no exact Appwrite favicon SSRF disclosure. GitHub/web searches for Appwrite favicon, /v1/avatars/favicon, AVATAR_REMOTE_URL_FAILED, getFavicon and SSRF found only broad module PRs/health-module work, not this redirect-after-validation SSRF path.

Additional exclusion rule used for this submission set: findings derived from public GitHub issues, public PRs, advisories, CVEs, or already-disclosed vulnerability reports were not counted as strict 0day items.

## Remediation

Disable redirects or revalidate each redirect target. Enforce DNS pinning and IP range checks for every hop, and add regression tests for public-to-loopback and public-to-metadata redirects.

