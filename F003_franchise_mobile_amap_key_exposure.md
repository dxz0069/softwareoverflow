# F003: franchise-mobile 前端泄露高德 Web 服务 Key 且未限制调用来源

- Severity: Medium
- Status: Confirmed
- Affected asset: `https://franchise-mobile.huazhu.com/js/app.6ed2e672.js`
- Affected third-party API: `https://restapi.amap.com/v3/place/text`
- Preconditions: 无需登录；任意客户端可从前端 JS 获取 Key；无需 Referer 即可调用高德 Web 服务接口。

## Summary

`franchise-mobile.huazhu.com` 前端 JavaScript 中硬编码了高德地图 Web 服务 Key：`6ebf98a4368fca69ac36c5769cda5052`。使用该 Key 直接请求高德 `place/text` API，在不带 Referer、Origin 设置为 `https://attacker.invalid` 的情况下仍返回有效 POI 数据，说明该 Key 未做有效来源限制或 IP 限制。

## Impact

- 外部人员可复制该 Key 调用高德 Web 服务 API。
- 可能造成第三方服务配额被消耗、账单/额度异常、业务功能受影响。
- 攻击者可将该 Key 嵌入自己的站点或脚本中批量调用，导致 Key 被封禁或额度耗尽。
- 若同一 Key 绑定了其他高德 API 权限，可能扩大滥用范围。

Source evidence:

```text
Source file: C:\Users\THUNDEROBOT\Desktop\test\pentest_20260709_171334\evidence\web_assets_expanded\franchise-mobile.huazhu.com__js__app.6ed2e672.js_2b8f60e0.js
SHA256: 8527854AD59C05AEFD3B7153B5AAF9DC05D68BB51DDF6759E4333D18317CDED3
```

Key exposed in frontend snippet:

```js
getCsss:function(e,t){
  return T.get("https://restapi.amap.com/v3/place/text?key=6ebf98a4368fca69ac36c5769cda5052&keywords=".concat(t,"&types=&city=").concat(e,"&children=&offset=10&page=1&extensions=all"))
}
```

Validation request used no Referer header and an attacker Origin:

```http
GET /v3/place/text?key=6ebf98a4368fca69ac36c5769cda5052&keywords=hotel&city=310000&offset=3&page=1&extensions=base HTTP/1.1
Host: restapi.amap.com
Origin: https://attacker.invalid
```

Observed response summary:

```json
{
  "http": 200,
  "status": "1",
  "info": "OK",
  "count": "600",
  "cors": "*",
  "sample_poi": "迷家青年酒店(上海财经大学店)"
}
```

A second single request with `keywords=coffee` also returned `status=1/info=OK` and POI data. No high-frequency or quota-exhaustion testing was performed.

## Reproduction

```bash
curl 'https://restapi.amap.com/v3/place/text?key=6ebf98a4368fca69ac36c5769cda5052&keywords=hotel&city=310000&offset=3&page=1&extensions=base' \
  -H 'Origin: https://attacker.invalid'
```

Expected vulnerable result:

- HTTP 200.
- JSON body contains `status: "1"` and `info: "OK"`.
- Response contains POI results.
- Response has permissive CORS (`Access-Control-Allow-Origin: *`) from the third-party API, enabling browser-side abuse.

## Root Cause

- Third-party API Key is hardcoded in public frontend JavaScript.
- Key appears to lack effective Referer/domain/IP restrictions.
- Frontend directly calls a third-party Web service API that should be proxied or constrained when quota/cost is relevant.

## Remediation

- Rotate/revoke the exposed高德 Key。
- 在高德控制台为新 Key 绑定严格的 Referer、域名或 IP 白名单。
- 若该 API 需要后端保护配额，改为后端代理调用，并增加鉴权、限流和缓存。
- 将不同业务环境、不同站点拆分为独立 Key，限制每个 Key 的 API 权限与额度。
- 增加前端构建产物的 secret scanning，阻止第三方 Key 被硬编码发布。

## Verification after fix

- 前端 JS 中不再出现高德 Key。
- 使用旧 Key 调用 `restapi.amap.com/v3/place/text` 返回 key 无效或无权限。
- 使用新 Key 从非白名单来源/无 Referer 调用失败。
- 业务前端正常通过受限 Key 或后端代理获取所需地点数据。
