# Resin Egress Gateway

`resin-egress-gateway` 是一个小型、受信任的内部 L7 出站恢复服务。它在调用方与 Resin 之间缓存一次请求，并只在响应尚未提交给调用方时，使用新的 Resin 粘性身份重放请求。

它解决 Resin 无法解决的那一段：CONNECT/TLS 已经建立，但业务请求随后遇到响应头超时、首字节超时、连接重置或临时 HTTP 错误。Resin 继续负责节点池、路由、lease 和健康状态；Gateway 不采集节点、不管理模型账号，也不提供直连兜底。

## 边界

- 总计默认最多 3 次尝试，每次失败推进一个持久化 `generation`，成功身份会被后续请求继续使用。
- 请求体默认最多 8 MiB，普通响应默认在 8 MiB 内完整缓冲；超过上限的响应转为流式透传。
- 普通响应首字后最多缓冲 2 分钟；超时发生在下游尚未提交响应时，可按所选 retry mode 换身份重试。
- 默认最多同时处理 4 个请求；额外请求最多排队 30 秒，避免请求与响应缓冲耗尽容器内存。
- SSE、NDJSON 和 JSON sequence 只等待首个 body 字节。首字一旦写给调用方，后续中断不会重放。
- 默认策略：GET/HEAD/OPTIONS/PUT/DELETE 或携带 `Idempotency-Key` 的请求可对临时状态码重试；其他非幂等请求默认不重试。
- 调用方可以显式选择 `transport`，用于签到等业务上可重复、但没有标准幂等键的 POST。
- 不支持 CONNECT、WebSocket upgrade、TLS MITM 或直连 fallback。
- 不跟随上游重定向；`Location` 原样返回调用方。默认在首次请求及每次重试前拒绝显式私网目标，以及本机 DNS 已解析到私网、环回、链路本地和保留地址的目标。本机 DNS 权威返回无记录时交给 Resin 出口解析，因为实际连接与 DNS 均发生在所选节点；DNS 超时或解析器故障仍拒绝。这是内部 SSRF 门禁，不会固定 Resin 侧的 DNS 解析结果。
- 日志只记录 method、目标 hostname、短 route hash、状态、attempt 和耗时；不记录 Cookie、Authorization、URL query 或 body。

## 内部协议

调用 `/v1/forward` 时保持原始 HTTP method、headers 和 body，并增加：

| Header | 含义 |
|---|---|
| `Proxy-Authorization: Bearer <token>` | Gateway 内部鉴权；不会发往目标站点 |
| `X-Egress-Target` | 完整目标 URL 的 base64url（无 padding）编码 |
| `X-Egress-Key` | 稳定业务身份，例如应用名 + 账号 ID |
| `X-Egress-TLS-Profile` | 可选的账号传输配置 `v1:<0..103679>:<64 位小写 SHA256>`；版本化入口必填 |
| `X-Egress-Retry-Mode` | `never`、`transport`、`safe` 或 `auto` |
| `X-Egress-Response-Header-Timeout-Ms` | 可选，1 秒到 10 分钟 |
| `X-Egress-First-Byte-Timeout-Ms` | 可选，1 秒到 10 分钟 |

响应会增加 `X-Egress-Attempts` 与 `X-Egress-Generation`。Gateway 控制头和 `X-Resin-Account` 均不会泄漏给目标站点。

需要逐账号 TLS 的客户端调用 `/v1/forward/tls-v1`。该入口强制校验 profile，
并在 Resin 确认后回传 `X-Egress-TLS-Profile`。响应回执表示选择了账号传输配置；
普通 HTTP 只有连接池隔离，不会因此变成 HTTPS。无回执不触发 POST 重放。

`transport` 覆盖网络错误、Resin `UPSTREAM_*`、`NO_AVAILABLE_NODES`、响应头/首字节超时和响应提交前的 body reset。`safe` 另外覆盖 HTTP 408、425、429、500、502、503、504，并对 `Retry-After` 做最多 3 秒的有界等待。

## Resin 接入

Gateway 使用 Resin 官方 reverse-proxy 协议：

```text
http://resin-host:10834/<proxy-token>/<platform>/<scheme>/<target-host>/<path>
X-Resin-Account: egw-<route-hash>-g<generation>
```

Resin reverse-proxy 每次只选择一个 sticky identity。Gateway 的三次 generation 正好形成最多三个新的 L7 尝试，不会与 CONNECT 内部三节点重试形成 3x3 放大。

携带 profile 时，协议段改为 `https+tls-v1` 或 `http+tls-v1`，并传递
`X-Resin-TLS-Profile`。新版 Resin 校验并剥离控制头，目标 HTTPS 握手使用 uTLS 账号配置；
旧 Resin 会在路由前拒绝不支持的 protocol，旧 Gateway 则不接受版本化入口。
因此组件版本不匹配时不会先用默认 TLS 发出业务请求。升级顺序为 Resin、Gateway、调用方。

generation 改变出口粘性身份，不改变显式 TLS profile。目标 TLS 连接池由 Resin 按
node/platform/account/profile 分离；账号 uTLS 路径当前使用 HTTP/1.1，不宣称 HTTP/2 指纹伪装。
Node 到本服务、以及本服务到 Resin 的内部控制连接不等于目标站点 TLS 握手。

## 配置

| 环境变量 | 默认值 |
|---|---|
| `LISTEN_ADDRESS` | `:8080` |
| `GATEWAY_TOKEN_FILE` | 必填 |
| `RESIN_BASE_URL` | `http://proxy.internal:10834` |
| `RESIN_PROXY_TOKEN_FILE` | 必填 |
| `RESIN_PLATFORM` | `AppsGlobal` |
| `STATE_PATH` | `/data/state.json` |
| `MAX_ATTEMPTS` | `3` |
| `MAX_IN_FLIGHT` | `4` |
| `MAX_QUEUE_WAIT` | `30s` |
| `MAX_REQUEST_BODY_BYTES` | `8388608` |
| `MAX_RESPONSE_BODY_BYTES` | `8388608` |
| `RESPONSE_HEADER_TIMEOUT` | `30s` |
| `FIRST_BYTE_TIMEOUT` | `30s` |
| `RESPONSE_BUFFER_TIMEOUT` | `2m` |
| `MAX_RETRY_AFTER` | `3s` |
| `ROUTE_STATE_TTL` | `720h` |
| `ALLOW_HTTP_TARGETS` | `false` |
| `ALLOW_PRIVATE_TARGETS` | `false` |

生产部署模板见 `deploy/docker-compose.yml`。容器以 `65532:65532` 运行；部署前须让两个 secret 文件可由该 UID/GID 只读，并让 `./data` 可写，例如 `chown 65532:65532` 后分别设置 `0400` 与 `0700`。服务只加入 MetAPI 的 Docker 网络，并在宿主机 `127.0.0.1:19086` 暴露健康检查；不会进入 Router/Sub2API 当前会话链路。

## 验证

```bash
go test -race ./...
go vet ./...
test -z "$(gofmt -l cmd internal)"
```

GitHub Actions 在 `main` 上完成格式、vet、race tests 和镜像构建，先发布不可变 `sha-<commit>`，确认远端 `main` 未变化后再提升 `main` 标签。
