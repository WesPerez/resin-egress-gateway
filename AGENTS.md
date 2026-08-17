# Repository Agent Instructions

- 默认使用中文维护文档，代码标识符与协议字段保持英文。
- 本项目只负责受信任内部客户端的 L7 出站恢复；不得加入 TLS MITM、直连兜底、节点采集、账号调度或模型语义转换。
- Resin 节点池与 lease 仍由 Resin 管理。Gateway 只通过官方 reverse-proxy 协议派生稳定身份并在响应提交前轮换 generation。
- 非幂等请求默认不重放；只有调用方显式选择 `transport`/`safe` 或携带幂等键时才扩大重试范围。
- 一旦向下游提交响应头或响应体，禁止重放。SSE、NDJSON 和其他流式响应必须遵守该边界。
- 不记录请求头、Cookie、Authorization、完整 URL query、请求体或响应体。
- 正常发布必须经 GitHub Actions 测试并构建 GHCR 镜像；生产服务器不本地构建发布镜像。
- 修改重试边界时必须补充故障注入测试，并运行 `go test -race ./...`、`go vet ./...` 与格式检查。
