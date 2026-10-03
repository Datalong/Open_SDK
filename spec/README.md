# A2Net 协议规范（单页站）

零依赖的静态规范页，直接打开 `index.html` 即可阅读。

## 本地查看

```bash
# 方式一：直接打开
open index.html

# 方式二：本地静态服务
python3 -m http.server 8085
# 浏览器访问 http://localhost:8085
```

## Docker 部署

已集成到根目录 `docker-compose.yml` 的 `spec` 服务（nginx:alpine）：

```bash
docker compose up -d spec
# 默认端口 8085，可用 SPEC_PORT 覆盖
```

## 内容

覆盖协议 13 节：概述、身份标识、消息格式、规范化与签名、消息类型、错误码、权限模型、扩展命名空间、中继协议、发现与寻址、Lightning 支付、身份恢复、安全考量、版本兼容。

配套长文档见 `../docs/`。

## 许可

**协议规范文本公开授权**：任何人可阅读、复制、分发本规范，并可依据它独立实现兼容组件并自由分发，无需付费或另行授权。详见 [`LICENSE`](LICENSE)。

注意：本授权仅覆盖**规范文本**；仓库中的参考实现源代码（SDK、中继、目录、控制台等）为专有软件，见根目录 [`../LICENSE`](../LICENSE)。
