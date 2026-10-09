# 原资产与明确 URL 收集

包内资产记录：类型、文件路径、尺寸、SHA256、引用模块/页面、角色、来源及取得状态。PNG/JPEG/GIF/WebP 等可识别尺寸记录像素；未识别为 `unknown`，不凭扩展名或 null 判断损坏。条目数、唯一哈希数和逻辑模板数分开。

角色为 `preview / original / icon / background / font / other / unknown`。角色需使用位置与分辨率证据，不能因图片大就自动标原图。预览放大、补画和重导出的资产各自记录，不冒充原件。

远程资源是独立 opt-in 阶段，先运行：

```sh
python3 scripts/asset_tool.py --help
```

工具只接受明确列出的 HTTPS URL（默认 443）、允许的 host 和全球公开 IP，不接受 credentials/query/fragment。重定向再次校验并固定已校验 IP 连接；不自动请求本地/内网服务。工具限制单资源字节、超时、有限重试和请求间隔，下载记录 HTTP、最终 URL、类型、尺寸、哈希和失败理由。签名或需凭证资源不由此工具处理，单独列授权材料缺项，不采集账号 token、不猜路径全量抓取。

下载前列出 URL 清单及来源调用点，可使用 [remote-assets.example.json](../templates/remote-assets.example.json)。实际格式为 `allowed_hosts` 加 `assets` 数组；每项包含具体 `url`，可选 `expected_sha256` 与 `expected_dimensions: [width, height]`。

```sh
python3 scripts/asset_tool.py --list "/separate/remote-assets.json" --out "/separate/new-assets" --timeout 15 --max-bytes 10485760 --retries 1 --interval 1
```

输出 SHA256 命名的原字节文件及 `asset-manifest.json`，不覆写已存在目录。支持 PNG/JPEG/WebP/GIF/BMP 栅格；SVG、字体、AVIF 等远程格式未支持需列缺项。有限重试，不把拒绝、过期签名和需要认证的结果标为素材缺失。成功文件还须读回、实际打开和核对角色。

状态分 `not_discovered / restricted / failed / downloaded / verified`。URL 本身可能敏感，公开报告脱去认证、签名和账号定位参数；远程二进制不默认进入开源包。
