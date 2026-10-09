# 证据、报告与补全表

## 四层完整性

| 层 | 需要证明 | 不能据此证明 |
| --- | --- | --- |
| 缓存范围 | 扫描 roots、失败目录、版本/账号、全部已发现包及原件哈希 | 线上所有分包已缓存 |
| 包内容 | 索引、正文覆盖、路径、全部文件写出读回哈希 | 后台工程包含在包中 |
| 前端依赖 | 页面/分包/模块/视图/样式/动态资源与访问状态 | 预览即高清；云端内容齐全 |
| 产品行为 | 页面×状态×操作、视觉、保存恢复、导出读回 | 支付/AI/平台发布已完成 |

数目必须声明口径：全部条目、去重路径、唯一 SHA256、模块出现次数、已选版本/历史版本。不要混用层级。

## 报告注释

先复制 [annotations.example.json](../templates/annotations.example.json) 到独立项目，填写目标身份、证据、流程和实际验收。样例内容都是未知/待核验，不能原样当完成结果。

```sh
python3 scripts/report_tool.py --out "/separate/evidence" --version 1 --visibility private --annotations "/separate/annotations.json"
python3 scripts/report_tool.py --out "/separate/evidence" --version 1 --visibility public --annotations "/separate/annotations.json"
```

工具汇总可静态获得的范围、模块、资产、接口、提示词和缺项；需要语义判断或实机操作的项目由注释和证据补齐。模板 schema 是交换/登记约定，自动分析未知项不能因字段存在变成已完成。

实际注释入口是 `identity`、`acceptance`、`viewport`、`visits` 与安全的 `keyNames`。身份和验收项每份附件使用证据根目录内的相对 `path` 与实际 `sha256`；缺文件、哈希不符或路径越界会降级。截图哈希只验证附件，不自动证明 UI 等价；`manual_verified` 表示有附件的人工声明。

```sh
python3 -c 'from pathlib import Path; import hashlib; print(hashlib.sha256(Path("/separate/evidence/qa/result.png").read_bytes()).hexdigest())'
```

将真实读回哈希与 `qa/result.png` 写入对应 `evidence` 数组，再填写实际结果。不能填写示例假哈希或只把 `status` 改成 verified。`data_sources`、`endpoints`、`prompts`、`gaps` 的人工自由信息只留私有证据，不透传公开报告；公开模式采用安全字段与脱敏摘要。

## 公开/私有

私有报告保留可追溯路径、原始哈希和授权证据；敏感凭证仍不写入持久化报告。公开报告在独立文件生成，脱敏用户目录、账号标识、认证值、URL 凭据/query/signature 和敏感响应，自由文本也需检查。

保留安全的结构信息：`Authorization: Bearer <redacted>`、请求参数名、公开域名/静态路径和凭证类别。不要把所有 `API_KEY` 字段名删掉而使契约失真。原缓存、反编译商业代码、原图片、截图、账号数据默认不进入公开分发包。

自动脱敏是辅助；发布前人工查看公开 JSON/Markdown/CSV，核对新增字段和样例。不能自动修改原证据来伪造无敏感信息。

## 补全表

从页面缺项、接口契约和平台差异形成表，参考 [completion.csv](../templates/completion.csv)。列出：材料、提供者、凭证类别、配置变量/位置、接入后效果、限制、验证步骤和状态。

需补原图/设计文件、缺失分包、正式 API 权限、会员/测试账号、服务端规则、采集调度和提示词时分别写明。用户 Key 不等于全功能权限；客户端会话不等于服务器源码。没有证据时不要要求购买某个模型、数据库、MCP 或 Skill。

## 报告状态

统一使用 `verified / partial / unverified / missing / not_applicable`。每个已验证结论都绑定实际证据/时间/范围；“工具具备能力”“本次执行通过”“平台实机通过”分开。交付源码或起服务器不替代最终状态、文件落盘和恢复结果读回。
