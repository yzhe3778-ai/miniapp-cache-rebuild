# 按功能拆解与学习

适用于已解包并完成静态分析的微信小程序。目标是快速回答“保存、导出、识别或刷新是怎么做的”，集中阅读相关证据，再独立实现并验证。工具不执行目标代码，不联网、不补缓存，也不自动生成整套产品。

## 最短用法

在技能目录执行，替换证据目录与已核验版本：

```sh
node scripts/analyze.cjs --out "/separate/evidence" --version 1
python3 scripts/feature_tool.py --out "/separate/evidence" --version 1 --query saveSchedule
```

先选实际页面名、方法名、存储 key 或按钮相关词。中文文案不一定保留在业务模块，零命中时改查 `pages/home`、`setStorage`、`setData` 等实际代码线索；零命中不证明功能不存在。默认最多返回 40 条，必要时用 `--limit 100`，上限 500；省略数始终展示。重复命令复用相同产物，输出已被修改时拒绝覆盖。

## 工具核验与结果

输出位于 `features/<version>/<evidence_id>.json`，仅为私有阅读档案；不自动合并到公开报告。绑定 AppID、明确版本、原包清单哈希、分析文件哈希和分析器版本；逐一读回选定版本已验证包的全部索引文件以及提取模块哈希。清单改变、分析过期、正文改变、路径越界或观察附件哈希错误均报错。旧分析缺少行为索引时标部分覆盖，要求重新分析。

每条记录有稳定证据 ID、分析 JSON 指针、包/文件/行位置、模块、类别和未知项。同一输入可重复定位，任一绑定材料变化会改变 ID；ID 标识这份材料，不证明原作者身份或记录真实性。记录原包的来源和采集时刻仍是必需的。

模块正文和记录采用字面量匹配，再补同名模块中的样式、配置、接口、提示词、定时器与行为线索。同名不同内容的模块变体保持独立。这是阅读候选集，既不等于页面全部依赖，也不证明调用先后、可达性或异步执行结果。静态覆盖、返回/省略数量与产品等价分别报告。

行为索引当前识别直接拼写的 `wx.*Storage*`、下载/保存/相册/Canvas 导出、路由导航和 `setData`，记录最近的函数名及出处。别名、动态成员、文件系统管理器和封装方法需人工继续追踪；即使 `wx` 被局部变量覆盖也只是语法候选。真正的事件绑定需阅读编译视图和页面注册代码，不能由最近函数名推断完成。

## 阅读顺序与学习交付

1. 从界面入口与同状态截图确定要研究的功能；查询实际模块/方法名。
2. 按记录指针打开原分析和模块正文，确认事件绑定、参数、状态、纯处理函数与结果。
3. 沿调用逐段追踪接口、返回字段、存储 key、导出格式和错误分支；找不到时登记未知，不补写成“原实现”。
4. 正常操作原小程序，补必要的已授权页面/分包和实机观察；材料变化后重跑分析与功能档案。
5. 用 [feature-map.csv](../templates/feature-map.csv) 记录入口、链路、原证据与独立实现；用 [acceptance.csv](../templates/acceptance.csv) 验收自己的复刻。

交付每个功能的“入口 → 方法 → 输入/状态 → 处理/接口 → 保存/输出 → 错误/权限”说明，附代码出处、原观察、无法确定之处、独立实现文件及实际验收。按需画流程图，不把静态候选图包装成真实运行轨迹。

## 原程序与复刻观察分开

复制 [feature-observations.example.json](../templates/feature-observations.example.json) 到证据目录，填写目标 AppID/版本和观察记录。模板默认空记录，绝不预填成功。每条至少含：

| 字段 | 要求 |
| --- | --- |
| `id` / `query` | 唯一字母数字标识；query 与当前命令完全相同 |
| `origin` | `original-miniapp` 或 `local-rebuild` |
| `action` / `result` | 实际操作和读回结果；只陈述已观察到的情况 |
| `outcome` | `observed`、`failed` 或 `not-observed`；表示人工描述，不是工具认证通过 |
| `observed_at` | 含时区的 ISO 时间 |
| `static_evidence_ids` | 本次功能档案中的候选证据 ID，可为空；关联仍需人工审阅 |
| `evidence` | 1～20 个 `{ "path": "proof/save.json", "sha256": "真实64位哈希" }`，路径相对于证据目录 |

```sh
python3 scripts/feature_tool.py --out "/separate/evidence" --version 1 --query saveSchedule --observations observations.json
```

工具只核验观察来源分类、时间格式、引用和附件字节，并保留人工描述；不会仅凭截图哈希确认保存成功。界面动效、文件存在、业务恢复和原产品等价仍须分别操作验证。观察记录有私有自由文本，不能直接公开。

## 从 REA 借鉴的范围

参考 [JavaScript artifact reconstruction](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md) 与 [MCP contracts](https://github.com/morluto/rea/blob/main/docs/mcp-contracts.md) 的证据定位、紧凑输出和明确未知项思路，参考 [Browser observation](https://github.com/morluto/rea/blob/main/docs/browser-observation.md) 区分观察与推断。本技能重新实现微信缓存专用工具，未复制 REA 源码、安装其运行时或引入 MCP；通用网站、原生 APP、调试注入均不在本技能范围。
