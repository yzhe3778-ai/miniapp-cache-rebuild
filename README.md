# miniapp-cache-rebuild · 微信小程序拆解与学习

解析本机已缓存的微信小程序，保存原件、验证包完整性、建立前端证据，再按需要做可验收的本地复刻。输入范围仅为微信小程序；可按功能学习，再输出本地浏览器版或按请求适配自己的微信小程序。工具不会登录微信、执行包内代码、获取后台源码或自动发布产品。

当前发布：**v1.1.1**。功能工具来自 v1.1.0，本次补齐公开发布、作者信息与学习用途许可。

**版权声明：仅供学习，禁止商用。** 本仓库公开源码，采用有限制的学习用途许可，不采用 MIT/OSI 开源许可；完整条件见 [LICENSE](LICENSE)。原小程序和第三方依赖不由本项目重新授权。

- 仓库：https://github.com/yzhe3778-ai/miniapp-cache-rebuild
- 使用入口：[SKILL.md](SKILL.md) · [完整提示词](references/prompt.md)
- 按功能学习：[features.md](references/features.md)
- 工具验收：[v1.1.0 工具测试](references/feature-validation.md) · [历史真实缓存回归](references/release-validation.md)

## 下载与安装到 Agent

下载本仓库 ZIP 并解压，将根目录内的完整文件放在 Agent 的 `miniapp-cache-rebuild` 技能目录，不要只复制 SKILL.md。支持遵循 SKILL.md 的 Agent；发现机制与权限以实际宿主为准。

Codex 安装示例（目标目录已有内容时先保留旧版，不直接覆盖）：

```sh
git clone https://github.com/yzhe3778-ai/miniapp-cache-rebuild.git miniapp-cache-rebuild
mkdir -p "$HOME/.codex/skills"
cp -R miniapp-cache-rebuild "$HOME/.codex/skills/miniapp-cache-rebuild"
```

安装后确认 `~/.codex/skills/miniapp-cache-rebuild/SKILL.md` 可读，在安装的技能目录完成下述依赖安装；若宿主尚未识别，刷新或重新打开对应会话。CLI 研究不要求安装到 Agent，也不需要模型 API Key。

## 安装

Python 3.9+ 用于缓存与报告工具；V1MMWX 解码依赖 pycryptodome。Node.js 20+ 用于可选静态分析。依赖在此目录独立安装，不借用其他项目的 `node_modules`。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
npm ci
.venv/bin/python scripts/cache_tool.py doctor
```

Windows PowerShell：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
npm ci
.\.venv\Scripts\python.exe scripts/cache_tool.py doctor
```

不使用 AST 分析时无需安装 Node 依赖。`doctor` 检查环境，不证明某个微信版本的缓存格式一定受支持。

## 一次完整研究

先在微信正常打开目标、确认名称/图标，再定位候选缓存。下列值必须替换成目标的真实信息；例示 AppID 不属于真实案例。

```sh
python3 scripts/cache_tool.py discover --appid wx0000000000000000
python3 scripts/cache_tool.py extract --appid wx0000000000000000 --source "/verified/cache/root" --out "/separate/evidence"
python3 scripts/cache_tool.py inventory --out "/separate/evidence" --version 1
node scripts/analyze.cjs --out "/separate/evidence" --version 1
python3 scripts/feature_tool.py --out "/separate/evidence" --version 1 --query saveSchedule
python3 scripts/report_tool.py --out "/separate/evidence" --version 1 --visibility private --annotations templates/annotations.example.json
```

Windows 路径同样作为带引号的参数传入；不要复制上面的示例路径。先运行各工具 `--help` 查看限制、输出和当前参数。

正常访问声明页面、核心操作和弹窗以补按需缓存，再增量提取、盘点和分析。包数不再变化不能证明线上所有内容已取得。缺失材料通过人工注释写入报告，不猜测后端实现。

```sh
python3 scripts/report_tool.py --out "/separate/evidence" --version 1 --visibility public --annotations "/separate/annotations.json"
```

公开模式生成单独的脱敏报告，原私有证据不改。发布前仍要审阅公开结果，尤其是自由文本、截图和新加字段。

## 能力与限制

| 能力 | 支持边界 |
| --- | --- |
| 微信包解码 | V1MMWX、BE/ED 明文 wxapkg；未知格式输出错误与原件快照 |
| 完整性 | 扫描错误、索引、正文覆盖、路径冲突、读回哈希、源文件变化与复用校验 |
| 静态分析 | 原生微信 `define` 模块、WXSS、有限常量/数组求值、调用与提示词线索 |
| 功能阅读 | 字面量/模块候选、绑定材料的证据 ID、未解析与省略项、原程序/复刻观察分开；不是运行调用图 |
| WXML | 提供编译文件/视图线索，不能自动还原开发者原始模板 |
| 资产 | 包内哈希/类型/尺寸线索；明确 URL 的远程下载为独立可选步骤 |
| 后端/API | 可记录客户端实际契约与授权返回；服务端源码、模型配置和数据库需另提供 |
| 复刻 | Agent 按请求实现并做状态、视觉与文件验收；不是一键生成全部应用 |
| 平台 | 本地浏览器复刻、自己的微信原生适配与实测；网站/APP/其他平台逆向超出范围 |

Mac 两款应用的实证摘要见 [cases.md](references/cases.md)。Windows 路径策略有合成测试，不等于已在 Windows 微信实机完成解析。远程 CI 是否通过只以真实 GitHub Actions 运行记录为准。

v1.1.0 本次优化与测试见 [feature-validation.md](references/feature-validation.md)；v1.0.0 历史安装和两案例回归见 [release-validation.md](references/release-validation.md)，不作为新版实机验收。

只研究一个功能时，先选实际页面名、方法名或存储 key，使用 `feature_tool.py --query`；详细字段、原程序观察和学习交付见 [features.md](references/features.md)。不需要安装 REA 或新增 MCP。

## 作为 Skill 使用

将完整目录复制到你的 Agent 技能目录，目录名为 `miniapp-cache-rebuild`，保持内部相对路径。Codex 常用技能目录是 `~/.codex/skills/`，其他 Agent 按其技能发现机制安装；工具本身可独立通过 CLI 使用。

```text
请使用 $miniapp-cache-rebuild 解析我已在电脑微信打开的【目标】，
先核对身份、全部缓存版本、主包和分包，正常访问补齐按需缓存。
保留原缓存，在新目录做本地浏览器版并开服务器。
交付全部哈希、资产/UI/流程/接口证据、真实提示词、缺项及保存/恢复/导出验收。
仅本地学习，不发布。
```

更多输入方式见 [prompt.md](references/prompt.md)。不需要微信账号密码、个人登录 token 或全盘账号数据来完成包研究。

## 测试与分发

```sh
python3 scripts/test_cache_tool.py
python3 -m unittest discover -s tests -p 'test_*.py'
npm test
python3 scripts/package_skill.py --root . --out /separate/miniapp-cache-rebuild.zip
```

公开测试生成合成包，不包含商业小程序原包。真实包回归是显式可选的私有验证，参数见缓存测试工具的 `--help`；早期手写案例清单先从原缓存重新提取成工具 schema 2，不直接冒充兼容。打包是本地动作，不上传 GitHub；归档含逐文件 SHA256 清单。目录白名单和敏感值检查见 [distribution.md](references/distribution.md)。

新写工具、文档、模板和自造测试使用本仓库的学习用途非商业许可：**不准商用，仅供学习**。第三方依赖和格式出处见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。原小程序、反编译结果、素材与账号数据仍归各自权利人。

## 开发者与内容入口

维护者：**若宇（Ruoyu）**，AI 应用开发者、工作流与 Skill 实践分享者。由若宇组织维护，并使用 AI 编程工具辅助实现和测试；上游参考与第三方来源分别记录，不冒充原小程序作者或官方团队。

| 页面 | 地址/入口 |
| --- | --- |
| GitHub 开发者 | [yzhe3778-ai](https://github.com/yzhe3778-ai) |
| 个人博客 | [blog.outageai.xyz](https://blog.outageai.xyz/) |
| AI 教程 | [教程中心](https://blog.outageai.xyz/learn) |
| 公开项目与 Skills | [项目页面](https://blog.outageai.xyz/open-source) |
| 关于我 | [个人介绍](https://blog.outageai.xyz/about) |
| X / Twitter | [@ElowenY20119](https://x.com/ElowenY20119) |
| 小红书 | [个人主页](https://xhslink.cn/o/8S4tkBw4wZm) |
| 公众号 / 视频号 | 微信内搜索 **若宇讲AI**；不是平台直达链接 |
| 交流入群 | [博客交流入口](https://blog.outageai.xyz/#connect) |

以上账号入口来自维护者的 GitHub 个人主页；能否访问以网络与平台实际状态为准。问题反馈使用本仓库 Issues，不附真实密钥、账号记录或商业原包。

## 版权与使用范围

允许个人非商业学习、阅读、运行、修改和保留署名的非商业分享。禁止未经另行书面授权用于商业产品、付费服务、客户交付、营利业务或付费课程。详细适用范围以 [LICENSE](LICENSE) 为准，第三方依赖继续适用其原许可。

公开仓库不分发课表壁纸或重置雷达的原包、解包正文、图片和账号数据。案例只保留脱敏事实摘要；本地学习授权不会自动变为对第三方内容的再分发权。
