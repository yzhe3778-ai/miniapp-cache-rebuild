# 缓存、版本、解码与增量工作流

## 快路径与完整路径

核心研究：`doctor → discover → extract → inventory → analyze → report`，先定位配置、入口和主链，按模块分批阅读。完整审计在此基础上补全部版本来源、声明分包、动态资源、状态矩阵和同视口验收。研究某个功能时在 analyze 后运行 `feature_tool.py --query`，先看紧凑候选与未知项，再打开原文。详见 [features.md](features.md)。没有固定耗时或节省比例承诺。

缓存完整性依赖扫描范围。`discover` 必须保存不可读目录、单文件读取失败及扫描状态；`complete`、`partial` 和空结果不同。任何扫描失败都不能解释成目标不存在。未知布局由用户指定已经核验的 `--root`，不扩大为全盘账号数据扫描。

## 目录适配与身份

| 系统 | 微信相关候选位置 | 验证等级 |
| --- | --- | --- |
| macOS | `~/Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/radium/users/<account>/applet/packages/` | 两个真实案例核验 |
| macOS | 微信 AppEx/共享容器内的目标包目录 | 候选目录探测；仍记录实际命中与权限 |
| Windows | `%APPDATA%\Tencent\xwechat\radium\users\<account>\applet\packages\` | 目录策略，未在本机 Windows 微信实测 |
| 旧布局 | `Documents/WeChat Files/Applet` 或明确提供的包目录 | 兼容候选，按实际文件头核验 |

包格式由文件头识别，微信版本不能替代格式检查。保存 OS、微信版本（能取得时）、扫描 roots、账号来源标签、包尺寸与修改时间。公开报告不用原账号路径。缓存修改时间不是产品上线时间。

AppID 未知时列候选，在提取配置/标题/图标后与当前界面比较。需要解开外层加密时使用已核验 AppID；不能用错误 AppID 得到不合法正文后继续分析。

## CLI

在技能目录执行；下面值均为示例，不作为默认目标。

```sh
python3 scripts/cache_tool.py doctor
python3 scripts/cache_tool.py discover --root "/verified/packages" --appid wx0000000000000000
python3 scripts/cache_tool.py extract --appid wx0000000000000000 --source "/verified/packages/wx0000000000000000" --out "/separate/evidence"
python3 scripts/cache_tool.py inventory --out "/separate/evidence" --version 1
python3 scripts/cache_tool.py diff --before "/separate/before-evidence" --after "/separate/evidence" --report "/separate/cache-diff.json"
```

`--source` 可以是目标目录、版本目录或单包。`discover --root` 可重复指定。`extract` 可设 `--max-package-bytes`、`--max-file-bytes`、`--max-output-bytes` 和 `--max-files`。版本必须由现场与候选差异共同选择，数字最大值仅为候选；以对应子命令 `--help` 的实际默认限制为准，不关闭限制强行解析损坏样本。

Windows PowerShell：

```powershell
$miniappPython = ".\.venv\Scripts\python.exe"
$miniappSource = "D:\verified\packages\wx0000000000000000"
$miniappEvidence = "D:\research\evidence"
& $miniappPython scripts/cache_tool.py discover --root $miniappSource --appid wx0000000000000000
& $miniappPython scripts/cache_tool.py extract --appid wx0000000000000000 --source $miniappSource --out $miniappEvidence
& $miniappPython scripts/cache_tool.py inventory --out $miniappEvidence --version 1
node scripts/analyze.cjs --out $miniappEvidence --version 1
```

## 输出和续作

```text
evidence/
  scope.json                         目标及源范围
  package-manifest.json              版本化包/文件清单与扫描错误
  packages/<snapshot-key>/
    original.wxapkg                  原件快照
    decoded.wxapkg                   去外层加密的容器
    files/                           所有索引条目
  inventory/<version>/               包内资产、配置与调用线索
  analysis/<version>/                模块、样式、数组和调用证据
  features/<version>/                私有功能档案与证据定位
  reports/                           私有/公开报告
```

实际工具可能额外输出辅助文件，当前结构以清单记录为准。Schema 2 清单保留包来源、文件 SHA256 与完整性结果；工具 schema 1 可兼容读取。案例早期手写清单不自动兼容，需要从原缓存重新提取为工具清单后回归，不能信任未知格式或人工改写的路径。

相同源和内容哈希可复用快照，但仍核验原件、解码包、提取文件和当前源哈希。新内容产生新快照；损坏/修改过的输出不覆盖，先报错并改用新证据目录。读包期间源文件变化视为缓存尚在写入，等待正常访问完成再重试。

同一证据目录只允许一个写入进程；使用任务锁或独立输出目录。异常退出保留完成证据与阶段失败点，恢复前核对清单，不删除用户修改。

AST 分析的复用指纹应包含文件内容 SHA256、分析器版本、参数与依赖版本；分析器变更时重新分析。报告重用分析产物和人工注释，不整包重复塞进上下文。

## 补缓存闭环

用 [navigation.csv](../templates/navigation.csv) 记录目标页面、进入路径、账号范围、结果和截图。补前保存清单，正常访问后再提取，用 `diff` 比较包内容/版本/来源；不以文件名或包数比较替代哈希。

未补齐原因：`not_visited / entry_not_found / download_failed / entitlement_restricted / unavailable / unknown`。两次包数不变只证明观察期间缓存稳定。不要强制调用隐藏路由或接口绕过产品条件。

## 解码和支持扩展

已支持：V1MMWX 外层与 BE/ED 明文 wxapkg。V1MMWX 使用 AppID 相关密钥解出前段，再恢复尾段；容器按大端索引长度、正文长度、文件数和 UTF-8 路径解析。公开格式参考见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)，实现来源与授权范围分开。

成功要求：源哈希未变、头和总长度合法、全部索引消耗、每条路径/边界安全、正文覆盖结果可解释、逐文件写出读回哈希一致。共享正文区间可被多个索引引用，不把共享本身判为损坏。未覆盖字节与异常必须报告。

拒绝大小写/Unicode 别名、Windows 保留名/尾随点空格、父目录穿越、绝对路径、文件目录冲突和 symlink 越界。路径策略跨平台保守处理，以保持一条索引对应一条可追溯输出。

新格式按“识别 → 解码 → 容器解析 → 完整性 → 合成/合法样本回归”独立扩展。只有合法样本和校验通过才提升支持等级；未知格式保留原件与结构化错误，不宣传支持所有平台和版本。
