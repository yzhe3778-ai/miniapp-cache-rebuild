# 独立分发与首次发布检查

## 本地打包

```sh
python3 scripts/package_skill.py --root . --out /separate/miniapp-cache-rebuild.zip
```

输出目录必须已存在且在技能源码目录之外，归档路径不能已存在。工具只读技能目录、写一个新 ZIP；不创建 Git 仓库、不提交、不调用上传 API。

归档使用固定 `miniapp-cache-rebuild/` 前缀、固定时间/权限、字典序和 ZIP_STORED，重复相同输入得到相同归档 SHA256。`distribution-manifest.json` 记录每个被分发文件的路径、大小和 SHA256；自身不递归计算哈希。写完逐文件从归档读回校验。

## 允许范围

根目录只允许 Skill/README、LICENSE、来源/维护文档、Python/Node 依赖定义、`.gitignore` 与仅含占位值的 `.env.example`。子目录限 `scripts / tests / references / templates / agents / .github` 的 UTF-8 文本文件。

依赖目录、虚拟环境、Git 数据、缓存、私有证据、analysis/reports、exports/qa、dist/build 和 Python 字节码排除。意外目录/文件、二进制、symlink、大小写/Unicode 别名、源变化、超大文件和超量总输入失败，不自动复制未知材料。

归档自带的 `distribution-manifest.json` 在再次打包时排除，并由本次源文件重新生成，避免清单递归。解压后的目录可以独立安装和重新打包。

当前分发限单文件 8 MiB、总文本 32 MiB。公开 fixtures 在测试运行时自造；不把真实 `wxapkg`、目标原图片或反编译项目放入 tests 以绕过范围。

## 敏感值检查

拒绝个人绝对目录、常见 API token、JWT/private key、URL 内嵌凭据和凭证字段的可疑实际赋值。`API_KEY` 变量名、凭证类别与 `<redacted>` 等明确占位值允许保留。

这是保守辅助检查，不承诺识别所有秘密。被拒绝时审阅对应文件，不关闭检查强行分发；测试里的秘密样例使用运行时构造而非保存实际值。公开报告脱敏与分发检查是不同阶段，截图/二进制不在本归档范围。

## 首次公开发布

- 核对用户希望发布的 GitHub 账号、仓库、公开范围与许可证最终方案。
- 核对实际归档 manifest、源码 diff、依赖许可、第三方来源与不存在工作区外链接。
- 附本次本地合成测试/私有真实回归的范围；CI 未运行时明确标待运行。
- 只按发布授权上传工具包；本地准备和测试不自动授权外部操作。

当前学习用途非商业许可只覆盖本次发布的新写代码/文档/模板/自造测试，明确禁止商用；历史版本与第三方依赖保持各自原许可。第三方原程序和取证材料不被重新授权。`THIRD_PARTY_NOTICES.md` 与许可证审阅属于发布材料，当前优化任务可以先完成全部本地内容。
