# 验收与测试边界

## 工具验证

公开测试只使用测试中生成的合成包、代码与自造资产：

```sh
python3 scripts/test_cache_tool.py
python3 -m unittest discover -s tests -p 'test_*.py'
npm test
```

覆盖解码、扫描错误、路径别名、清单越界、未知格式、正文、源变化、增量复用、脱敏与分发等行为；必须验证实际产物和错误，不只匹配文案。真实包回归另显式运行，仍只写临时/独立目录，不改变原缓存或原取证。

功能档案测试还覆盖旧清单、修改正文/模块、错误身份与版本、同名候选、省略计数、未解析表达式、观察来源/失败、伪造附件、越界和保留用户改动。合成观察不代表原微信实机操作通过；新增功能实机记录单独登记。

CI 配置是待运行的检查方案，远端通过必须有真实 run 证据。Mac/Windows runner 的合成测试不等于在微信实机、所有包格式或各平台原生能力上通过。

## 产品矩阵

使用 [acceptance.csv](../templates/acceptance.csv)，每行对应页面/状态/操作；绑定原证据、输入、预期最终业务状态、本地实际状态、模拟/原业务类别、文件或截图证据、差异与结果。

至少覆盖当前实现的默认、编辑、空、失败、取消、权限条件、输出及恢复。原产品没有取得的状态标缺证据，不自行编造“相同”。请求 200、toast、弹窗或下载按钮被点击都不等于业务完成。

## 视觉和动态效果

使用 [visual-comparison.example.json](../templates/visual-comparison.example.json) 保存 viewport、DPR、宿主缩放、截图尺寸、字体、滚动、页面/状态、数据时间与比较时点。原图和规范化对照图同时保存，不能只保留重绘图。

同模板、文案、视口和状态比较布局、间距、颜色、图标、字体与原资产。动态雷达/闪烁等约定时点或时间区间，核查周期和状态，而不是只截一帧。像素 diff 可辅助，但不要编造百分比或让系统壳/字体误差掩盖产品差异。

## 保存、恢复、导出

按实际路径记录：浏览器下载、本地服务写出、平台原生保存。保存后刷新并读回状态；导出后检查最终文件存在、编码、内容、尺寸和 SHA256；从备份导入并检查恢复后的业务内容。不能只检查页面里有 JSON 或打开了保存对话框。

```sh
python3 scripts/verify_artifact.py --path "/separate/export.json" --type json --required-field data
python3 scripts/verify_artifact.py --path "/separate/export.png" --type image --dimensions 750 1334
```

此工具可核验 JSON/CSV/图片文件，也可指定 `--sha256`、可重复的 `--required-field`（或 `--required-key`）、`--max-bytes` 和受支持的简化 `--schema`。schema 未支持关键字会失败，不宣称完整 JSON Schema 验证。产品级恢复、UI 与平台保存仍需真实操作。失败时保留报错与部分结果，不把本地文件适配完成称为微信相册权限或下载行为已验证。

## 预览与最终交付

用户请求预览时启动独立 localhost 服务，先核对端口归属，不终止无关服务。读回 HTTP、实际浏览器界面、资源加载与控制台，再交地址。源码、依赖和启动命令也要独立可复用。

交付结果明确 `verified / partial / unverified / missing`，列本次执行的构建/测试和剩余差异；过往回归记录注明历史范围，不冒充当前执行。
