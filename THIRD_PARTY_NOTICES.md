# 第三方来源与许可范围

## 本工具的新写代码与文档

`LICENSE` 的学习用途非商业许可适用于本项目本次发布的新写工具、自写文档、通用模板与自造测试；仅供学习，禁止商用。第三方依赖仍遵循下列原许可证，不以本项目声明覆盖或改变其许可。历史版本保持对应分发时的许可。

## 微信包格式资料

[BlackTrace/pc_wxapkg_decrypt](https://github.com/BlackTrace/pc_wxapkg_decrypt) 是 V1MMWX 外层格式/参数的公开参考。此前审阅未在其根文件列表观察到 LICENSE，不把“公开可见”解释成授权。

本项目的 Python 解码器以包格式重新表达，并未将该项目 Go 源文件复制进本发布包。若后续引入第三方源码，应另核对具体文件、版本、许可证与署名要求；不能由格式引用推导第三方代码可重授权。

## 运行依赖

| 依赖 | 用途 | 来源与许可 |
| --- | --- | --- |
| Python 标准库 | 清单、哈希、文件、HTTP、测试、打包 | Python Software Foundation License，随 Python 发行 |
| pycryptodome 3.23.0 | AES/KDF 等解码所需密码原语 | [项目许可](https://github.com/Legrandin/pycryptodome/blob/master/LICENSE.rst)：原 PyCrypto 部分为 public domain，新写部分为 BSD 2-Clause |
| Node.js | 可选静态分析运行时 | [Node.js 许可](https://github.com/nodejs/node/blob/main/LICENSE)，含第三方 notices |
| @babel/parser / traverse / generator | 解析、遍历与格式化已缓存编译代码 | [Babel MIT](https://github.com/babel/babel/blob/main/LICENSE)；实际版本以 package-lock.json 为准 |

本归档不 vendoring Python/Node 运行时或 `node_modules`。依赖由独立环境安装，各自许可证仍适用；新增依赖先补来源与作用。

## 原程序与取证材料

解包后的目标代码、素材、字体、截图、服务端响应、设计文件和商标仍属于其相应权利人，不受本项目许可覆盖。学习授权不自动扩展成这些材料的再分发权。

公开工具包只纳入工具、自写说明、通用模板和自造测试；两款案例只提供脱敏事实摘要。商业原包、反编译源码、原图片、账号记录和凭据留在独立私有证据目录。需要分发第三方材料时单独记录其来源、授权与范围。

## REA 方法参考（v1.1.0）

参考 [morluto/rea](https://github.com/morluto/rea) 的 JavaScript artifact reconstruction、MCP contracts 与 browser observation 文档中的证据定位、紧凑材料与未知项管理思路，具体链接见 [features.md](references/features.md)。新增工具为本项目重新实现的微信静态证据流程；没有复制其源码、安装 REA 或引入其 MCP/调试引擎。后续如引入代码应另核验具体版本与许可。
