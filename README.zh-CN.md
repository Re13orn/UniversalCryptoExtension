# Universal Crypto Extension

[![Cross-platform build](https://github.com/Re13orn/UniversalCryptoExtension/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/Re13orn/UniversalCryptoExtension/actions/workflows/build.yml)
[![Latest release](https://img.shields.io/github/v/release/Re13orn/UniversalCryptoExtension)](https://github.com/Re13orn/UniversalCryptoExtension/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](BUILD.md)

[![GitHub stars](https://img.shields.io/github/stars/Re13orn/UniversalCryptoExtension?style=social)](https://github.com/Re13orn/UniversalCryptoExtension/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Re13orn/UniversalCryptoExtension?style=social)](https://github.com/Re13orn/UniversalCryptoExtension/forks)

[English](README.md) · **简体中文**

一款用于测试加密或签名 API 的 Burp Suite 扩展。可以在 Burp 中查看和编辑明文，再由规则在发送前重新加密报文或计算签名。

## 使用场景

接口使用密文传输时，Repeater 中只能看到密文。修改一个字段可能就要重新解密、组装报文和签名。把这些步骤配置为规则后，扩展会在匹配的请求或响应上执行它们。

## 主要功能

- **明文查看与编辑。** 解密请求和响应供查看。配置独立的加密动作后，可以提交修改后的明文。
- **请求重签名。** 从请求头、查询参数或正文构造签名原文，将结果写入请求头或 JSON 字段。
- **自定义处理。** 将内置加解密、编码和字段操作与 Rhino JavaScript 或已配置的外部服务组合使用。
- **规则验证。** 在启用规则之前，使用测试台或步骤预览核对样例报文的处理结果。

## 工作原理

规则可按主机、路径、HTTP 方法和 Burp 工具匹配流量。展示阶段负责生成明文视图，编辑器提交阶段处理修改后的内容，转发阶段对实际收发的 HTTP 报文执行动作。

## 安装

1. 从 [GitHub Releases](https://github.com/Re13orn/UniversalCryptoExtension/releases/latest) 下载 `universal-crypto-extension-1.0.0.jar`。
2. 在 Burp Suite 中打开 **Extensions → Installed → Add**，选择 **Java** 并加载 JAR。
3. 在 **Universal Crypto** 页签中创建或导入规则。

JAR 已包含运行依赖。扩展要求 Burp 进程使用 Java 17 或更高版本。构建已在 Linux、macOS 和 Windows 的 Java 17、21 环境中验证。

## 使用

首次启动时规则列表为空。可从预设库添加 10 组通用合成示例中的任意一组。示例添加后默认禁用。填写目标范围和协议参数，在测试台核对结果后再启用。

如果要在明文页签中编辑请求，需为展示阶段配置解密动作，为编辑器提交阶段配置加密动作。协议要求更新签名时，再添加签名动作。

内置处理器可离线运行。外部加解密和密钥查找需要配置对应服务。

## 从源码构建

安装 JDK 17 或更高版本及 Maven，然后运行：

```sh
git clone https://github.com/Re13orn/UniversalCryptoExtension.git
cd UniversalCryptoExtension
mvn clean verify
```

构建后，在 Burp 中加载 `target/universal-crypto-extension-1.0.0.jar`。

## 文档

- [构建与发布](BUILD.md)
- [规则编写手册](docs/规则编写手册.md)
- [规则编写 Skill](skills/universal-crypto-rules/SKILL.zh-CN.md)
- [离线验证指南](VERIFICATION.md)
- [可导入的规则和测试样例](skills/universal-crypto-rules/assets/examples/)

## 许可证

项目采用 [MIT 许可证](LICENSE)。随 JAR 分发的依赖见 [第三方声明](THIRD_PARTY_NOTICES.md)。
