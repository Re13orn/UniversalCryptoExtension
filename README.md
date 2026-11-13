# Universal Crypto Extension

[![Cross-platform build](https://github.com/Re13orn/UniversalCryptoExtension/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/Re13orn/UniversalCryptoExtension/actions/workflows/build.yml)
[![Latest release](https://img.shields.io/github/v/release/Re13orn/UniversalCryptoExtension)](https://github.com/Re13orn/UniversalCryptoExtension/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](BUILD.md)

Universal Crypto Extension 是基于 Montoya API 的 Burp Suite 扩展。它按规则处理 HTTP 请求和响应，支持内置加解密、签名、字段转换、Rhino 脚本和外部密码服务。

## 快速开始

### 安装发布版

从 [GitHub Releases](https://github.com/Re13orn/UniversalCryptoExtension/releases/latest) 下载并解压发布 ZIP，在 Burp Suite 的 **Extensions → Installed → Add** 中选择 **Java**，加载根目录的 `universal-crypto-extension-1.0.0.jar`。插件依赖已打包，使用 Burp 自带的 Java 运行时即可。若通过 Burp 的独立 JAR 启动，请按所用 Burp 版本选择兼容的 Java 运行时。插件的最低字节码版本为 Java 17。具体加载步骤见 [PortSwigger 安装指南](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/loading-in-burp)。

内置处理器和预设可离线使用。使用外部加解密或密钥查找规则时，需要先在设置中配置对应服务。

### 从源码构建

在项目根目录运行 `mvn clean verify`，产物位于 `target/universal-crypto-extension-1.0.0.jar`。构建需要 JDK 17+ 和 Maven。完整校验命令及 Windows、Linux、macOS 用法见 [构建与发布](BUILD.md)。

## 预设规则

首次启动的规则列表为空。预设库提供 10 组可手动添加的通用合成示例，涵盖 Base64、AES、HMAC、JSON 字段处理和明文编辑。示例使用保留域名与合成测试向量。启用前请按授权测试目标填写匹配条件和协议参数。离线验证命令见 [验证指南](VERIFICATION.md)。

构建包将原始签名 BC JAR 完整嵌入 `META-INF/lib/bcprov.jar`，加载时使用独立 Provider，不依赖额外 classpath，也不改变 Burp 全局 provider。Manifest 标记为 `Crypto-Provider-Layout: signed-bc-nested-v1`；旧合并 BC 的 1.0.0 包需要替换。SM2 使用 EC 密钥工厂读取 sm2p256v1 的 SPKI 公钥和 PKCS#8 私钥；默认密文为 raw C1C2C3。修复与验证见 [BC/SM2 修复说明](docs/BC与SM2修复说明.md)。

### 使用方式

1. **查看规则列表** - 进入 `Universal Crypto` 标签页
2. **启用需要的规则** - 根据你的API类型选择相应规则
3. **测试API请求** - 在Repeater中修改请求，插件自动处理
4. **添加自定义规则** - 支持用户添加新的处理规则
5. 在明文编辑标签页修改后发送，扩展会按规则自动重新加密
6. Universal Crypto 页签默认显示原始请求行/响应状态行、完整头部和明文正文。在正文区域右键，取消勾选“Show original HTTP headers”可切换为仅正文。可编辑请求支持修改请求行、头部和正文，切换保留全部修改，不触发重新加解密。Content-Length 初始显示原报文值，发送时由 Burp 按加密后的正文重新计算。HTTP 头和 JSON 自动高亮并显示行号；有效 JSON 默认展开，右键使用 `Pretty JSON` / `Raw` 切换。未编辑时保留原始明文字节对应的文本，不因格式化重签名或重加密；在 Pretty 视图实际编辑后，发送编辑后的正文文本（含展示空白）。

### 内置加解密配置

- `cryptoProvider`: 选择 `external`（默认）或 `internal`
- `algorithm`: `aes-gcm` / `aes-cbc` / `rsa` / `base64`
- AES 常用参数：`cipherField`、`ivField`、`plainField`、`keySource`、`keyValue`（字段名支持 `regex:<pattern>` 形式匹配动态键名）
- 可选：在加解密面板填写 `IV Literal Value`，即可固定使用该 IV，并同步写回 JSON
- RSA 参数：`rsaPublicKey`、`rsaPrivateKey`（支持 PEM/Base64），可搭配 `keySource: none`
- Base64：设置 `cipherField`，无需密钥（使用 `keySource: none`）

**示例**（内置 AES）：

```json
{
  "actionType": "decrypt",
  "processor": "crypto",
  "targetType": "body",
  "config": {
    "cryptoProvider": "internal",
    "algorithm": "aes-gcm",
    "keySource": "static",
    "keyValue": "gx8ZD5wTjguSHKcMDKibelYOmZpxTPDaGOgadSE69lU=",
    "cipherField": "ciphertext_b64",
    "ivField": "iv_b64",
    "payloadFormat": "json",
    "executionPhase": "display"
  }
}
```


## 💡 Advanced Usage (Template Engine)

本插件内置了强大的 **模板引擎 (Template Engine)**，支持在签名原文和支持模板的配置中进行变量提取和函数嵌套。仅在对应处理器明确支持的字段生效，详见 Skill。

### 1. 变量与提取 (Variables)
- **基础变量**: `${method}`, `${path}`, `${body}`, `${timestamp}`, `${host}`
- **Header 提取**: `${header.content-type}` (不区分大小写)
- **JSON 提取**: `${json:data.user.id}` (支持多层级和数组索引，如 `items.0.id`)

### 2. 内置函数 (Functions)
支持嵌套调用，例如 `${md5:${base64:...}}`。
- **Hash**: `${md5:text}`, `${sha256:text}`, `${sha1:text}`
- **Encoding**: `${base64:text}`
- **Utility**: `${random:16}` (生成指定长度的随机 Hex 字符串)

### 3. 复杂场景示例 (Complex Examples)

#### 场景 A: 先 MD5 密码再签名
假设签名算法要求：`Sign = SHA256(appId + MD5(password + salt) + timestamp)`

**配置模板**:
```text
appId=1001&secret=${md5:${json:data.password}MySalt123}&ts=${timestamp}
```
*注：在 Rule 编辑器的 "Custom Sign Template" 中填入上述内容，并选择 SHA-256 算法。插件会自动计算最终的 Hash 值作为签名。*

#### 场景 B: 组合带 HMAC 的 Header

模板引擎没有通用 `${hmac:...}` 函数。需要 HMAC 时使用内置 signature 处理器，或显式脚本（Header 目标需指定输入正文）：

```javascript
var nonce = Bytes.toBase64(Crypto.randomBytes(8));
var signature = Hash.hmacSha256(content, 'DemoKey');
return 'Custom ' + Base64.encode('1001:' + nonce + ':' + signature);
```

DemoKey 和原文构造仅为示例，实际算法、密钥编码及 nonce 必须来自协议。

#### 场景 C: 提取 Token 并重新组合
```text
Token=${json:auth.access_token}&Nonce=${random:12}&Ts=${timestamp}
```

## 📋 Available Build Commands


| Command | Description |
|---------|-------------|
| `./build.sh` | Build the BurpSuite JAR with verification |
| `make build` | Same full verified build via Makefile |
| `make verify` | Verify JAR file |
| `make clean` | Clean build files |
| `make help` | Show all available commands |

## 🏗️ Build Scripts

- **`build.sh`** - Single Linux/macOS build script with verification
- **Windows** - Maven + Python verification commands in [BUILD.md](BUILD.md)
- **`Makefile`** - Make-based build system

## 📁 Project Structure

```
UniversalCryptoExtension/
├── src/main/java/                    # Java source code
│   └── com/universal/crypto/
│       ├── burp/                     # BurpSuite integration
│       ├── engine/                   # Rule engine
│       ├── handler/                  # HTTP processing
│       ├── model/                    # Data models
│       ├── processor/                # Processing logic
│       └── util/                     # Utilities (logging, debug)
├── src/main/resources/               # Resources
│   └── META-INF/services/           # SPI service registration
├── target/                          # Build output
│   └── universal-crypto-extension-1.0.0.jar  # Complete JAR for BurpSuite
├── build.sh                        # Linux/macOS build script
├── build.bat                       # Windows build script
├── Makefile                        # Make-based build
└── BUILD.md                        # Detailed build instructions
```

## 🔧 Features

- **Rule-based Processing**: Flexible rule engine for HTTP request/response processing
- **API Integration**: Connects to external DeEn_API service for crypto operations
- **Multiple Algorithms**: Support for AES, HMAC, signing operations
- **Debug Support**: Comprehensive logging and debugging utilities
- **Thread-safe**: Concurrent processing support

## 📖 Documentation

- [Build Instructions](BUILD.md) - Detailed build guide
- [External API Integration](docs/EXTERNAL_API.md) - Configure helper services for encrypt/decrypt/sign/verify
- [Architecture Overview](docs/) - Technical documentation (if available)

## 🛠️ Requirements

- Java 17+
- Maven 3.6+
- BurpSuite Professional

## 🐛 Troubleshooting

### Build Issues

```bash
# Download dependencies
mvn dependency:resolve

# Clean and rebuild
make clean build

# Verify JAR
make verify
```

### Common Errors

- **ClassNotFoundException**: Rebuild with `./build.sh` and use `target/universal-crypto-extension-1.0.0.jar`
- **Build fails**: Check Java/Maven versions
- **Permission denied**: `chmod +x *.sh`

## 🤝 Development

```bash
# Development mode (auto-rebuild on file changes)
make dev

# Run tests
make test

# Create release package
make release
```

---

**Built with** ❤️ **using Java, Maven, and BurpSuite Montoya API**

## 2026-10-10 评审优化与脚本迁移

脚本引擎升级为 Rhino 1.8.1。脚本通过 `Crypto`、`Bytes`、`Base64`、`Hex`、`Hash`、`request`、`ctx` 工作，禁止直接访问 `Packages`、`java`、Java 反射及文件/进程 API。旧的 `Packages.javax.crypto` 脚本需迁移至辅助 API。

- `content`：当前动作输入文本；`bodyBytes`：当前报文的原始正文，以 0–255 整数数组表示。
- `return` 文本可写回文本目标；正文动作也支持返回字节数组，按原始字节写回。
- 无返回值、`return undefined`、`return null` 均表示不改写目标，显式返回空字符串会清空目标。
- `Base64.encode/decode` 与 `Hex.encode/decode` 保留为 UTF-8 文本兼容方法。二进制必须使用 `Base64.decodeBytes/encodeBytes` 或 `Bytes.fromBase64/toBase64`。
- `Bytes.utf8(text)`、`Bytes.text(bytes)`、`Bytes.concat(a,b)`、`Bytes.slice(bytes,offset,length)` 提供字节转换。
- `Crypto.pbkdf2(password,salt,iterations,bits)` 使用 PBKDF2-HMAC-SHA256；`Crypto.hmacSha256(key,data)` 返回字节数组。
- `Crypto.aesGcmEncrypt(key,iv,plaintext,aad)` / `aesGcmDecrypt(key,iv,ciphertext,aad)` 使用 128 位认证标签，密文包含标签。无 AAD 时传 `null`。
- `Crypto.randomBytes(length)` 产生随机字节。

```javascript
var key = Crypto.pbkdf2('password', Bytes.utf8('salt'), 50000, 256);
var iv = Crypto.randomBytes(12);
var encrypted = Crypto.aesGcmEncrypt(key, iv, Bytes.utf8(content), null);
return JSON.stringify({iv: Bytes.toBase64(iv), ciphertext: Bytes.toBase64(encrypted)});
```

响应规则默认或 `response-display` 阶段仅在 Universal Crypto 响应明文页签执行，原始响应保持不变。要在 HTTP 回调自动改写响应，请明确设置 `response-send`；`always` 会同时参与展示和流量处理。正文为二进制时，请使用 `bodyBytes`，避免从 `content` 重建二进制数据。文本修改按 `Content-Type` 声明的 charset 编码，缺省为 UTF-8；未变更正文保留原始字节。

文件导入会先校验脚本语法、处理器、目标及执行阶段，再展示旧规则和新规则供对照；导入规则默认禁用。新导出文件包含 `schemaVersion` 和 `engineBuild`，仍支持导入旧数组格式。版本不匹配的文件会提示错误。持久化配置格式保持兼容。

流量追踪面板会记录动作成功、失败、未变更、前后正文长度及耗时。失败动作跳过，其余动作继续生效。脚本编译缓存最多 128 份，作用域按执行隔离；扩展加载时运行 PBKDF2 + AES-GCM 自检。请求/响应共享数据按 Montoya message ID 配对，响应处理结束释放；未返回响应的上下文保留最多 10 分钟。不具备 message ID 的离线上下文不进行跨请求/响应缓存关联。

验证记录与实现边界见 [评审优化说明](docs/评审优化说明.md)。

## 规则编写 Skill 与完整参考手册

其他 agent 编写本插件规则时，可使用仓库内的 [Universal Crypto 规则编写 Skill](skills/universal-crypto-rules/SKILL.md)，或从 [规则编写手册](docs/规则编写手册.md) 查阅全部规则字段、执行阶段、内置处理器、脚本 API、协议示例和排错流程。技能包含 10 组可导入的脱敏示例及调用真实 Java/Rhino 引擎的离线验证工具，不使用 mock crypto。


明文页签深色配色参照 Burp 原生 Pretty：HTTP 头名浅蓝、JSON 字段名黄色、字符串绿色、数字蓝色、布尔值和 null 橙色，正文背景为深灰。浅色主题使用相应的深色文字保证对比度。


请求/响应明文页签的字体、字号和字重读取 Burp 的 HTTP message display 设置（currentEditorFont），高亮 token 与行号使用同一字体；切回页签或加载新报文时刷新。不会固定为 12 号，也不会额外加粗。


Repeater 等可编辑请求窗口：解密成功且匹配 encrypt/body-or-field/editor-send 动作后，请求行、HTTP 头和明文正文均可编辑；默认光标位于正文，Cmd+A/Ctrl+A 或右键 Select all 选择当前完整视图。隐藏头部时仅显示及编辑正文，已修改的头部仍保留。发送时使用编辑后的方法、路径及头部匹配加密/签名规则，仅将正文交给加密处理。Host 的修改不会改变 Repeater 的连接目标，目标需在 Burp 中设置。只读窗口遵循 Burp EditorMode.READ_ONLY，响应页签在 READ_ONLY 模式保持只读；可编辑窗口需匹配显式 response-editor-send 正文加密动作才开放编辑。


插件重载后仍可编辑：明文编辑器使用独立的 keymap、InputMap 和 ActionMap，避免 RSyntaxTextArea 的全局缓存继续引用已卸载插件的键盘动作。无需重启 Burp 清缓存。

响应仅展示解密且客户端继续接收密文时，使用 `response-display`。原请求头参与 AAD/密钥派生时，脚本读取 `request.getOriginalHeader('X-Nonce')` 或 `request.getOriginalHeaders()`；`request.getHeader()` 在响应阶段仍是响应头。原请求头不并入响应条件匹配。已有 `response-send`/`always` 解密规则需手工迁移到展示阶段并更新取头代码，修复不会自动改当前规则。

`getOriginalHeader/getOriginalHeaders` 同时支持请求方向：读取本轮规则处理开始时的请求头快照；后续 Header 动作改变当前 `getHeader`，不改变快照。响应方向读取关联请求头，不保证是请求发送动作之前的值。

Repeater 请求预览/取值不会清除编辑状态，重复取值复用本次密文；再次编辑自动使缓存失效。Burp 设置新报文后才重置编辑状态，避免发送时回退到旧请求。

Proxy Intercept 响应编辑现已支持：保留 response-display 解密动作，另外添加 actionType=encrypt、targetType=body/field、executionPhase=response-editor-send 的响应动作。未修改时保留原密文；编辑后重新加密再提交；只有匹配加密规则才开放编辑。只读窗口仍不可修改，旧规则和当前用户配置不会自动迁移。

当前维护版以 Manifest UCE-Revision=2026.11.13.3 识别。整体检查、已修复问题与验证边界见 [整体检查记录](docs/整体检查与优化_2026-10-13.md)。


实时流量详情区默认各占约一半高度，分隔条可拖动。左侧是收到的报文快照，右侧区分“转发的报文快照”和“明文预览”：`response-display` 不改写网络报文，因此转发快照仍是密文；打开“明文预览”才按当前规则执行展示阶段并格式化 JSON。预览结果按记录缓存，规则改变后用“重新生成”更新；外部 API/lookup 不执行，失败明确提示。列表区分规则匹配、动作结果和转发数据变化，响应动作按上下文归类，不再把响应规则误记作请求处理。详见 [实时流量修复说明](docs/实时流量展示修复_2026-10-13.md)。


当前统一修复说明见 [历史遗漏与统一优化](docs/历史遗漏与统一优化_2026-10-13.md)。未实际执行正文加密时，请求/响应编辑都保留原密文；规则更新使已准备的密文缓存失效。外部客户端初始化失败不再使用模拟加密，内部算法继续可用。构建校验会拒绝 revision 与当前工程不一致的旧 JAR。

UI 布局与交互本轮修复见 [UI 检查记录](docs/UI检查与优化_2026-10-14.md)：语言刷新保留测试数据、当前页签和规则选择；测试任务后台执行；设置导入先进入待保存表单；实时流量仅从汇总报文运行完整展示预览。

“按场景创建”和“预设库”已同步升级，见 [场景与预设更新](docs/场景向导与预设库更新_2026-10-14.md)：新增响应明文编辑场景；预设库提供 10 个可验证合成示例；新请求编辑模板通过 editorOnly 跳过发送回调中的再次加密。

当前隐藏交互修复见 [UI 保存与交互记录](docs/UI隐藏交互缺陷与优化_2026-10-14.md)：规则工具来源、取消/失败草稿保持、变量/字段实际改名、签名模式与密钥来源联动，以及排序和字体展示。

表单常用/高级分组、实时流量搜索与筛选、主要帮助中英文同步见 [本轮交互优化](docs/表单分组与流量筛选优化_2026-10-14.md)。高级区折叠保留参数；筛选不丢弃已记录流量，也不改变网络处理。

本次整体复核修复了重复头误写、编辑器二进制密文损坏、保存失败仍生效、测试丢配置与自定义算法刷新丢失等问题，见 [整体复核记录](docs/整体复核与修复_2026-10-14.md)。测试资源现已与用户 用户目录 和真实配置隔离。

## 许可证

项目源码采用 [MIT 许可证](LICENSE)。随 JAR 分发的依赖沿用各自的许可证，见 [第三方声明](THIRD_PARTY_NOTICES.md)。
