---
name: universal-crypto-rules
description: 为 UniversalCryptoExtension Burp Suite 插件编写、迁移、排错及离线验证可导入的加解密、签名、编码和字段处理规则。适用于用户提供 HTTP 报文、客户端协议或现有规则并希望在本插件中处理流量的场景。
---

# Universal Crypto 规则编写

输出实际可导入的规则 JSON、对应协议说明和脱敏验证样例。以本插件的真实行为为依据，避免把其他 Burp 插件、浏览器 JavaScript、Node.js 的接口套到本插件上。

## 版本与资料路由

本技能针对 2026-10-14 UI 维护后的 UniversalCryptoExtension 1.0.0：Java 17+、Rhino 1.8.1、导出 `schemaVersion=1`、`engineBuild=rhino-1.8.1-sandbox-v1`。插件版本号未变化，旧版 1.0.0 JAR 不保证具有这些能力。BC/SM2 修复包额外使用 Manifest `Crypto-Provider-Layout: signed-bc-nested-v1`，内含 `META-INF/lib/bcprov.jar`；schemaVersion/engineBuild 保持兼容，不能仅凭它们认定部署已修复。当前发布包额外包含 UCE-Revision=2026.11.13.3 和 Response-Editor-Phase=response-editor-send，启动日志可核对 revision。先核对源码、导出文件或引擎自检日志；只有旧 JAR 时不要声称新 API 可用。

- 所有规则：先读 [规则结构与执行语义](references/rule-format.md)。
- 内置加密、字段、签名或外部 API：读 [处理器参数全集](references/processors.md) 中相应部分。
- 使用脚本：读 [Rhino 脚本 API 与字节语义](references/script-api.md)。
- 选取方案和模板：读 [协议配方与完整示例索引](references/recipes.md)，可复制 `assets/examples/` 中的完整规则。
- 验证、导入、排错：读 [验证流程与限制](references/validation.md)。

不要一次加载全部资料。不同路径的参数名和 JSON 路径语法并不相同，按实际处理器选用。

## 从协议到规则

1. 从用户提供的报文、客户端实现或协议说明确定：匹配范围、请求/响应方向、查看明文或实际改写、明文与密文封装、字符编码、key/salt/IV 的来源与编码、KDF、AES 模式/填充、GCM tag 的长度及位置、AAD、签名原文构造与输出格式。记录证据，区分已知值与假设。
2. 缺少必要密钥、密钥派生算法、IV 或封装信息时，仍可生成禁用的结构草案并标明缺项；不得编造实际参数或宣称解密成功。已有信息足够时直接完成，不额外要求确认。
3. 内置处理器能精确表达协议时优先使用。PBKDF2 + GCM/AAD、嵌套字段、分离 tag、字节帧等使用脚本。脚本 Crypto 只提供 PBKDF2-HMAC-SHA256、HMAC-SHA256、AES-GCM 和随机字节，不具有 AES-CBC/RSA/SM4 的脚本辅助方法；这些走内置处理器或已获授权的外部服务。
4. 明确动作输入和写回目标。写 Header 或提取变量时通常须显式 `inputSource=request-body` / `response-body`。`targetType=field` 不会替脚本定位某个字段：脚本要返回完整修改后的正文。
5. 明确 `executionPhase`。请求编辑必须另有明确的 `encrypt`、`body/field`、`editor-send` 动作，其条件覆盖编辑后的明文/头部；缺少实际加密时保留原密文，不能用 `execute` 代替加密标识。请求页签的解密动作使用 `actionType=decrypt`、`targetType=body/field`、`display` 和 `showInEditor=true`。响应明文页签使用 `response-display`；Intercept 中手工编辑后重加密使用独立的 `encrypt`、`body/field`、`response-editor-send` 动作，未编辑时保持原密文。HTTP 回调自动改写才用 `response-send`。响应 AAD/nonce 来自原请求头时用 `request.getOriginalHeader(name)`，不能为取得上下文而改用 `response-send`。不要默认使用 `always`。新建仅用于页签编辑的请求加密动作设置 `config.editorOnly=true`，避免 Repeater HTTP 回调二次加密（需构建 2026.10.14.2+）。旧规则未设置时，`editor-send` 仍会在 Repeater HTTP 回调执行；该路径须幂等或检查有效密文后返回 null。
6. 使用 JSON 序列化器生成文件，正确转义多行 `scriptCode`。默认生成 `enabled=false` 的完整版本化导入文件，不写入当前用户配置、不自动启用规则、不发送真实流量，除非用户已授权这些动作。
7. 使用真实引擎离线验证：先验证导入/动作配置，再用固定脱敏样例验证匹配条件、阶段、输出、签名原文和失败路径。引用下面工具，不以 Python/Node.js 算法往返代替 Rhino 验证。没有运行环境时标记“未运行”，给出可执行命令。

## 必须保留的行为约束

- 禁止 `Packages`、`java`、Java 反射、文件/进程/网络脚本调用。没有 `require`、`Buffer`、`fetch`、WebCrypto 或浏览器 DOM。
- 加密数据使用 0–255 的普通 JS 数组、`Bytes` 和 `Crypto`。`Base64.decode` / `Hex.decode` 是 UTF-8 文本转换，不能拿来读取随机 key/IV/ciphertext。
- 显式 return 字符串或字节数组；null/undefined 不改写目标；空字符串会清空。返回 JS 对象不是结构化写回；返回 JSON 必须 `JSON.stringify`。
- 本插件不会替你插入、拆分 GCM tag，也不会替你判断 IV 在正文还是 Header。`Crypto.aesGcm*` 固定 tag 128 bit，返回/接收 ciphertext||tag；无 AAD 也必须传第四个参数 null。
- 当前修复包保留并独立加载嵌入式签名 BC，内置 AES 与 HMAC 示例 02/06 已通过 packaged 验证；旧合并 BC 的 fat JAR 仍影响受 javax.crypto 门控的 AES/SM4/DESede、HMAC、PBKDF2 等。SM2 密钥加载已改为 EC + sm2p256v1，BC 本身的 SM2 工厂别名仍不存在。生成规则前核对 [新旧部署边界及验证矩阵](references/validation.md)。
- 内置签名 HMAC key 按 UTF-8 文本读取，不支持 `keyFormat` 解码；二进制 HMAC key 用 `Crypto.hmacSha256(keyBytes,dataBytes)`。
- 请求/响应共享仅存在于实际 HTTP message ID 配对链，10 分钟内；展示编辑器和 Playground 创建独立上下文。不要让响应展示依赖先前发送动作的随机共享值。
- 实际 HTTP 链动作失败会跳过并继续，**不是整条规则事务**。若解密、修改、签名必须全部成功才写回，放进一个脚本动作。编辑器相位服务遇到失败则返回整体 failure。
- `request.getOriginalHeader/getOriginalHeaders` 两个方向均可用：请求为本轮处理开始时的请求头快照，响应为关联请求头；快照不跟随后续 Header 动作变化。
- `request.getHeaders()` 是当前方向的只读头部对象；没有 `request.setHeader`。写头使用独立 Header 目标动作；共享值使用 `ctx`。
- `keyValue` 不是自动模板字段。不要把 `${...}` 放到任意 config 并假设会解析。模板仅在文档列出的字段启用。

## 离线工具

```bash
python3 /path/to/universal-crypto-rules/scripts/check_rule.py \
  --project /path/to/UniversalCryptoExtension --rules /path/to/rules.json
python3 /path/to/universal-crypto-rules/scripts/check_rule.py \
  --project /path/to/UniversalCryptoExtension --rules /path/to/rules.json \
  --fixtures /path/to/fixtures.json
```

只有发布 JAR 时可用 `check_rule.py --jar /path/to/plugin.jar --rules rules.json --fixtures fixtures.json`，自动选择 packaged 模式，不需要源码或 Maven。提供 --project 时默认 source 模式使用 target/classes；新内置引擎加载自身嵌入式签名 BC，`--runtime packaged` 单独测试 fat JAR。它只读取构建产物和规则，在临时目录运行真实 Java 处理器，不使用 mock crypto，不访问当前规则配置、不发 HTTP 请求。它拒绝需要 external provider 或 lookup 的验证；这些只能检查结构并按 [外部服务章节](references/processors.md#外部-http-api) 另外验证。`--fixtures` 会在临时内存中启用提供的规则，用例可显式指定展示/发送路径；正式导入仍然默认禁用。

## 交付

提供规则文件链接、用途和匹配范围、导入后的启用步骤、修改哪些目标、密钥和 IV 格式、测试命令及结果。不能完成的部分明确说明缺失证据。真实敏感 key 若用户要求写入本地规则可以按授权使用，但分享用样例和示例材料用脱敏值；不要声称已在真实 Burp 环境回归，除非确实进行了测试。


实时流量排错：先区分“转发的报文快照”和“明文预览”。`response-display` 只展示解密，转发快照保持密文是正确结果；列表“匹配规则”不证明动作已执行。打开“明文预览”按当前规则重新执行 `display`/`response-display`，结果不会回写 HTTP 链；规则改动后点击“重新生成”，旧预览有记录级缓存。外部 provider/lookup 明确未验证，不能以预览失败直接认定真实服务失败。单动作记录展示中间快照，完整转发结果看汇总记录。[实时流量验证与边界](references/validation.md#22-实时流量展示与明文预览2026-10-13)。


统一链路边界：wire、editor、preview 共用输入解析、生成 Header 写回、当前正文/字节和变量命名；charset 改变重解释原字节，不自动重编码。失败动作恢复 Header 和共享变量的顶层绑定；wire 继续后续动作，编辑器/展示阶段停止失败链。null/noChange 仍可保留脚本对共享变量的有意赋值，但不能作为正文已加密的证明。外部客户端不可用明确失败，不使用 mock；查密钥失败保留原因。请求/响应准备密文按规则 revision 缓存，规则更新自动失效。[统一处理链验证](references/validation.md#23-历史遗漏与统一处理链2026-10-13)。
