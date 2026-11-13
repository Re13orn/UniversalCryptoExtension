# 协议配方与完整示例索引

所有规则/fixtures 在 `../assets/examples/`（相对于本 references 目录）。完整 JSON 已正确转义 scriptCode，规则默认禁用。key/password/IV 都是合成测试值，不能当作用户协议参数。fixtures 的期望值由独立密码实现计算，再用插件真实 Java/Rhino 验证。

## 1. 协议收集表

从客户端代码/报文说明中填表，未知处明确未知：

| 类别 | 需要确定 |
|---|---|
| 操作目的 | 请求/响应，展示/编辑后加密/实际改写，Burp 工具范围 |
| 匹配 | host/path/method，request/response Content-Type 是否相同 |
| 明文 | UTF-8/GBK/原始字节；JSON object 还是 JSON string；签名前是否保留空白 |
| 外壳 | 顶层/嵌套字段，Base64/Hex/Base64URL，原始 byte 帧，magic/version/长度前缀 |
| 密钥 | 原始 bytes 或 password；来源是静态/header/query/payload；编码和解码后长度 |
| KDF | 函数、PRF、salt 来源/编码、iterations、输出 bit/byte 长度、password Unicode 处理 |
| AES | GCM/CBC/ECB，padding，IV/nonce 来源/字节长度，是否每条消息随机 |
| GCM | tag bit 长度、tag 与 ciphertext 的先后和编码、AAD 原始 bytes |
| 签名 | 原文构造、METHOD 大小写、path 是否含 query、排序、重复参数、分隔符、URL 编码、timestamp 单位 |
| 输出 | 保留外壳还是提取明文，写哪个 Header/字段，是否删除旧字段、重新签名 |
| 证据 | 至少一个已知 plaintext↔ciphertext 或 data↔signature 向量，错误/非目标样例 |

仅凭密文长度无法确定算法或 KDF。没有真实 key 时可交付结构和配置缺项，不能声称可解密。协议中的弱算法或固定 IV 以兼容真实对端为目标描述，合成测试的固定 IV 不等于部署建议。

## 2. 完整可运行资产

| 文件前缀 | 用途 | 验证重点 |
|---|---|---|
| [01-text-base64](../assets/examples/01-text-base64.rules.json) | 内置 UTF-8 文本 Base64 | 中文、非目标 host 不改写 |
| [02-internal-aes-cbc](../assets/examples/02-internal-aes-cbc.rules.json) | 内置 AES-CBC，JSON 顶层 payload/iv | 解密保留外壳；response-display 不改写真实响应 |
| [03-pbkdf2-aes-gcm](../assets/examples/03-pbkdf2-aes-gcm.rules.json) | PBKDF2 + GCM 请求编辑/响应展示 | request decrypt/display、encrypt/editor-send、随机 salt/IV、防重复加密、tag 篡改拒绝 |
| [04-gcm-split-tag-aad](../assets/examples/04-gcm-split-tag-aad.rules.json) | 嵌套 ciphertext、分离 tag、AAD | Bytes.concat；改变 path 导致认证失败 |
| [05-binary-key-hmac](../assets/examples/05-binary-key-hmac.rules.json) | Base64 编码 binary key 的 HMAC-SHA256 | Crypto 参数顺序、显式正文输入、Header 写回 |
| [06-internal-hmac-signature](../assets/examples/06-internal-hmac-signature.rules.json) | 内置 HMAC 的 custom 模板 | METHOD\nPATH\nBODY 精确原文，不改正文；新修复包 packaged 已精确验证签名头 |
| [07-json-field](../assets/examples/07-json-field.rules.json) | field 替换嵌套字符串 | $.field 路径、to 模板取 Header、其他 JSON 类型不变 |
| [08-raw-binary-gcm](../assets/examples/08-raw-binary-gcm.rules.json) | 整个原始正文为 GCM ciphertext | bodyBytes 输入、byte 数组输出、避免 UTF-8 替换 |
| [09-shared-wire-context](../assets/examples/09-shared-wire-context.rules.json) | request/response-send 配对共享 | 两个 message ID 乱序响应，nonce 不串线 |
| [10-response-editor-aad](../assets/examples/10-response-editor-aad.rules.json) | 原请求头 AAD，响应展示、编辑后加密与签名 | response-editor-send；未修改 wire 保持密文 |

当前修复包 9 组示例在 source/packaged 模式各 19 个用例均通过，见 [修复后验证矩阵](validation.md#9-bc-打包与-sm2-修复后验证2026-10-10)。部署时可通过 signed-bc-nested-v1 构建标记核对 BC 布局。

每个 `NAME.rules.json` 对应 `NAME.fixtures.json`。运行：

```bash
python3 /path/to/skill/scripts/check_rule.py --project /path/to/plugin \
  --rules /path/to/skill/assets/examples/04-gcm-split-tag-aad.rules.json \
  --fixtures /path/to/skill/assets/examples/04-gcm-split-tag-aad.fixtures.json
```

03 的随机加密用例只验证产生变化和成功，固定解密向量验证真实兼容，重复密文输入验证幂等。需要保证随机输出可再解密时，额外做输出捕获/回输（下方验证文档提供边界），不能把成功状态本身当作完整往返证据。

响应 Intercept 编辑参考 [10-response-editor-aad](../assets/examples/10-response-editor-aad.rules.json) 和 [fixtures](../assets/examples/10-response-editor-aad.fixtures.json)：请求头 nonce 参与响应 AAD，分开配置展示解密、编辑后加密和密文签名，未编辑 wire 保持密文。向量使用固定 IV 以便复核，实际 nonce/IV 应按协议产生。

## 3. 典型方案如何调整

### AES-256-GCM + PBKDF2-HMAC-SHA256

以 03 为起点，根据真实协议替换 password、iterations、salt 格式/长度、IV 格式和字段名。每次生成 salt 还是使用账户固定 salt 必须由协议决定。salt/IV 来自正文时读取正文，不使用示例随机生成行为替代。密码在配置/脚本中是字面值，不是 keySource=static 自动注入。

- 对端 ciphertext 已含 16-byte tag：直接 Crypto.aesGcmDecrypt。
- tag 单独提供：以 04 拼接 ciphertext||tag。
- 对端 tag 不是 128 bit：当前脚本 helper 不支持配置长度；无 AAD 且顶层 JSON 可以尝试内置 gcmTagLength，否则 external 或扩展代码。
- AAD 是原始 Header 值：Bytes.utf8(request.getHeader('X-AAD'))，注意响应阶段只能读取响应 Header。
- 解密后返回完整 JSON object 还是字符串由对端和用户查看需求决定，别额外 JSON.stringify 已经是 JSON 的字符串造成双层引号。

### AES-CBC/ECB 和原始密文

内置对称加密只接受 JSON 外壳。整段 Base64 密文可在同一方向内先用脚本包装成 JSON，再执行 crypto，最后脚本提取结果，但步骤失败不保证原子性。若要求“失败时保持原始完整密文”，优先使用精确 external 服务或用户允许的单动作实现；当前脚本 Crypto 没有 CBC。

包装示意（这三步不是插件自动行为）：

```javascript
// 包装：inputSource=response-body，targetType=body
return JSON.stringify({payload:content,iv:'PROTOCOL_IV_BASE64'});
// 中间：内置 AES-CBC，payloadFormat=json、cipherField=plainField=payload
// 提取：inputSource=response-body，targetType=body
return JSON.parse(content).payload;
```

真实 IV 在正文前缀、Hex、URL 编码外壳时先精确拆分；不把 UTF-8 字符数当字节偏移。

### Header/Query 中的密钥或 nonce

请求方向用 request.getHeader，响应处理依赖原请求头时用 request.getOriginalHeader；与 getQueryParam 获取文本后按协议 Base64/Hex/UTF-8 转字节。签名协议若使用原 query（如保留 `%20` 和参数顺序），用 getQuery 原文。getQueryParam 会 form decode 且只取第一个重复参数。

向 Header 写值须 targetType=header/targetName；脚本只 return 值。若同一步要改正文并生成多个 Header，可拆动作用 ctx 传值，但注意失败不是事务；内置 signature headerTemplates 可以在成功结果中生成多个 Header。脚本当前不能 return `{body:...,headers:...}` 做结构化多目标写回。

### 解密 → 改字段 → 重新加密 → 签名

同方向动作依次执行，每步后继正文更新。明确签名到底针对明文还是密文，把 sign 放在正确位置。改 JSON 数字/对象要 script，field.to 会变字符串。若协议要求任意一步失败都不改变流量，将可支持的全流程放一个脚本动作；最后一次 return 才写回。

若最终同时写正文和 Header，当前没有单脚本多目标事务接口；可把正文计算成共享变量，后续分别写 body/header，但必须明确失败策略和依赖检查，不能宣称完全原子。不要在发送流程设置始终生效的“先解密”规则，导致服务收到明文。

### 请求展示与编辑后发送

请求页签只有 decrypt/display/body-or-field 才显示。editor-send 加密须防止 Repeater HTTP 回调第二次执行时再加密。展示与发送上下文独立，key/salt/IV 必须可从当前外壳或固定协议重新得到。用户编辑后的正文可能不含原外壳字段，应明确如何恢复协议需要的 key/session 参数。

如果 key 仅存在于某次请求临时内存共享，独立编辑器目前不能可靠恢复：必须获取可见的协议字段或明确指出功能缺口，不把 ctx 当作全局内存。

### 响应展示与 Intercept 编辑后转发

保留 decrypt/response-display；需要编辑响应时新增 encrypt/body-or-field/response-editor-send。响应窗口为 READ_ONLY 或没有匹配加密动作时不可编辑，未编辑直接返回原密文。独立的 Header 签名步骤使用同一个新阶段并显式 inputSource=response-body；编辑器和步骤预览均接收 signature.headerTemplates 生成的附加头。

response-editor-send 不参加普通 HTTP 回调，也不由单独 always 隐式触发。规则要从原请求头重建 AAD，用 getOriginalHeader；响应 getHeader 仍是响应头。相位服务创建独立 ctx，每次加密须重新派生 key/nonce/AAD，不能依赖先前展示步骤的共享状态。参考示例 10。

### RSA/SM2/SM4

读 processors 对应参数。RSA public 使用 X.509 SPKI，private 使用 PKCS#8；PKCS#1 标签剥离不等于 DER 转换。先验证 padding/块大小/OAEP hash/MGF1/SM2 数据顺序。技能不提供凭空转换的万能脚本：Rhino 沙箱下不能 Packages 调 OpenSSL、Java Cipher 或第三方库。

新修复包 SM4 已通过 signed BC 的 Cipher 验证；SM2 改用 EC 工厂读取 sm2p256v1 密钥，独立 OpenSSL 向量和篡改拒绝通过。BC 1.70 的 SM2 工厂别名仍不存在；不要再调用 SM2 KeyFactory/KeyPairGenerator，也不能把 OpenSSL ASN.1 密文直接当成默认 raw C1C2C3。见 [部署与 SM2 路径](validation.md#源码模式与打包模式)。

### 外部服务

现有算法不支持时可以给 external 配置草案，并标明全局 apiBaseUrl 和相对 endpoint；是否允许外发 key/data 沿用用户授权。安全拼 JSON 用 apiFieldMap，不用 `${data}` 直接塞进带引号的字符串模板。服务需 JWT/登录态、动态 URL、复杂 payload 时先核对现有客户端能否表达，不能假设 apiHeaders 会解析普通模板。

## 4. Agent 交付模板

- 规则文件：完整版本化 JSON，明确启用状态，匹配范围可核对。
- 协议表：算法/KDF/key/salt/IV/tag/AAD/签名原文/编码。
- 使用方式：文件导入，核对差异，启用规则；在哪个 Burp 工具/页签观察什么。
- 验证：脱敏输入、期望输出、失败样例、真实引擎工具命令及运行结果。
- 限制：缺失协议证据、暂不支持的算法/上下文、只验证到哪一级；不把独立 Python 成功称为插件成功。

当前 Burp 预设库包含本节的 10 个可验证样例，并附相同 fixtures。向导适合基础 JSON 字段加解密/签名；需要 PBKDF2、AAD、原请求头、分离 tag 或原始二进制时使用对应脚本预设。“编辑后添加”创建独立禁用草稿，不覆盖已有规则。新请求编辑动作使用 editorOnly=true；旧构建不支持该选项，须先核对 UCE-Revision=2026.10.14.2+。
