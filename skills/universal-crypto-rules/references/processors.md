# 处理器参数全集

依据 `processor/impl/{CryptoProcessor,InternalCryptoEngine,SignatureProcessor,InternalSignatureEngine,FieldProcessor,HttpApiClient}.java`。参数均在 Action.config 内；不要用 schema 内不存在的 CryptoJS 配置格式。共同字段 inputSource/inputName/variableName/executionPhase/editorOnly 见 [规则语义](rule-format.md)。下文只承诺实际实现，不以 Constants 中声明的名字推断支持。

## 方案选择

| 协议 | 首选路径 | 限制 |
|---|---|---|
| JSON 顶层字段 AES-CBC/ECB/GCM、DES、3DES、SM4 | crypto + internal | 对称加密只支持 JSON object 外壳；GCM 内置无 AAD；可用字段名 regex |
| PBKDF2 + AES-GCM、AAD、嵌套/分离 tag/二进制帧 | script + Crypto/Bytes | GCM tag 固定 128 bit，KDF 固定 PBKDF2-HMAC-SHA256 |
| RSA、SM2 加解密 | crypto + internal | 支持 raw 或 JSON；密钥 DER 类型必须对应；不提供任意协议分块 |
| 文本编码、摘要 | crypto + internal | Base64/Hex 解码到 plain 会按 charset 转成文本；二进制须保持 base64/hex 或改用 Bytes |
| UTF-8 文本 key 的 HMAC、加盐摘要、RSA 签名 | signature + internal | HMAC key 不解码 keyFormat；RSA verify 非标准公钥验签实现 |
| 二进制 key HMAC-SHA256、复杂签名拼接 | script + Crypto/Hash | key/data 参数顺序注意区别 |
| 简单 JSON 字符串字段增删改 | field | 受限 JSONPath，不自动创建父节点，值类型为字符串 |
| 其他算法/库/压缩/专有协议 | 已获授权的 external 服务，或用户允许扩展代码 | 沙箱禁止通过 Packages 导入 Java 或 Node 库；当前没有 gzip/任意库加载辅助 API |

## 内置 crypto

必须设置 actionType=encrypt/decrypt；algorithm、keySource 为必填。**cryptoProvider 缺省 external**，本地规则必须显式 `"internal"`。

部署前核对 [新旧 BC 构建边界](validation.md#源码模式与打包模式)：当前修复包独立加载嵌入式签名 BC，内置算法 packaged 验证已通过。旧合并 BC 的 fat JAR 仍影响 javax.crypto 门控的 AES/SM4/DESede、HMAC、PBKDF2 等；仅算法参数正确或 source 通过不能保证旧包可部署。

### 通用参数

| key | 取值/默认 | 实际含义 |
|---|---|---|
| algorithm | 见下表，必填 | 算法、模式或 codec |
| cryptoProvider | internal / external；默认 external | 计算位置 |
| keySource | static / lookup / cached / none；必填 | static 用 keyValue；none 仅 internal，且只有无密钥算法或独立 RSA key 字段时合适 |
| keyValue | string | static key 的字面值，**不解析 `${...}`** |
| keyFormat | base64（默认）/hex/plain | 对称 key 解码；plain 使用 UTF-8，不受 charset 参数影响 |
| payloadFormat | json / raw | 对称默认 json 且只能 json；非对称默认 json 但可 raw；codec/hash 默认 raw |
| cipherField | string | 对称/非对称默认 ciphertext_b64；codec 默认 ciphertext；hash JSON 输出默认 hash |
| plainField | string，通常回退 cipherField | 解密输出/加密输入字段；解密后作为 JSON 字符串值，不自动 parse 嵌套明文 JSON |
| cipherFormat | base64 / hex / plain | 密文字节表示；对称/非对称默认 base64；hash 默认 hex |
| plainFormat | plain（默认）/hex/base64 | 明文字节与字符串之间的表示方式；二进制明文可以保留为 base64/hex |
| charset | UTF-8（默认）或 Java charset 名 | 明文文本转换和 hash 内容编码 |

### 算法与模式

| algorithm | 实现 |
|---|---|
| aes-gcm / aes-cbc / aes-ecb / aes | AES；aes 默认 CBC |
| des-cbc / des-ecb / des | DES；des 默认 CBC |
| 3des-cbc / 3des-ecb / 3des / triple-des / desede / desede-cbc / desede-ecb | DESede |
| sm4-cbc / sm4-ecb / sm4 | SM4，使用 BC |
| rsa / rsa-ecb / rsa-oaep | RSA，名字不会自动切换 OAEP padding，仍需 rsaPadding |
| sm2 | BC 的 SM2 Cipher 默认模式 |
| base64 / base64-encode / base64-decode | 文本/表示形式转换 |
| hex / hex-encode / hex-decode | 文本/表示形式转换 |
| url / url-encode / url-decode / urlencode / urldecode | Java 表单 URL 编解码，空格编码为 `+` |
| md5 / sha1 / sha-1 / sha256 / sha-256 / sha512 / sha-512 / sm3 | 摘要，不可逆；actionType 不会使其可解密 |

`aes-256` 虽在 Constants 中出现，不是 InternalCryptoEngine 的已支持 algorithm。AES-256 应写 `aes-gcm`/`aes-cbc` 并传 32 字节 key。

### 对称参数和字段规则

| key | 默认/取值 |
|---|---|
| aesMode | 名称含 gcm→GCM，ecb→ECB，其余 CBC；显式值覆盖名称，且此 key 也被 DES/SM4 分支使用 |
| padding | GCM→NoPadding；其他→PKCS5Padding；可按 BC transformation 指定 NoPadding 等 |
| gcmTagLength | 128，单位 bit；JCE/BC 支持的长度需实际验证 |
| ivField | iv_b64；可设置普通顶层字段名或 regex:... |
| ivLiteralValue | 非空则优先于正文 ivField；按 ivFormat 解码 |
| ivFormat | base64（默认）/hex/plain；plain 为 UTF-8 |

cipherField/plainField/ivField：对称分支仅解析顶层字面字段，`data.cipher` 是含点的字段名，**不是路径**。`regex:^encrypted_.*$` 对顶层名称使用完整匹配，取迭代中首个匹配；不是替换所有字段。输出字段若为 regex 必须找到已有匹配字段，不能凭 regex 创造字段。

加密从 plainField 取文本（JsonNode.asText），写 cipherField；解密反向操作。非文本 object/array 不能当作自动序列化明文，须脚本 JSON.stringify。普通字段不存在时输出字段可以新建。原字段若不同名会保留，不自动删除。

非 ECB：IV 优先 literal，其次正文现有字段；加密缺失时生成随机 IV 并写入 ivField。GCM 默认生成 12 字节，AES/SM4 CBC 16，DES/3DES CBC 8。固定/复用已有 IV 必须是协议明确需求，不把固定测试 IV 用到随机加密协议。GCM 密文输出包含认证 tag；无独立 AAD 参数，不会把额外字段隐式用作 AAD。

### 非对称参数

| key | 默认/行为 |
|---|---|
| rsaPublicKey | 加密公钥，优先于 keyValue；X.509 SPKI PEM/DER Base64 |
| rsaPrivateKey | 解密私钥，优先于 keyValue；PKCS#8 PEM/DER Base64 |
| rsaMode | ECB |
| rsaPadding | PKCS1Padding；OAEP 要显式指定准确 transformation |

rsa-oaep 名称本身不会自动启用 OAEP。当前无独立 OAEP/MGF1 参数对象配置，严格 SHA-256/MGF1 或 label 协议必须通过测试或 external 精确实现。不自动分块处理长 RSA 明文。SM2 采用 BC 默认 Cipher，不能未经测试假设匹配 C1C2C3/C1C3C2 的任意对端。

SM2 密钥加载已改为 `KeyFactory("EC", provider)`，接受 sm2p256v1 的 X.509 SPKI 公钥、PKCS#8 私钥（PEM/Base64）；配置仍使用 rsaPublicKey/rsaPrivateKey，不改现有规则字段。测试生成密钥使用 EC generator + ECGenParameterSpec("sm2p256v1")。BC 1.70 本身未注册 SM2 工厂/生成器别名，直接调用这些别名仍失败。当前 Cipher("SM2") 默认为 raw C1C2C3，已用 OpenSSL 独立向量验证；ASN.1 或 C1C3C2 协议需转换，不会自动识别。

### codec/hash 细节

`*-decode` 名称或 decrypt 动作触发解码；encode 后缀优先对应编码。keySource=none + internal 适用于 codec/hash。raw 支持整段文本；json 支持顶层 cipherField/plainField。codec 的 plainFormat=base64/hex 能避免把解码字节直接当 UTF-8；最终想发原始字节用 script Bytes，内置处理器结果仍以字符串传递。

hash 分支对整个输入 content 按 charset 求摘要；payloadFormat=json 时把摘要写到 cipherField，**不是先提取 plainField 再 hash**。若只对某字段摘要，先脚本提取变量，再用 inputSource=variable，或一个 script 完成。

### keySource=lookup / cached

lookup 需要 lookupMethod、lookupEndpoint；lookupHttpMethod 默认 POST；responseKeyPath 默认 key。先调用 `lookup_key` 取得 key，再执行加/解密。internal 完成 lookup 操作后保存 cached_key；external 分支仅当计算响应 metadata 含 key 时缓存，而当前 HttpApiClient 正常响应不自动产生 key metadata。不要假设 lookup/external 一定填充 cached_key。

cached 固定读取共享名 cached_key，缺失时 fallbackLookup=true 可再 lookup。它不是进程级永久缓存，作用域见 [共享语义](rule-format.md)。没有缓存写入路径就不选 cached。纯 crypto static 不会自动把 keyValue 写入 cached_key。

## 内置 signature

actionType=sign/verify；algorithm、keySource、signContent 必填；cryptoProvider 默认 external。

内置 HMAC 使用同一个独立加载的签名 BC Provider 对象；当前修复包的示例 06 已在 packaged 模式精确验证 X-Signature 写入。旧合并 BC 的 fat JAR 中 Mac 认证失败，签名头缺失或保留旧值；生成规则时先核对部署构建。脚本 HMAC 使用默认 JCE provider，示例 05 另行验证通过。

| key | 默认/行为 |
|---|---|
| algorithm | hmac-sha256/hmac-sha1/hmac-sha512/hmac-md5/hmac-sm3（或 sm3hmac）、md5/sha1/sha256/sm3、SHA256withRSA 等 |
| keySource | static 使用 keyValue；lookup 可调用服务并在当前上下文保存 signature_key；none 给空 key（只适用于不需要 key 的 hash）；没有通用 cached 分支 |
| signContent | body / method+path+body / custom |
| customSignTemplate | custom 使用 TemplateEngine；未提供时回退 content |
| cipherFormat | hex（默认）/base64/plain；plain 不适合随机签名字节 |
| signatureHexCase | lower（默认）/upper，仅 hex |
| hashKeyPlacement | suffix（默认）/prefix/both/none，用于普通摘要，不改变 HMAC |
| sortKeys | true 时规范化待签内容 |
| pairSeparator / kvSeparator | 默认 `&` / `=` |
| urlEncodeValues | true 时用 Java URLEncoder 编码值 |
| headerTemplates | object：预先生成并写入当前 processor context 的头，成功结果再通过 metadata.setHeaders 写回 |

method+path+body 是 METHOD + URL.getPath() + content，没有分隔符、没有 query。精确协议用 custom 或脚本。body 指动作的 content，不保证就是报文正文，因此 Header 目标必须设置 inputSource。

sortKeys 对 JSON **顶层**按字母排序并输出 k=v 对，不是递归 canonical JSON；嵌套值直接 JSON 字符串化。query 规范化用 TreeMap 会折叠同名参数；还会 decode 值，按 urlEncodeValues 决定是否重新编码。重复 query、特别的空格编码/Unicode/小数规则应脚本按协议实现。

HMAC 内置将 keyValue 按 UTF-8 编码，不读取 keyFormat。Base64/Hex secret 必须脚本解码后调用 Crypto.hmacSha256。普通摘要默认是 hash(data||key)；无需 key 的 SHA256 应 keySource=none + hashKeyPlacement=none，或者 Hash.sha256。

RSA sign 需要 PKCS#8 私钥。实现虽会剥离 `RSA PRIVATE KEY` 标记，仍然使用 PKCS8EncodedKeySpec；PKCS#1 DER 不因此自动获得支持。

签名写回：header 目标返回签名；field 目标且 targetName 非空时，sign 处理器将签名写入 JSON 顶层字面字段并返回完整 JSON。body 目标直接把整个正文替换为签名，通常不是想要的结果。嵌套签名字段用 script。

headerTemplates 在构造待签名数据前执行，可以 `${header.Timestamp}` 引用同一个生成值。timestampHeader/timestampFormat 虽会产生 metadata.timestampHeader/timestampValue，但当前写回路径只处理 setHeaders，**不要依赖这两个字段自动写时间戳头**。`${timestamp}` 是 ProcessorContext 毫秒值；想用秒需要 script 或显式协议转换。

### verify

| key | 用途 |
|---|---|
| signatureSource | header（默认）/fixed/body-field/query |
| signatureHeader | 默认 X-Signature |
| expectedSignature | fixed；未指定 source 而有 expectedSignature 时也优先 fixed |
| signatureFieldPath | 默认 $.signature，支持受限点路径和数组访问 |
| signatureQueryParam | 默认 sign |

内部 verify 通过再次计算签名然后比较字符串。Base64 精确比较；其他格式忽略大小写。HMAC/摘要适用，但 **不是使用 RSA 公钥的标准 Signature.verify**，不能声称支持 RSA 公钥验签。返回字符串 true/false，false 仍可 success=true。使用 targetType=variable 保存验证结果，随后自己处理；不要 targetType=body 破坏报文。缺失签名值会返回 failure。

## field

actionType 与 config.operation 一致：replace/add/remove。fieldPath 必填。

| key | 用途 |
|---|---|
| operation | replace / add / remove |
| fieldPath | `$.userId`、`$.data.items[0].name` |
| to | replace/add 必填，**总是字符串**；支持 TemplateEngine |
| from | replace 可指定原值，缺省或 auto 表示不校验 |
| overwrite | add 默认 false；true 可覆盖已有字段 |
| ignoreNotFound | remove 默认 false；true 时目标不存在不算失败 |

仅支持 $. 开头、字母/数字/下划线/连字符字段名、每段可带非负数组索引；没有 wildcard/filter/recursive descent/quoted keys/JSON Pointer。父对象和数组容器必须存在；数组添加并非任意 append。写数字、boolean、null、对象或数组用 script JSON.parse 后赋值。field 处理器返回整个 JSON，targetType=field/body 都按完整正文写回；targetName 不是其路径来源。

## TemplateEngine

只在 field.to、signature.customSignTemplate、signature.headerTemplates 等明确调用它的位置解析，不会自动遍历任意 config；scriptCode 不进行 `${...}` 替换，也没有自动 shared-variable 模板。

| 表达式 | 返回值/边界 |
|---|---|
| ${method}/${path}/${host}/${query}/${body} | 当前 method、无 query 的 path、host、原 query、当前动作输入 |
| ${timestamp} | 当前 ProcessorContext 的毫秒时间戳，不是自动秒时间戳 |
| ${header.X-Name} | 大小写不敏感的当前 Header，缺失空字符串 |
| ${uuid}/${uuid32} | 每次解析随机 UUID / 去连字符 UUID |
| ${queryjson} | query JSON；重复参数形成数组 |
| ${payloadjson} | GET→query JSON，其他→解析正文 JSON |
| ${json:data.token} | 点路径取值，数组用点数字如 items.0.name；不是 $. JSONPath |
| ${base64:text}/${md5:text}/${sha1:text}/${sha256:text} | UTF-8 文本操作 |
| ${random:16} | 指定长度随机十六进制文本，不是 16 字节 Base64 |
| ${canonicalize:json:&:=:sign} | 顶层排序 k=v，逗号排除字段；json.foo 可选嵌套来源 |
| ${canonicalize:json:json:sign} | 顶层排序 JSON 并排除 sign；不递归排序 |
| ${stablejson:body/query/payload/json.foo} | 特定协议规范化：递归排序、移除 null/空对象、数值/布尔转字符串；不是普通 canonical JSON |

未知表达式保留原 `${...}`，函数异常可能变成 `<Error: ...>`，不保证阻断发送。嵌套 `${...}` 的解析存在 regex 限制，不依赖 `${sha256:${body}}` 这类复杂组合；复杂嵌套用脚本。cryptoparam 为遗留路径，未保证协议兼容，不作为通用签名配方。

## 外部 HTTP API

external 将计算委托给用户已授权的服务，不代表脚本可联网。配置全局 apiBaseUrl 与相对 endpoint；当前客户端直接拼接 base+endpoint，不支持把任意绝对 URL 当作 endpoint。

| config | 行为 |
|---|---|
| encryptEndpoint/decryptEndpoint/signEndpoint/verifyEndpoint | 各动作的相对 endpoint，实际调用必须存在 |
| encryptMethod/decryptMethod/signMethod/verifyMethod | 默认 POST |
| lookupEndpoint/lookupHttpMethod/lookupMethod/responseKeyPath | key 查询；responseKeyPath 默认 key |
| apiRequestTemplate | 原始字符串替换 `${action}` `${algorithm}` `${key}` `${data}` `${param.NAME}`，**不自动 JSON 转义** |
| apiFieldMap | 将 action/algorithm/key/data/parameters 名称映射到服务字段；推荐代替有引号风险的 JSON 模板 |
| apiHeaders | object，直接发给计算服务；不自动解析当前请求 ${header.*} |
| apiContentType | 有请求体时默认 application/json |
| apiResponsePath | JSON Pointer `/data/result`、点路径 `data.result`、受限 `$.data.items[0]`；不支持完整 JSONPath |

默认请求 JSON：`{"action":"encrypt","algorithm":"aes-gcm","key":"...","data":"...","parameters":{...}}`，无值字段省略。lookup action 为 lookup_key，parameters 含 lookupMethod 和 keyPath。GET/HEAD 不发送生成的 body，也不自动把参数转成 query；若服务需要 GET query，明确 endpoint 中的静态 query 或另行适配。

2xx 才成功；没有 apiResponsePath 时整个响应正文作为结果。提取路径不存在失败；响应非 JSON 时部分路径会回落原始文本，测试必须检查真实输出。key/data 都可能传出本机，不把调用服务作为未授权的默认验证步骤。

## 声明但不应凭空依赖的功能

`scriptEngine` 不切换引擎，当前固定 Rhino；`maxContentLength`、通用 KEY_FORMAT 在 signature、任意动态 ${shared.*} keySource、脚本 Java 库导入、Header 删除、Query/Cookie 写回、WebSocket、完整 JSONPath、AES-256 名称别名、标准 RSA 公钥 verify 不能仅因常量、UI 提示或名字存在就假定可用。需要实现支持和实际测试；本技能不会把计划中的能力当成接口。
