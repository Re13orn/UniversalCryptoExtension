# 验证流程与限制

第 8 节起为历史验证记录。当前版本可按前 7 节使用仓库内的规则和 fixtures 重跑验证。

## 1. 构建及版本核对

当前仓库最低 Java 17，建议使用已验证的 JDK 21。当前 1.0.0 版本号不足以识别新旧引擎；核对 ScriptProcessor 辅助 API、RuleSerializer.ENGINE_BUILD、pom.xml Rhino 1.8.1 或加载日志。

```bash
cd /path/to/UniversalCryptoExtension
./build.sh
```

只需要规则验证时无需重复全套构建，若 target/classes 和发布 JAR 已对应当前源码可直接使用。使用 --project 时工具检查源码/pom 是否比 JAR 新；source 模式额外检查各主源码的 class 是否存在。独立发布 JAR 可以使用 --jar，不依赖 target/classes、源码或 Maven；陈旧或不完整构建会明确失败，提示重新 ./build.sh，不静默切换 mock。文件时间检测不等同完整的可复现构建指纹；复制旧构建并修改时间的情况仍需自行核对。

### 源码模式与打包模式

默认 `--runtime source` 使用 target/classes 加发布 JAR 的其余依赖；`--runtime packaged` 仅使用发布 JAR。修复后的内置引擎在两种模式均由 `BouncyCastleSupport` 加载自己的嵌入式原始签名 BC JAR，不依赖本机 Maven BC classpath 或全局 BC 注册。`--bc-jar` 仅作为旧构建的可选额外 source classpath 参数，不能覆盖新引擎的独立 BC provider。两种模式都不是 mock，结果必须分别标明。

```bash
python3 /path/to/skill/scripts/check_rule.py --project /path/to/plugin \
  --rules /path/to/rules.json --fixtures /path/to/fixtures.json --runtime packaged
```

**当前部署方式（已修复）：**发布单 JAR 中 `META-INF/lib/bcprov.jar` 是 Maven 原始签名 BC 1.70 JAR 的完整副本；外层不包含 `org/bouncycastle/` 类。运行时将嵌入 JAR 复制到私有临时文件，从以 platform classloader 为父级的独立 URLClassLoader 加载，并验证证书和 HMAC JCE 认证。所有内置算法传入同一个 Provider 对象，不注册、不替换 Burp 全局 BC provider。扩展卸载时关闭加载器并删除临时 JAR；加载失败返回明确错误，不能切换到未签名 BC 类。临时目录需可写，磁盘清理失败时保留 deleteOnExit 兜底。

区分新旧构建：Manifest `Crypto-Provider-Layout: signed-bc-nested-v1`、嵌入 JAR 和加载日志 `Signed BC provider loaded`；规则 schemaVersion/engineBuild 保持兼容，1.0.0 版本号及 Rhino engineBuild 不能单独证明已修复。

SM2 密钥加载已改为 `KeyFactory("EC", provider)`，使用 sm2p256v1 的 X.509 SPKI 公钥和 PKCS#8 私钥；生成测试密钥使用 `KeyPairGenerator("EC", provider)` + `ECGenParameterSpec("sm2p256v1")`。BC 1.70 的 `SM2` 工厂/生成器别名本身仍未注册。内置 `Cipher("SM2")` 默认 raw C1C2C3；OpenSSL ASN.1 密文必须按协议转换，不能直接当作 raw Base64 输入。独立向量和篡改拒绝验证见第 9 节。

**修复前的 BC 认证边界（Oracle JDK 21.0.10）：**旧 shade 配置移除依赖签名，将 BC 类合并到扩展 fat JAR。影响范围是使用该未认证 BC provider、受 `javax.crypto` 认证门控的服务，不限于 AES：`Cipher` 的 AES、SM4、DESede 等，以及 `Mac` 的 HMAC、`SecretKeyFactory` 的 PBKDF2 均受影响。典型错误为 `JCE cannot authenticate the provider BC`。不能从某个 BC 摘要或 `java.security` 服务成功推断这些服务可用，也不能以 source/Maven 测试通过认定 fat JAR 可部署。

**修复前内置 HMAC 签名也失败：**旧内置 signature 明确调用 `Mac.getInstance(algorithm, new BouncyCastleProvider())`，示例 **06 的 `Mac HmacSHA256` 在旧 packaged 模式失败**，不产生新签名头。HTTP 链会跳过失败动作：无旧签名头时该头缺失，有旧头时可能保留旧值，不能当作有效新签名继续部署。示例 02 的内置 AES-CBC 同样失败。

脚本 `Crypto.pbkdf2`、`Crypto.hmacSha256`、`Crypto.aesGcm*` 使用未指定 provider 的标准 JCE 调用；本环境由默认 provider 执行，示例 03/04/05/08 的 packaged 验证通过。这与显式指定 BC 的同类服务失败不矛盾。其他 JDK/provider 顺序仍需单独验证，不把“PBKDF2 受影响”扩大成所有 provider 的 PBKDF2 都失败。

用户提供的修复前同 JDK、同插件 JAR 的 18 项服务探测对照如下；此处记录用户实测数据，交付物未附该次探测程序，因此不把它声明为本工具复现的 18 项报告：

| classpath 模式 | BC 类签名证书 | 18 项探测失败数 | 解释 |
|---|---|---|---|
| 仅 fat JAR | 无 | 8 | 包含 BC 的 JCE 认证失败及以下独立 SM2 限制 |
| 原始签名 BC JAR 放在 fat JAR 前 | 2 张 | 2 | JCE 认证相关失败消失，SM2 别名限制仍在 |

**SM2 是另一个独立问题：**BC 1.70 未注册 `KeyFactory("SM2")` / `KeyPairGenerator("SM2")` 别名，这两项在两种模式均失败，与 provider 认证无关。旧内置 SM2 密钥加载使用 `KeyFactory.getInstance("SM2", "BC")`；即使原始签名 BC JAR 位于前面，也不能因此宣称内置 SM2 加解密可用。算法名/别名不可用与 `JCE cannot authenticate` 应分别诊断；只修复签名依赖不会补上别名。

上述记录针对旧 JAR；修复后的结果见第 9 节。BC 1.70 本身的 SM2 别名仍未添加，插件改用正确的 EC 路径解决功能问题，不能把别名缺失探测误写成现在插件 SM2 仍不可用。

独立发布包可直接验证：

```bash
python3 /path/to/skill/scripts/check_rule.py --jar /path/to/plugin.jar --rules rules.json --fixtures fixtures.json
```

只需 Python 3 与 JDK 17+。该命令自动选择 packaged，不读取当前用户配置；源码对照时仍用 --project 和 --runtime source。

## 2. 两级离线验证

结构验证（不执行脚本）：

```bash
python3 /path/to/universal-crypto-rules/scripts/check_rule.py \
  --project /path/to/plugin --rules /path/to/output.rules.json
```

它编译并运行 bundled RuleProbe.java，调用真实 RuleSerializer.importRules、ProcessorInterface.validateConfiguration；此外拒绝未知 JSON/config 字段、无 condition、无动作和缺失目标名。结构通过不证明算法、key、IV、明文向量正确。

样例验证（执行真实 Rhino/内置引擎）：

```bash
python3 /path/to/universal-crypto-rules/scripts/check_rule.py \
  --project /path/to/plugin --rules /path/to/output.rules.json \
  --fixtures /path/to/output.fixtures.json
```

不使用 ProcessorFactory.createTestProcessorManager，因为那条路径带 mock crypto。工具使用 createDefaultProcessorManager(null)，internal/script/field 是真实计算；external/lookup/fallbackLookup 用例拒绝执行，绝不联网。临时 RuleManager 使用临时配置目录，规则只在该模拟中启用，不读写当前用户规则、不调用 Burp UI 或 HTTP client。

## 3. Fixtures 格式

```json
{
  "cases": [{
    "name": "响应展示",
    "direction": "response",
    "route": "response-display",
    "method": "POST",
    "url": "https://api.example.test/api/demo",
    "headers": {"Content-Type": "application/json"},
    "body": "ciphertext-text",
    "messageId": 1,
    "expect": {"matched": true, "success": true, "body": "expected-plaintext", "errors": 0}
  }]
}
```

每个用例必须有非空 expect。仅检查 success 而无内容 oracle 不能验证解密正确，除非是随机输出/明确错误路径。

| 字段 | 说明 |
|---|---|
| direction | request（默认）/response |
| route | wire（默认）走真实 HttpInterceptor；请求可 display/editor-send；响应可 response-display/response-editor-send，走真实 RuleProcessingService |
| method / url | method 默认 POST，url 必填。url 决定 host/path/query |
| toolSource | 可选，默认 REPEATER；若未指定，wire 请求也会执行 editor-send，忠实模拟 Repeater 回调 |
| headers | 当前方向 Header object；响应仅为响应头 |
| requestHeaders | 响应用例可选的原请求 Header object，独立于 headers，不参与规则匹配；省略表示不可用 |
| body / bodyBase64 | 二选一，后者先解码成原始字节，适合 GBK/gzip/二进制；都无时正文空串 |
| messageId | optional int；wire 配对共享使用同一个 ID，cases 顺序就是报文顺序 |
| expect.body | 精确字符串比较，不自动 JSON 结构排序 |
| expect.bodyBase64 | 仅 wire 原始正文的精确 bytes 比较 |
| expect.headers | 子集、头名忽略大小写，不要求仅存在这些头 |
| expect.matched | wire 表示有启用规则满足条件；不保证有适用动作；phase 服务表示该服务 outcome 的匹配状态 |
| expect.success | wire 无上下文错误且无 Action Failed 事件；phase 使用 outcome.isSuccess |
| expect.errors | 动作失败/处理错误计数；phase 失败为 1 |
| expect.unchanged | 正文和头是否未改；wire 按 bytes 比较 |

报告含规则数、动作数、外部执行标记、通过用例数和实际输出。检查失败退出码非零。测试输出可能含明文/签名，请使用脱敏 fixtures。全局 `--timeout` 默认 90 秒，整个 Java probe 超时会失败，不绕过脚本超时。

wire 模拟未调用 Montoya ByteArray/continueWith 工厂，也不验证最终线上 Content-Length、Burp 编辑器启用条件或真实 messageId 分配。phase 模拟也不执行请求编辑器的 UI 判定；写请求 display 规则时仍要满足 actionType=decrypt/body-or-field。不要将工具通过等同真实 Burp 全流程通过。

## 4. 推荐验证组合

按协议选择：

1. 固定向量：真实/脱敏 plaintext↔ciphertext 或 data↔signature，与独立实现对照。
2. 编码：中文、非 ASCII password、随机 key/IV、base64 padding、Hex 长度；有 binary 输出时逐字节比较。
3. 认证：改一个 tag/ciphertext/AAD byte，必须拒绝；错误不是“成功返回密文”。
4. 匹配：非目标 host/path/method/工具，不应改写；response Content-Type 与 request 不同的路径也核对。
5. 阶段：response-display 页签有明文，wire 原响应不变；实际 rewrite 单独使用 response-send。
6. 编辑：展示后修改明文、editor-send 加密、Repeater 回调再次经过加密动作时不重复加密。
7. 依赖：request/response-send 配对，乱序响应、无共享值、超过 TTL 的行为。
8. 错误：无 return 保留输入、JSON 无效、字段不存在、单动作失败后后续动作是否仍可执行。

随机输出不能固定期望密文：工具报告捕获实际 body，另建 fixture 回输解密并比较原始明文；重复明文加密可检查 IV 随机且不复用。生成 fixtures 时不要以插件自身生成的错误值作为唯一正确 oracle。附带资产的固定向量使用独立实现求得。

## 5. 故障定位表

| 现象 | 优先核对 |
|---|---|
| 导入成功但不执行 | UI 导入默认禁用；rule.enabled/action.enabled；condition 是否 null；host/path/method/toolSource；phase |
| 请求明文页签不出现 | showInEditor、decrypt 动作名、body/field 目标、display 阶段、规则是否匹配、请求正文是否为空 |
| 响应页签有但无明文 | response-display，响应 Content-Type/headers 条件；当前方向变量；异常日志 |
| Repeater 发送后仍是明文 | 是否匹配 editor-send/send；相位服务检查的是编辑后上下文；encrypt 异常是否跳过 |
| Repeater 发送后双重加密 | editor-send 在页签和 Repeater callback 都执行；加密脚本必须检查已加密外壳 |
| Packages/Java/getClass 不可用 | 这是沙箱设计；改用真实辅助 API，不能通过更换导入方式绕过 |
| PBKDF2 参数正常但 key 不同 | password Unicode 处理，salt 是 UTF-8 还是 Base64，iterations，bits vs bytes，PRF |
| AEADBadTagException/认证失败 | key、salt/KDF、IV、ciphertext||tag、AAD 的每个字节；不要通过取消验 tag 修复 |
| AES invalid key length | 解码后的 bytes 为 16/24/32；不是字符长度；Base64/Hex 是否错当 plain |
| IV/字段找不到 | 对称 cipherField/ivField 是顶层字面名，不是 JSONPath；regex 仅首个已有匹配 |
| internal crypto 报 JSON required | 对称 raw 不支持；JSON 外壳或更合适的脚本/服务方案 |
| 加密后多了引号或明文变字符串 | obj.put 输出字符串；JSON.stringify 已是 JSON 的文本导致双层编码；是否需要 JSON.parse |
| Header 签名与独立结果不同 | inputSource 是否明确 body；Hash vs Crypto 参数顺序；UTF-8 key vs decoded key；METHOD/path/query/分隔符 |
| 时间戳签名不一致 | 毫秒 vs 秒；多次 uuid/random/timestamp 生成；timestampHeader metadata 不自动写回 |
| 变量值变成奇怪字符串 | variable/inputSource 会 String 化；byte arrays 用 ctx 直接传，不走文本变量路径 |
| 响应共享 key 为 null | 只在 wire messageId 配对；不是 UI 全局；TTL/响应已消费/无先前缓存写入 |
| verify=false 但动作成功 | success 是处理完成，不等于验签通过；返回 false 字符串，禁止 target body |
| 外部服务返回整段 JSON | apiResponsePath；不是业务 JSONPath；未知/非 JSON 回落；真实响应核验 |
| JCE cannot authenticate the provider BC | 旧合并 BC 的 fat JAR 会影响 AES/SM4/DESede、HMAC、PBKDF2 等；确认新嵌入式签名 BC 构建、证书与加载日志。示例 06 在新包已通过，不能更改协议参数掩盖加载故障 |
| SM2 KeyFactory/KeyPairGenerator 不可用 | BC 1.70 无 SM2 工厂别名；插件已改用 EC + sm2p256v1。直接调用 SM2 别名仍失败，与 JCE 认证问题分开 |
| JSON 配置看似正确却参数没生效 | 未支持/拼写错误 config 被忽略；不是任意字段都进行 ${...} 模板解析 |
| GBK/gzip 原始内容乱码 | 用 bodyBytes 原始输入，文本 charset 与 byte 管道分开；展示服务不等于 byte 精确 wire 写回 |

## 6. 实机验证和授权边界

只有用户授权导入/启用/发送时才实际改变插件状态或请求。离线 JSON/构建/临时测试可直接完成。验证本地文档不需要打开业务系统，也不需要把 key 发给外部服务。

真实 Burp 测试应确认：规则页差异/禁用状态、请求和响应页签出现条件、原始响应保留、发送前重新加密、实际线上的字节和 Content-Length、并发 messageId 对应、失败日志不损坏无关报文。没有执行这一步就交付“离线已验证，实机待验证”，不要夸大。

## 7. 维护技能

源码路径变化时用 rg 搜索相应类；版本升级后重核对 RuleSerializer、Constants、ScriptProcessor、HttpInterceptor、RuleProcessingService、各 InternalEngine 与 editor。修改接口时同步相应 reference 与资产向量，并通过真实引擎重跑对应 examples。SKILL.md 是路由及核心约束，不复制所有参数表到入口。

## 8. 本次验证记录（2026-10-10）

**本节为修复前历史快照。当前修复验证见第 9 节。**

环境 Oracle JDK 21.0.10，BC 1.70；发布 JAR 为 `target/universal-crypto-extension-1.0.0.jar`，SHA-256 `df99c8fb8b0b109f5ac78383488282087f5f831e8bffe56f2e72d569f8185f0c`。本技能结构校验通过；本地引用均已检查。此前 9 组资产 source 模式 19 个用例通过。本次逐组重跑 packaged 模式，完整结果如下：

| 示例 | source 已通过用例数 | packaged 本次结果 |
|---|---:|---|
| 01 文本 Base64 | 2 | 通过 2 |
| 02 内置 AES-CBC | 2 | 失败：BC JCE 认证；首个解密用例失败即退出，未完成整组 |
| 03 脚本 PBKDF2-GCM | 5 | 通过 5 |
| 04 脚本分离 tag/AAD | 2 | 通过 2 |
| 05 脚本二进制 HMAC | 1 | 通过 1 |
| 06 内置 HMAC 签名 | 1 | 失败：Mac HmacSHA256 的 BC JCE 认证，新签名头未生成 |
| 07 JSON 字段 | 1 | 通过 1 |
| 08 脚本 raw binary GCM | 1 | 通过 1 |
| 09 共享 wire 上下文 | 4 | 通过 4 |

packaged 共 7 组、16 个用例通过，02/06 不计入通过。用第 1 节命令传入对应 `assets/examples/NAME.rules.json`、`NAME.fixtures.json` 可重放；02/06 应以非零退出码和认证错误识别其预期部署失败，不能把日志中的失败记为成功。此前还捕获了随机加密输出并回输解密，精确还原中文明文；该额外实验未纳入以上 16 个固定 fixtures 用例数。

## 9. BC 打包与 SM2 修复后验证（2026-10-10）

本节保留 BC/SM2 修复阶段构建快照。后续 HTTP/JSON 展示的当前构建见第 11 节。

`./build.sh` 现运行 `mvn clean verify`，然后对规范化后的最终 JAR 再运行独立 JVM 密码探测，防止 Maven 正常而最终包损坏。`mvn verify` 的 Failsafe 集成测试只用发布 JAR 和测试 probe 启动子 JVM，不继承 Maven 依赖；还覆盖已有全局 BC 的场景。加载器单元测试覆盖并发共享、嵌入依赖缺失及签名内容被篡改时拒绝。

Oracle JDK 21.0.10 上，274 项单元测试、2 项打包集成测试通过；最终包中的 BC 与 Maven 原始签名 JAR 字节一致，证书为 2 张。新 18 项服务探测全部通过：AES CBC/GCM/ECB、DES、DESede、SM4、RSA PKCS1/OAEP、EC sm2p256v1 密钥工厂/生成器、SM2 OpenSSL 独立向量、5 种 HMAC、BC PBKDF2、SHA256、SM3。这是本次附带程序的新矩阵，不是对用户历史 18 项探测的逐项重放；新矩阵使用正确的 EC 路径，未声称添加 BC 的 SM2 别名。最终 JAR SHA-256、测试统计见 构建验证信息。

| 示例 | 修复后 source | 修复后 packaged |
|---|---:|---:|
| 01 文本 Base64 | 2/2 | 2/2 |
| 02 内置 AES-CBC | 2/2 | 2/2 |
| 03 脚本 PBKDF2-GCM | 5/5 | 5/5 |
| 04 脚本分离 tag/AAD | 2/2 | 2/2 |
| 05 脚本二进制 HMAC | 1/1 | 1/1 |
| 06 内置 HMAC 签名 | 1/1 | 1/1 |
| 07 JSON 字段 | 1/1 | 1/1 |
| 08 脚本 raw binary GCM | 1/1 | 1/1 |
| 09 共享 wire 上下文 | 4/4 | 4/4 |

两种模式各 9 组、19 个用例通过。示例 06 的 fixture 精确核对生成的 X-Signature，确认不再缺失。独立 agent 原有 8 个 fixtures 在新最终包重放 8/8 通过。

SM2 用例读取 `src/test/resources/crypto/sm2-openssl-vector.json`（合成测试密钥），验证私钥解密独立密文、公钥加密/JSON 保留字段和 C3 篡改拒绝；`scripts/generate-sm2-vector.py` 只在重新生成向量时需要支持 SM2 的 OpenSSL。该生成器使用新随机测试密钥/密文，因此重生成值变化是正常的。已有固定向量回归不依赖 OpenSSL。项目源码测试与该资产中的向量一致。

从插件仓库根目录复核：

```bash
mvn verify
# 对 build.sh 交付路径也构建并执行最终包密码回归：
./build.sh
# 可独立重放最终包的 18 项密码矩阵：
java -Djava.awt.headless=true \
  -cp target/universal-crypto-extension-1.0.0.jar:target/test-classes \
  com.universal.crypto.packaging.PackagedCryptoProbe
# 重放 HMAC Header 规则；其他示例替换文件前缀：
python3 skills/universal-crypto-rules/scripts/check_rule.py --project . \
  --rules skills/universal-crypto-rules/assets/examples/06-internal-hmac-signature.rules.json \
  --fixtures skills/universal-crypto-rules/assets/examples/06-internal-hmac-signature.fixtures.json \
  --runtime packaged
```

未执行真实 Burp 页签/流量验证，未跑 JDK 17/26；当前结果是本机 JDK 21 的真实处理器及单 JAR 打包验证。

## 10. 原始 HTTP 头显示开关验证（2026-10-10）

Universal Crypto 请求/响应页签新增右键菜单“Show original HTTP headers”开关，正文区域不再常驻工具栏，默认显示完整 HTTP 头，右键取消勾选可切换为仅正文；完整视图使用原始报文字节前缀中的请求行/状态行和全部头，再接明文正文。头部只读，保留重复头、顺序及原 Content-Length；编辑后发送只把正文交给 editor-send。视图切换不重执行规则、不改变 isModified，保留明文编辑和当前编辑器的选择；未新增全局持久化设置。

本节保留 HTTP 头开关阶段的构建快照。该次 `./build.sh` 在 Oracle JDK 21.0.10 成功：275 项单元测试、2 项打包集成测试通过；最终单 JAR 的 18 项密码回归仍全通过。新增请求编辑器测试验证重复头保留、头部改写被拒绝、视图切换不触发加解密、明文编辑保留、发送不把请求头混入加密输入、新报文重置修改状态。响应编辑器回归验证状态行/原头显示、只读、切换不重复解密且返回原响应。

已用真实 Swing 组件的离屏渲染核对完整视图布局；未操作正在运行的 Burp，尚未验证真实 Burp 页签交互。

## 11. HTTP/JSON 高亮与展示格式化验证（2026-10-10）

请求/响应明文页签使用 RSyntaxTextArea 3.4.0（BSD，许可证保留在 JAR 的 META-INF/uce-third-party），按 Swing 当前主题设置深浅配色。请求行/状态行、HTTP 头名和 JSON 键、字符串、数字、布尔值有语法高亮，显示行号。保留原始头默认显示和右键取消选项，无常驻工具栏。未嵌套 Burp HttpRequestEditor/HttpResponseEditor，避免官方文档所述的编辑器递归问题。

有效 JSON object/array 默认展开为两空格缩进，右键 `Pretty JSON` / `Raw` 切换。JSON 先由流式解析器校验，再仅插入字符串外的空白，不反序列化/重新序列化：重复字段、数字写法、转义和顺序均保留。非 JSON/无效 JSON 原样显示。未编辑时保留精确原明文；展示切换不改变 isModified，不重执行规则。实际编辑 Pretty 正文后按编辑后的文本加密，包含展示空白；精确签名场景先切换 Raw 再编辑。展示切换清空撤销栈，防止跨模式撤销。

Oracle JDK 21.0.10 上 `./build.sh` 通过 279 项单元测试、2 项打包集成测试，最终规范化单 JAR 18 项密码探测全通过。新增验证涵盖 JSON 格式切换不误标修改、不触发发送加密、真实编辑仅把正文交给加密规则、原头保护、切换保留编辑、无效 JSON 回退、转义/重复键/数字词法保留和 JSON 语法 token。见 构建记录 与同目录测试摘要、最终包密码日志、Swing 离屏预览。

尚未操作运行中的 Burp，未验证真实 Burp 页签交互及 JDK 17/26；展示接近原生，未声称与 Burp Pretty 实现完全一致。

深色配色已按用户提供的 Burp 原生 Pretty 截图修正：头名 #D1E8F9、键 #E9C062、字符串 #93C763、数字 #79C1F4、布尔值/null #F89E57、背景 #2B2B2B。HTTP 头名改用独立 DATA_TYPE token，避免与 JSON null 的 RESERVED_WORD 颜色冲突。截图比对及离屏渲染可复核于 配色修复记录。颜色为截图近似值，未读取 Burp 内部主题定义；历史 Pretty 构建记录保持原样。

## 12. Burp 编辑器字体同步验证（2026-10-10）

请求/响应页签均从 Montoya UserInterface.currentEditorFont 读取 HTTP message display 字体设置，保留字体、字重和小数字号；行号与所有语法 token 使用同一字体，不附加高亮库默认粗体。加载新报文或组件重新显示时刷新字体，不改正文、不触发规则执行。只有无 API 的离线视图才回退至 Monospaced plain 12。

官方 API 的 [currentEditorFont 文档](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/ui/UserInterface.html#currentEditorFont()) 明确该设置来自 HTTP message display；不是通用 Appearance 显示字体。项目已有 Montoya 2023.12.1 接口包含该方法，无需升级依赖。

本机 JDK 21.0.10 下 280 项单元测试、2 项打包集成测试、最终包 18 项密码回归通过。新增回归用代理 API 向两个编辑器传入带小数字号的字体，再改变字体，验证正文、token 和行号同步且展示文本及原明文不变。未操作真实 Burp，尚未验证实际窗口的字体渲染。当前字体构建验证记录；第 11 节保留前版展示构建快照。

## 13. Repeater 正文键盘编辑验证（2026-10-10）

完整 HTTP 明文视图此前默认光标在只读头部，Cmd+A/Ctrl+A 全选还会包含只读头部，随后输入/替换会被 DocumentFilter 拒绝。可编辑请求现在在解密成功后将光标定位到正文，Pretty/Raw 或头部切换后也定位正文；快捷键和菜单 Select all 仅选择正文。选中/编辑原头仍被拒绝。READ_ONLY 创建模式保持只读，响应页签保持只读。

新增参数化回归使用 REPEATER 来源与 DEFAULT/READ_ONLY 两种模式，调用真实 Swing 键入和全选 Action：验证 DEFAULT 键入生效、全选替换正文、原头保留、模式切换后光标回到正文、editor-send 只接收编辑正文、仅执行一次加密；READ_ONLY 不接受键入、不触发发送加密。282 项单元测试、2 项打包集成测试、最终包 18 项密码探测通过。当前构建记录。

读取了运行中 Burp 的 Repeater 状态，确认现有报文已有解密成功的 JSON；未发送流量。该 Java 窗口的计算机控制未能完成可靠的页签切换/输入验证，未在运行中 Burp 重载新版插件；上述编辑流程结论来自真实 Swing Action 与代理 Montoya API 的回归测试，仍需用户重载后验证实际 Repeater 操作。未声称已证明用户报告只有这一原因。

## 14. 插件重载导致键盘动作失效的修复（2026-10-10）

第 13 节的光标/全选调整不是用户“整个正文无法输入”的完整修复。后续实验证明：RSyntaxTextArea 3.4.0 把键盘动作保存到进程共享的 UIManager 缓存（RSyntaxTextAreaUI.actionMap）和名为 RTextAreaKeymap 的 Swing keymap。Burp 重载插件后新类加载器创建的 RTextArea，与旧动作 instanceof 检查所用类不同，旧 RecordableTextAction 静默忽略所有操作。首次加载/单类加载器测试无法揭示问题。

新增 IsolatedSyntaxTextArea，自定义 installKeyboardActions：每个编辑器独立创建未命名 keymap、RSyntaxTextAreaDefaultInputMap 和本轮类加载器产生的 ActionMap，不读写库的全局动作缓存。高亮、字体、原头保护、正文加密逻辑保持不变。已存在的旧缓存无需清空，也不影响其他扩展的编辑器。

EditorReloadTest 在真实独立 URLClassLoader 中复现原版“第一次输入 ax、第二次仍是 a”，然后连续三个新加载器验证修复版的键入、退格、替换、updateUI 后继续输入和只读保护；全程确认全局旧动作缓存未被覆盖。283 项单元测试、2 项打包集成测试和最终单 JAR 18 项密码回归通过。当前构建及重载证据。之前的验证目录保留历史快照。

未在用户运行中的 Burp 重载新版；结论依据同一 JVM 中共享 Swing 全局缓存的跨类加载器复现与最终 JAR 重载探测，不声称已完成真实 Burp 鼠标/键盘验证。

## 15. Repeater 完整请求编辑（2026-10-10）

可编辑请求开放请求行、HTTP 头和解密正文；完整视图的 Select all 选择全部文本。头部与正文以空行分隔，发送时仅将头部前缀交给 Montoya HTTP 解析器，然后使用新方法、路径和头部执行 editor-send，最后写入加密正文及规则生成的头部。仅修改头部仍保留原始明文的精确文本。隐藏/显示头部与 Pretty/Raw 切换保留全部编辑。响应和 READ_ONLY 窗口仍只读。

新增回归覆盖 PATCH 方法、查询路径、Host、新增/删除和重复头的传递、仅修改头部时精确明文保留、视图切换及发送缓存；请求行错误或缺少头部空行时，不执行加密并返回原始密文请求，错误写入 tooltip 和扩展错误日志。这里不会阻止 Burp 发送原始请求。方法/路径变化可能使原规则不再匹配，无 editor-send 匹配时也保留原请求并报告错误。

Host 编辑不会改变原 HttpService 连接目标，目标需在 Burp 中设置。修改头部会通过 Montoya 文本接口重建请求，HTTP/2 专属元数据的保留尚未实机验证；未修改头部时使用原请求对象。修改后的头必须使用正常“名称: 值”格式，不支持折叠续行。Content-Length 由 withBody 根据最终密文重算；若规则随后显式改写该头，以规则输出为准。

本机 JDK 21.0.10 下 285 项单元测试、2 项打包集成测试、最终包 18 项密码探测通过。最终 JAR 的独立类加载器重载探测通过。编辑流程测试使用真实 Swing 与代理 Montoya 请求接口；未在运行中 Burp 重载验证，也未发送网络请求。本次构建及离线证据。第 13、14 节为历史修复记录，当前请求头已开放编辑。

## 16. 已勾选头部但只显示正文的兼容修复（2026-10-10）

用户截图显示 Show original HTTP headers 已勾选但请求区只有 JSON，不能归因为关闭了显示选项。此前视图直接用 bodyOffset 截取序列化报文前缀，偏移为 0 时头部会静默为空。现改为识别序列化报文中的 HTTP 首行及空行边界，保留原始头部文本；序列化信息不可用时，使用 Montoya 的方法、路径、版本和有序 headers 列表恢复完整视图。备用路径保留重复头，但不保证原始头部空白；不改明文正文和规则执行阶段。

新增真实 Swing 回归分别覆盖 bodyOffset=0 但序列化报文完整、序列化仅含正文但结构化请求信息完整，验证默认勾选仍显示头部、开关切换恢复及明文不混入头部。287 项单元测试、2 项打包集成测试和最终 JAR 18 项密码检查通过。最终包跨类加载器重载探测通过。本次证据。未在运行中 Burp 实机验证，尚未证明截图实例的具体 API 返回值。

## 17. 响应只读链路的原请求头（2026-10-10）

原缺陷已修复：响应页签和 Montoya HTTP handler 将关联原请求的 headers 独立传入 HttpResponseContext.requestHeaders，经 ProcessorContext 暴露为 request.getOriginalHeader(name)/getOriginalHeaders()。头名忽略大小写、快照只读、缺失头返回空串；无原请求时脚本返回空对象。所有 withBody/withBodyBytes/withHeader/withError 副本保留原请求头。现有 request.getHeader/getHeaders 和条件 headers 继续使用当前方向头，响应规则仍只匹配响应头。

修复不自动修改当前用户规则。仅展示解密必须用 response-display；以前为绕过缺口选用 response-send/always 的解密动作需要改为 response-display，并将读取请求头的代码改用 getOriginalHeader。这里不补请求正文或跨报文共享数据，已存在的请求头多值折叠限制仍在。

新增测试覆盖两个入口、无 initiatingRequest、大小写及不可变快照、所有响应副本、两条响应路径的脚本可见性、响应头条件不误匹配请求头。独立 Python cryptography AESGCM 固定向量验证原请求 X-Nonce 参与 AAD：正常展示精确中文明文，错误/缺失 nonce 拒绝认证，三个 wire 用例逐字节密文和 Content-Length 原样保留。第七个用例验证请求 Content-Type 不能满足响应 Content-Type 条件。原探针也保持旧 getHeader 语义不变。

fixture 的 response-display 输出 unchanged=false 只描述展示结果。线上改写由 wire 路由及原响应回归测试验证。

本次完整构建：291 项单元测试、2 项独立 JVM 打包集成测试、18 项密码检查全部通过；AES-GCM 新样例在 source/packaged 各 7/7 通过。兼容探针在明确提供原请求头后，旧 getHeader 仍只看到响应头。原请求头指当前关联请求快照，不保证是请求动作执行之前的值。

## 18. 请求方向原始头 API 对称性（2026-10-10）

ProcessorContext.forRequest 统一填充起始请求头快照，覆盖 processRequestForPhase 的 display/editor-send 和 HttpInterceptor 的 send 路径；无需规则作者分方向处理 getOriginalHeader/getOriginalHeaders。后续 Header 动作更新当前 getHeader，但起始快照不变。响应仍取关联请求头，响应条件仍只匹配响应头。每次处理调用分别建立快照，不恢复更早阶段的头部。

回归执行真实 Rhino 的 Header 修改后再读取原始值，验证三个请求阶段均得到 orig=hello、get=changed；未修改时原始/当前值一致。

本次 292 项单元测试、2 项打包集成测试、最终包 18 项密码检查通过；新增请求方向 fixtures 在 source/packaged 各 6/6 通过。未进行真实 Burp 流量验证。

## 19. Repeater 修改取值生命周期（2026-10-10）

修复 getRequest 生成修改请求后立即将 modified=false 的错误。读取或预览编辑结果不等于 Burp 已提交修改；isModified 应持续表示相对于 setRequestResponse 基线存在用户编辑。getRequest 现在缓存本次生成的密文请求，重复调用返回同一请求，不重复加密；实际文本编辑使缓存失效，下次取值重新加密；Pretty/Raw、头部显示切换不使缓存失效。只有 setRequestResponse 建立新基线才清除修改状态和缓存。

[Montoya isModified 的官方契约](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/ui/editor/extension/ExtensionProvidedHttpRequestEditor.html#isModified()) 是反映用户是否修改当前报文，并没有将 getRequest 定义为提交确认。新增 RepeaterEditLifecycleTest 使用真实 RuleProcessingService/Rhino/Crypto AES-GCM，与 JDK 独立 Cipher 核对密文：模拟 host 先预览 getRequest、再检查 isModified 并读取 outgoing，验证修改后 value=2 能发出，再编辑 value=3 后缓存失效、重取不重复加密，host 设置已提交报文后解密展示新值并清除脏状态。修复前第一次预览便会让 isModified=false，模拟 host 会选择原请求。

这证明并修复了一个可导致用户所述回退现象的生命周期缺陷，不等于已确认运行中 Burp 的具体调用顺序。测试使用代理 Montoya 消息对象及真实 Swing 和密码处理，没有发送网络请求。规则 editor-send 不匹配、加密失败或 HTTP 格式错误时仍返回原请求并报告错误，此类规则问题与生命周期问题独立。

本次完整构建 293 项单元测试、2 项独立 JVM 打包集成测试、最终 JAR 18 项密码检查通过。

## 20. Intercept 响应明文编辑（2026-10-10）

新增 response-editor-send 常量、导入白名单、Schema、动作阶段 UI、中英文提示、编辑器和离线工具路由。响应 encrypt 动作的新建默认阶段为 response-editor-send；保留 response-send 的自动线上处理语义。always 不隐式进入新阶段，StepFlowPreview 使用相同阶段边界。新增 PlaintextHttpResponseEditor，遵循 EditorMode：只读窗口不编辑，可编辑窗口仅在展示成功且明文匹配显式正文/字段加密动作时开放编辑；未编辑返回原响应。

验证真实 Rhino/AES-GCM 与 JDK 独立 Cipher：编辑、加密缓存、重复取值脏状态、显示切换、状态行/头部编辑、原请求 AAD 传递、host 新基线、HTTP 回调不重复加密；旧 response-send/always 不开放编辑，无效响应头、加密异常/noChange、禁用加密动作均保留原密文。导入导出包含新阶段并保持默认禁用。

独立 Python cryptography AESGCM + hmac 生成的 7 个 fixtures 验证原响应展示、编辑后精确密文及签名、客户端再次解密得到修改值、原/新密文 wire 不重复处理、错误 nonce 拒绝认证及非目标 host 不匹配。

Content-Length 更新依赖 Montoya [HttpResponse.withBody 契约](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/message/responses/HttpResponse.html#withBody(java.lang.String))。旧只读历史记录继续保留；当前用户配置未修改，未在运行中 Burp 操作 Forward 或发送网络请求。实际文本 HTTP 解析使用代理 API 做回归，真实 Burp/HTTP2 解析行为仍需实机验证。

本次 300 项单元测试、2 项打包集成测试、最终包 18 项密码检查通过；新阶段的 7 个 fixtures 在 source/packaged 各 7/7 通过。

## 21. 整体一致性维护（2026-10-13）

集中执行阶段判断，补齐步骤预览的新响应编辑阶段、原请求头和正确响应默认阶段。预览多行 Header 解析使用真实行分隔符，修复把全部头误读为一行的问题；由 Live Trace 进入时携带实际工具来源和原请求头。预览停止伪造外部加密成功，明确拒绝外部 provider、lookup/fallbackLookup；内置与脚本仍执行真实引擎。响应字段模板可选择添加编辑后加密，不改变已有规则。

编辑器相位服务、预览和线上链路都接收处理器 setHeaders 附加头；后续 bodyBytes 跟随当前正文，字节结果不经 UTF-8 重建。无变化结果不把 Header 输入写成正文。相位失败停止，wire 阶段继续跳过失败动作。撤销全部编辑恢复原始明文和脏状态，并丢弃已准备密文。

BUILD/VERIFICATION 和 Make/status 入口已更新；发布校验要求正确 SPI、能力标记、未合并 BC 和原始签名 JAR 的精确 SHA-256。新增同步脚本校验源码快照、Schema 阶段、资料链接、镜像及 ZIP；安装镜像仅在 --install 时处理。发布包自带 Skill，可用 --jar 独立验证。

本次 313 项单元测试、2 项打包集成测试、18 项密码服务检查通过；10 组标准示例和独立 forward-test 合计 34 个 fixtures，在 source/packaged 各 34/34 通过；独立 JAR 模式响应编辑示例 7/7 通过，发布维护脚本 6 项回归通过。

## 22. 实时流量展示与明文预览（2026-10-13）

实时流量的“处理后”原本记录线上拦截器返回的报文，不包含 `response-display` 展示解密；因此收到/转发两侧相同密文符合客户端协议。现明确标注收到/转发快照，并新增独立的明文预览页签。汇总行显示规则匹配和动作阶段，不把匹配当成功执行；结果按字节及 Header 对照显示是否改变，未改变为中性状态，动作失败显示错误。单动作行使用动作前/后标签，防止中间结果被当最终转发报文。仅响应规则不再生成请求方向的处理事件。

明文预览只在用户打开页签或点击重新生成时触发，后台执行真实展示阶段，保留原请求头用于 AAD；不在记录流量时额外解密。使用当前规则和捕获的起始上下文，不代表捕获时规则已执行成功；记录缓存须在规则改变后重新生成。预览失败不展示半成品为成功明文；无展示动作明确提示；外部 provider/lookup/fallbackLookup 拒绝执行，不伪造成功，也不据此断言外部服务在真实链路失败。JSON 输出仅用于展示格式化，原转发数据不变。

默认列表/详情各占约一半，摘要固定约 4 行可滚动，左右快照均分；拖动分隔后的比例在刷新中保留。修正时间列名称、顺序编号、数字排序、响应动作方向，以及新记录插入/刷新时的选中详情。上下文未捕获协议版本时明确注明，不能凭详情重建文本中硬写的 HTTP/2 判断真实协议。

回归使用真实 Rhino/AES-GCM、独立 Python 固定向量和真实 Swing：原请求 AAD 解密、错误 nonce 拒绝、无展示动作、外部不调用、异步页签触发/缓存、排序/选择/刷新和初始布局。已有规则不需要为这个 UI 修复修改。

本次完整构建 321 项单元测试、2 项打包集成测试、18 项密码检查全部通过；发布维护脚本 6 项通过；标准示例与 forward-test 在 source/packaged 各 34/34 通过。

## 23. 历史遗漏与统一处理链（2026-10-13）

构建 `2026.10.13.2` 将输入解析、当前正文/原始字节、生成 Header、变量输出和 noChange 处理集中到 ActionPipeline；线上、编辑器、步骤预览共用实现。保留失败策略区别：wire 跳过失败动作继续，展示/编辑阶段停止。失败步骤恢复 Header 与共享变量的顶层绑定，防止失败签名的临时 Header 或脚本赋值影响后续步骤；不能回滚共享对象内部的任意外部副作用。charset 更新重解释已有字节，不重编码原始正文。

请求编辑新增与响应一致的显式 encrypt/body-or-field/editor-send 能力及实际正文加密结果检查；无动作、noChange、结果为空或正文未变化时保留原密文。仅 display 的请求可展示但只读；历史用 execute 标记加密的脚本需改为 encrypt，正确的 encrypt/editor-send 规则不需迁移。两种编辑器遵循 READ_ONLY 并按规则 revision 使已准备密文缓存失效。规则条件须覆盖编辑后的明文、请求行和 Header，能力检查本身不执行加密。离线 phase fixtures 直接验证相位服务，不等同已经证明 Burp 的可编辑资格与最终 write-back，后者由编辑器回归覆盖。

Montoya 映射统一读取真实正文 bytes、声明 charset、原请求 Header 及工具来源。单值 Header API 对重复头统一取大小写无关的最后一个值，原始传输对象的未修改重复头保留。HttpFraming 在正文或 framing Header 改变时按实际字节长度处理 Content-Length，chunked 按完整 token 判断；不修改无变化的传输数据。汇总实时流量记录在此规范化之后，仍不等于所有其他扩展处理后的最终网络抓包。

外部 HttpApiClient 初始化失败不再回退 MockApiClient。内部加解密/签名独立可用，外部不可用和密钥查询失败明确返回失败；不会以模拟输出污染实际 HTTP 链。规则配置拥有可变副本，克隆隔离嵌套 JSON 配置；RuleManager 的写入、读取和分类查询都隔离调用方对象，批量替换校验失败保留旧规则与 revision。通过 RuleManager.updateRule/setRuleEnabled 等接口提交更新，不通过旧对象引用修改已存规则。

本次完整构建 344 项单元测试、2 项独立 JVM 打包测试、18 项密码服务检查通过。未操作真实 Burp Send/Forward、未发送网络请求，也未更改用户启用中的规则。

标准示例与 forward-test 在 source/packaged 各 34/34 通过；发布维护脚本 7 项通过，包括旧 revision 拒绝。

最终补充：编辑器所有 Header 写回后按实际正文 bytes 校正 framing，避免生成模板覆盖长度；HEAD/304 的仅 Header 修改保留 representation 长度。启用/禁用也发布副本、更新 revision 并通知；批量替换一次发布完整快照，并发读不经过临时空列表。签名依赖最终长度 Header 时，须在签名前显式准备依赖并验证最终报文字节。

## 24. UI 布局与交互维护（2026-10-14）

当前构建 `2026.10.14.1`。语言刷新保留当前页签、测试台表单/输入/输出和规则筛选/选择；测试台与完整步骤预览后台执行，结果在 EDT 发布。规则表支持排序；编辑仅单选，启停/复制/删除处理所有选中规则，复制副本默认禁用。旧规则无需因 UI 维护迁移。

实时流量的完整明文/步骤预览仅从请求/响应汇总记录触发；单动作记录是中间快照，对它重放全部解密步骤可能重复解密。取消选中清空详情。预览缓存按当前规则 revision 和语言失效；修改规则后重新生成，而不是把旧缓存当作新规则验证。收到/转发快照仍保持密文，预览不改实际通信。

设置导入进入待保存表单，应用后生效，取消可恢复；导出可见的待保存值。不要把 URL 格式校验理解成连接验证。后台测试使用点击时的输入快照，关闭预览会停止结果发布，但取消不保证处理器或已发生的外部副作用立刻终止。

完整构建 364 项单元测试、2 项独立 JVM 打包测试、最终 JAR 18 项密码检查通过；标准示例与 forward-test 在 source/packaged 各 34/34 通过，维护脚本 7 项通过。UI 验证材料包含测试源码、日志和合成布局截图。未在运行中的 Burp 操作 Send/Forward；截图是本地 Swing 渲染，不证明 Burp 的实际主题、DPI 与焦点行为。

## 25. 场景向导与预设库同步（2026-10-14）

当前构建 `2026.10.14.2`。向导生成的响应解密规则开启 showInEditor；新增响应编辑重加密场景，明确使用 response-editor-send。新请求编辑模板设置 `config.editorOnly=true`，跳过 HTTP send 路径中对已准备密文的再次加密；旧规则未设置时保留 Repeater editor-send 的兼容行为。自动发送明文加密仍使用 send，不应混用该选项。

预设库包含 10 个与 Skill 原文件逐字节一致的可验证合成样例；JAR 内同时附带对应 fixtures。搜索/预览及“编辑后添加”均使用当前模板，已有规则不会自动替换。所有新建模板均为禁用草稿；替换测试密钥、地址、固定 nonce 和 AAD 后再验证和启用。历史厂商规则没有完成第三方服务实测，不能因为模板在库中就认定其协议仍有效。

375 项单元测试、2 项独立 JVM 打包测试、18 项密码服务检查通过；源码/打包样例各 34/34，20 个打包样例资源与维护文件一致，维护脚本 9 项通过。模板验证材料附实际回归源码和日志。重点覆盖请求显示→编辑→wire 不重复加密、响应向导的独立 JDK 解密、Header 正文签名、Body 重签稳定、预设持久化/失败撤销及布尔额外参数保留。未操作真实 Burp Send/Forward 或第三方网络服务。

## 26. UI 保存语义与隐藏交互（2026-10-14）

当前构建 `2026.10.14.3` 修复规则编辑丢失 toolSource、空值 Header 条件和正则首尾文本的问题；工具来源现在可见、可编辑。纯响应规则无需添加请求步骤才能保存；规则与动作使用独立草稿，校验成功才提交。旧文件中已经丢失的来源限制不会被猜测恢复，需作者按实际用途核对。

保存动作时保留其他已有配置，脚本 execute/process 和旧正文输入别名不再被默认选项代替；变量改名写入 variableName，字段路径改名同步到 fieldPath。额外参数不能覆盖基本页的阶段/输入来源，也不能重复同名键。无修改保存保留 signContent；改变模板再切换 custom。保留历史模式不等于引擎增加了相应协议支持。

配置面板在载入时不做中途自动改值，离开无密钥算法恢复原密钥来源；弹窗接受 Window，预设库→规则→步骤编辑链路不再强转 Frame。排序、多选范围、字体行高和长预设提示同步优化。387 项单元测试、2 项独立 JVM 打包测试、18 项密码服务检查通过；源码/打包固定样例各 34/34，维护脚本 9 项通过。未操作真实 Burp 或发送网络流量。

## 27. 表单分组、流量筛选与共享帮助（2026-10-14）

构建 `2026.10.14.4` 调整 UI，不要求迁移规则。加解密字符集/tag、签名参数整理、规则高级匹配和长篇帮助可折叠；加载已有非默认参数自动展开。折叠不移除控件，保存仍包含原高级值。常用表单跟随容器宽度，避免长模板把整个面板撑宽。

实时流量可按编号/方法/URL/规则/工具来源做大小写无关的字面搜索，并叠加方向、连线结果、汇总/动作明细筛选；不搜索正文，不执行处理器，不影响网络报文或丢弃未显示记录。最近 1,000 条上限保持不变。隐藏/淘汰选中记录会清空详情并取消预览，刷新语言保留筛选与排序。

脚本编辑器和测试台共用中英文帮助。`targetType=field` 对脚本不做字段定位，脚本需返回完整修改后的正文；Java / Packages 访问被禁止。原请求头与当前方向头部继续分别使用 `getOriginalHeader` 与 `getHeader`。签名说明按固定编号关联，翻译文字不决定内部参数值。

401 项单元测试（新增 14 项）、2 项独立 JVM 打包测试、18 项密码服务探测均通过；源码/打包固定样例分别 34/34。使用实际 Swing 面板做离屏布局检查，未执行 Burp 实机或网络测试。其他历史状态文字与用户脚本代码未全量翻译。

## 28. 整体复核与独立验证边界（2026-10-14）

构建 `2026.10.14.5` 保留旧规则格式与阶段。编辑器将处理结果中的 bodyBytes 直接写回 Montoya ByteArray，修复非 UTF-8 密文在 String 往返中损坏的问题；明文视图仍是文本编辑器。未变更的重复 HTTP 头不再因单值映射与第一项原始值的差异被重写，规则 API 仍是单值头语义。

UI 规则修改先保存候选，成功后再统一发布；失败不改变内存、列表或 revision。已有匹配字段未编辑时保留原列表，避免逗号路径被重拆。自定义算法和未提交的下拉编辑文本在刷新/翻译时保留。应用内“测试当前配置”使用完整步骤草稿的子级预览，父规则/步骤窗口保留；预览按实际输入源、目标、方向及阶段执行，不调用外部服务或 lookup。

响应链回归使用仓库内的合成测试数据。合成 PBKDF2-GCM/AAD 规则已内置于测试资源中，JCE 独立校验其密文；该测试不声明真实厂商当前协议或外部历史版本已验证。完整构建隔离用户 home。发布校验核对全部 20 个内置预设与 fixtures，以及资源内容和 source contract 的移除输入。

418 项单元测试（新增 17 项）、2 项独立 JVM 打包测试、18 项密码服务检查均通过，零失败/错误/跳过；源码与打包固定样例分别 34/34。本轮未进行 Burp 实机或网络测试。主测试台手工表单仍是简化处理器试验入口，完整协议参数使用步骤预览和 CLI fixtures 验证。
