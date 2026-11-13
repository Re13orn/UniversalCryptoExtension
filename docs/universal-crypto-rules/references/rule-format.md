# 规则结构与执行语义

依据：`model/{ProcessingRule,RuleCondition,ProcessingAction,RuleSerializer,Constants}.java`、`engine/RuleMatchEngine.java`、`handler/HttpInterceptor.java`、`engine/RuleProcessingService.java`、`ui/editor/`。源码位于插件仓库 `src/main/java/com/universal/crypto/`。本技能记录的是当前实现，不是未来功能约定。

结构可参考 [JSON Schema](../assets/rule.schema.json)，算法参数仍需真实处理器验证。源码核对快照见 [source-contract.json](../assets/source-contract.json)，可用于版本变更时对照，验证器不自动修改技能。

## 1. 导入格式

推荐完整文件：

```json
{
  "schemaVersion": 1,
  "engineBuild": "rhino-1.8.1-sandbox-v1",
  "rules": [{
    "id": "example-response",
    "name": "示例响应明文",
    "category": "示例协议",
    "enabled": false,
    "priority": 100,
    "description": "只在页签展示，不改写真实响应",
    "showInEditor": true,
    "condition": {"hosts": ["api.example.test"], "paths": ["/api/*"], "methods": ["POST"], "toolSource": "ANY"},
    "requestActions": [],
    "responseActions": [{
      "actionType": "decrypt",
      "targetType": "body",
      "processor": "script",
      "enabled": true,
      "description": "解码响应",
      "config": {"executionPhase": "response-display", "inputSource": "response-body", "scriptCode": "return Base64.decode(content);"}
    }]
  }]
}
```

这只是 Base64 文本演示，不是 AES 解密。新文件版本信息不匹配会拒绝导入。旧的规则数组 `[{...}]` 仍可导入；单个规则对象不属于文件导入格式。UI 导入验证后把所有规则设为禁用，用户核对后启用。持久化的 `~/.universal-crypto/universal-crypto-rules.json` 使用数组；不要把导入信封直接写到持久化文件。

导入检查包含：非空且不重复的 ID、processor、targetType、executionPhase 枚举，以及 script 动作名/非空脚本/语法。它并不穷尽所有协议和加密参数；字段拼写未知时 Jackson 可能忽略，须再做处理器配置及样例验证。

## 2. Rule 字段

| 字段 | 类型与默认 | 行为 |
|---|---|---|
| id | string，建议明确指定 | 唯一 ID；合并导入相同 ID 会更新已有规则 |
| name / description / category | string | 可读名称、协议说明、分类 |
| enabled | boolean，模型默认 true | 作者应显式 false；UI 导入后始终禁用 |
| priority | integer，默认 100 | 较小的数先执行；同优先级不要作为协议次序保证 |
| showInEditor | boolean，默认 true | 决定对应明文编辑器是否显示，不是 HTTP 链开关 |
| condition | object | 必须存在；缺省 null 不匹配，`{}` 匹配全部流量 |
| requestActions / responseActions | array，默认 [] | 请求/响应动作，按数组顺序执行 |

规则间按 priority 执行；同一方向的规则和动作共享本次 ProcessorContext。匹配规则集合基于处理前报文一次确定，不会每步重新匹配。所有条件类别是 AND；同一个 hosts/paths/methods 列表内是 OR。

## 3. Condition 字段与匹配

| 字段 | 例子 | 实际语义 |
|---|---|---|
| hosts | `["api.example.test","*.example.test"]` | host 不含协议/端口；`*` 任意字符，`?` 单字符；全串匹配、忽略大小写。`*.example.test` 不包含裸域名 |
| paths | `["/api/*","/login"]` | URL path，不含 query；与 host 同样是全串通配符、忽略大小写，不是 regex |
| methods | `["POST","PUT"]` | 忽略大小写；响应使用发起请求 method |
| headers | `{"Content-Type":"application/json*","X-*":"*"}` | 所有条目都要满足；头名称和值使用全串通配符、忽略大小写。响应检查响应头；原请求头独立暴露给脚本，不参与此条件 |
| contentType | `"application/json"` | 实际值去掉 `;charset=...` 等参数后比较；此字段不支持 `*`，不应填写 charset |
| contentPattern | `"\"ciphertext\"\\s*:"` | Java regex `find()`，CASE_INSENSITIVE + DOTALL；非法 regex 会回落为忽略大小写 contains，应避免依赖回落 |
| toolSource | `"PROXY"` / `"REPEATER"` / `"ANY"` | 忽略大小写的单值，不是数组；空/ANY 不限制 |

hosts、paths、methods 空数组，headers 空对象，以及其余空条件都表示该项不限制。工具常用值：PROXY、REPEATER、INTRUDER、SCANNER、SEQUENCER、DECODER、COMPARER、EXTENSIONS、ANY；按当前 Burp 工具来源核对。

一个 Rule 的 condition 同时约束 requestActions 和 responseActions。请求与响应头、Content-Type、正文格式不一样时拆成两个 Rule。请求编辑器加密阶段匹配的是当时明文上下文；若 contentPattern 只识别密文，加密动作可能根本不匹配。优先用 host/path/method 限范围，再在脚本内检查数据形态。

## 4. Action 字段

| 字段 | 取值 | 行为 |
|---|---|---|
| processor | crypto / signature / field / script | 精确指定，不依赖未知名称的自动回退 |
| actionType | crypto: encrypt/decrypt；signature: sign/verify；field: add/replace/remove | script 可用 process、execute、encrypt、decrypt、sign、verify、replace、add、remove |
| targetType | body / header / field / variable | 小写，写回目标，**不等于输入来源** |
| targetName | string，可选但视目标必要 | header 是头名；variable 是变量名回退；field 含义由处理器决定 |
| enabled | boolean，默认 true | false 跳过单个动作 |
| description | string | 解释步骤目的 |
| config | object | 处理器参数及输入/执行阶段 |

不要使用 `type`、`actions`、`match`、`script`、`headersToSet` 等臆造字段代替上述字段。

### 输入

| config | 值 | 语义 |
|---|---|---|
| inputSource | request-body / response-body | **都指当前方向正文**，响应阶段 request-body 也不会取回原始请求正文 |
| inputSource | header | 读取 `inputName` 指定的当前方向 Header；缺失可能为 null |
| inputSource | variable | 读取 `inputName` 指定共享值并转成字符串；缺失是空字符串 |
| inputName | string | Header/变量输入名 |
| variableName | string | targetType=variable 的输出变量名；缺省回退 targetName |

未显式 inputSource 时：body/field 输入正文；header 输入 targetName 对应的头；variable 输入 variableName/targetName 当前值。给 Header 签名正文却不设置 inputSource 时，可能签的是原 Header 值或空值。实际 HTTP 链中 script 的 `bodyBytes` 总是当前正文，不受 content 输入来源影响。

### 输出

- body：完整替换当前正文。返回 bytes 可精确改写原始正文。
- header：只写 targetName 头，正文不变。需要 return 头值；脚本没有 setHeader。
- field：HTTP 写回层仍完整替换正文。field 处理器使用 `config.fieldPath`；signature sign 使用 targetName 作为**顶层字面字段名**；script 自行 parse/修改/stringify 整个正文。
- variable：只存储字符串结果，不写正文。保存二进制共享值用 `ctx.setSharedData` + `return null`，不要把 byte[] 返回到 variable 后指望类型保留。

null/undefined（包括无 return）成功但标记 noChange，写回层跳过所有目标。显式 `""` 清空。JS 对象必须 JSON.stringify；普通 JS 数组会被当作字节数组，所有元素必须是 0–255 整数，不能直接返回任意 JSON 数组。

## 5. 执行阶段矩阵

config.executionPhase 是逗号分隔字符串，如 `"display,editor-send"`；导入建议使用精确小写 token。

| 阶段 | 放置位置 | 执行位置 | 真实流量 |
|---|---|---|---|
| display | requestActions | 请求明文页签展示 | 不自动改写；页签允许编辑 |
| editor-send | requestActions | 页签编辑后的加密；未设置 editorOnly 时，**Repeater HTTP 发送回调也会执行** | 会写回发送请求 |
| send | requestActions | HTTP 请求发送回调 | 改写发送请求 |
| response-display | responseActions | 响应明文页签展示 | 展示本身不改写真实响应 |
| response-send | responseActions | HTTP 响应回调 | 实际自动改写响应 |
| response-editor-send | responseActions | 可编辑响应页签实际修改后的重新加密 | 将新密文提交给 host；普通 HTTP 回调不执行 |
| always | 任一方向 | 该方向原有展示/HTTP 路径，不包含 response-editor-send | 可能展示/发送重复执行 |

缺省：请求 send，响应 response-display。请求页签出现条件还包括 showInEditor=true、匹配规则、enabled 的 decrypt 动作、body/field 目标、display 阶段。script 使用 process/display 虽可由服务执行，但**不能单独满足请求页签出现条件**；用 decrypt/display。响应页签没有 decrypt 动作名的额外要求。

避开重复加密：构建 2026.10.14.2+ 可给请求 editor-send 动作设置 `config.editorOnly=true`，跳过 HTTP 的 send 路径；只在明确调用 editor-send 的编辑提交中执行。新向导/请求编辑模板使用此选项。旧规则未设置时行为保持不变：当 editor-send 动作既经过页签又经过 Repeater 回调，脚本检查有效密文外壳（字段类型、IV 和 tag 长度等）后返回 null；内置 encrypt 对 payload 常会直接再次加密，不能假设插件自动防重。设置 `send,editor-send` 不是防重措施。重复取随机值或时间戳也会影响签名。

## 6. 共享状态、字节与错误

实际 HTTP 请求动作的共享数据按 messageId 提供给配对的 response-send 动作。配对后即移除，响应无命中也清理；最长 10 分钟。没有 ID 的离线上下文不做跨报文关联。

display、editor-send、response-display、response-editor-send、Playground 创建各自独立 ProcessorContext。不能依赖 UI 展示后缓存的 key 在 UI 发送时仍存在；从当前报文、固定配置或同一脚本中重新派生。也不能在 response-display 直接读取 send 生成的随机 key。

正文读取保留 byte[]；文本按 Content-Type charset 解码，无声明默认 UTF-8。未变更正文原字节保留；修改文本按声明 charset 编码，字节数组直接写回，Content-Length 使用实际字节长度。gzip/protobuf 等不可从 UTF-8 content 往返；Crypto/Bytes 显式操作 `bodyBytes`。现有编辑器及相位服务主要传递字符串，二进制精确写回优先用真实 HTTP 链并离线测试该路径。

实际 HTTP 链跳过失败动作并保留其他成功改动；失败动作此前对 `ctx` 或头模板造成的内部状态修改不保证回滚。没有规则级原子性。编辑器相位服务则遇到异常/失败时返回整体 failure。`signature.verify` 返回 `"false"` 也可能 success=true，不能把 success 解释为验签通过，更不能把验签返回值写到 body。

## 明文页签的 HTTP 头显示

Universal Crypto 请求/响应页签默认显示原始请求行/状态行、完整头部与明文正文。在正文区域右键，取消勾选“Show original HTTP headers”切换为仅正文，再次勾选恢复完整视图。原始头部优先从序列化报文的 HTTP 空行边界读取，不依赖 bodyOffset；无法读取时从请求/响应结构化信息恢复，保留顺序、重复头及原 Content-Length，备用路径不保证原始空白。可编辑请求支持修改请求行、头部和正文；发送规则读取修改后的请求信息，但加密输入仅为正文。发送时由 Burp 按加密后的正文重新计算 Content-Length。切换视图保留头部及正文编辑，不执行规则、不改变 isModified；选择保留在当前编辑器实例，未新增全局持久化设置。响应未编辑时返回原响应；只有可编辑窗口匹配显式 response-editor-send 正文加密动作时，才能编辑并提交重新加密后的响应。


HTTP 头和 JSON 自动高亮、显示行号；有效 JSON 默认 Pretty。右键 `Pretty JSON` / `Raw` 切换，非 JSON 或无效 JSON 不格式化。格式化保留重复键、转义和数字词法；未编辑时 `bodyText()` 返回精确原明文，切换不会触发发送重加密。实际编辑 Pretty 正文后按编辑后文本发送，包含展示空白；若协议签名依赖精确文本，应先切换 Raw 再编辑。切换展示或加载新报文会清空撤销记录，以免撤销跨越只读头或不同展示模式。


明文页签深色配色参照 Burp 原生 Pretty：HTTP 头名浅蓝、JSON 字段名黄色、字符串绿色、数字蓝色、布尔值和 null 橙色，正文背景为深灰。浅色主题使用相应的深色文字保证对比度。


请求/响应明文页签的字体、字号和字重读取 Burp 的 HTTP message display 设置（currentEditorFont），高亮 token 与行号使用同一字体；切回页签或加载新报文时刷新。不会固定为 12 号，也不会额外加粗。


Repeater 等可编辑请求窗口：解密成功后请求行、HTTP 头和明文正文均可编辑；默认光标位于正文，Cmd+A/Ctrl+A 或右键 Select all 选择当前完整视图。隐藏头部时仅显示及编辑正文，已修改的头部仍保留。发送时使用编辑后的方法、路径及头部匹配加密/签名规则，仅将正文交给加密处理。Host 的修改不会改变 Repeater 的连接目标，目标需在 Burp 中设置。只读窗口遵循 Burp EditorMode.READ_ONLY，响应页签在 READ_ONLY 模式保持只读；可编辑窗口需匹配显式 response-editor-send 正文加密动作才开放编辑。


插件重载后仍可编辑：明文编辑器使用独立的 keymap、InputMap 和 ActionMap，避免 RSyntaxTextArea 的全局缓存继续引用已卸载插件的键盘动作。无需重启 Burp 清缓存。

行号栏与正文的分隔线使用主题对应的低对比度灰色：深色 #505050，浅色 #D0D0D0，避免高亮库默认浅色边框在深色模式下形成白线。

可编辑请求的修改状态以最近一次 Burp setRequestResponse 为基线。读取 getRequest 不清除修改状态；重复读取使用已准备的密文缓存，后续文本编辑会使缓存失效。显示模式切换不触发重复加密，host 设置新报文才重置基线。

## 响应 Intercept 编辑与重新加密

在 Burp 提供的可编辑窗口中，response-display 展示成功且匹配启用的 response-editor-send、actionType=encrypt、targetType=body/field 动作时，开放状态行、响应头和解密正文编辑。READ_ONLY 模式和仅有展示解密的旧规则保持只读；悬浮提示说明缺少加密动作。新阶段必须显式配置，单独 always 或 response-send 不作为编辑加密能力。

未实际编辑时 getResponse 返回原响应对象，不重加密。实际编辑后按修改后的响应头/正文匹配响应加密规则，原请求头仍通过 getOriginalHeader 读取。加密和同阶段 Header 签名完成后提交新密文，withBody 按最终正文更新 Content-Length；随后显式修改该头的规则仍可能覆盖它。普通 HTTP 响应回调不会执行 response-editor-send，避免再次加密。重复读取缓存同一结果，直到再次编辑或 host 设置新报文。

旧规则只需额外添加独立的 response-editor-send 正文加密动作，保留 response-display 解密；不要把同一个解密动作移到新阶段。匹配条件优先 host/path/method；编辑加密基于明文上下文，密文专用 contentPattern 可能让它不匹配。修改 status/headers 需要正常 HTTP 文本格式，不支持折叠续行；头部重建使用 Montoya 文本接口，HTTP/2 专属元数据保留未实机验证。

无匹配、加密失败、返回空/null/noChange/相同正文或格式错误时返回原始密文，不提交编辑明文，提示及错误日志说明原因。这不会阻止 Burp Forward 原响应。协议依赖原正文之外的 nonce/tag/signature 时，响应加密动作必须同步输出相应封装和 Header。此文本编辑器不保证任意二进制正文精确往返。

维护版还保证：正文步骤更新后续脚本的 bodyBytes（字节结果保留原 bytes，文本按当前 Content-Type charset 编码）；signature.headerTemplates 的附加头在编辑器、预览和线上链路均写回。步骤预览可分别填写响应头和原请求头；显示/编辑相位失败后停止，线上 send/response-send 预览按拦截器策略跳过失败动作后继续。外部 API 和 key lookup 在预览中标为未验证，不模拟成功。撤销到基线后恢复原始明文空白并取消编辑脏状态。

请求 `config.editorOnly` 接受 Boolean 或字符串 true/false，默认 false。它仅阻止请求 HTTP send 路径（含 Repeater 的 editor-send 兼容执行）；不改变 response-editor-send 或显式 display 的阶段匹配。RuleProcessingService 和完整步骤预览遵循相同 send 边界。用于自动发送明文加密的规则应继续使用 send，且不勾选此选项。

构建 2026.10.14.3+ 的规则编辑页显式显示 toolSource，并保留空 Header 匹配值和原正则文本。保存纯响应规则不要求附加请求动作。旧 UI 保存过的规则若已丢失工具限制，须按实际用途恢复；不能从规则名称推断。动作编辑会保留其他已有配置，无修改保存保留原 signContent；修改变量或字段目标时同步实际 variableName/fieldPath。

### 编辑器密文字节边界（2026.10.14.5+）

脚本返回字节数组时，请求/响应编辑回写使用处理结果的实际 bodyBytes，不再先转换为 UTF-8 字符串。加密是否确实改变正文也按字节判断。这个修复不改变执行阶段，不代表文本视图可以编辑任意二进制明文；二进制明文场景仍应使用字节管线与固定 fixtures 核对。
