# Rhino 脚本 API 与字节语义

依据当前 `processor/impl/ScriptProcessor.java`。Rhino 1.8.1，ES6 模式，解释执行；不等同浏览器/Node，优先采用 var、普通函数、JSON 和简单循环。脚本包装在函数内执行，所以顶层 return 合法。每次执行独立全局 scope，编译缓存 128 项。

## 全局输入与返回

| 名称 | 含义 |
|---|---|
| content | 本动作根据 inputSource/target 取到的字符串，Header 缺失时可能 null |
| bodyBytes | 当前报文正文的普通 JS byte 数组；实际 HTTP 链每步刷新。直接调用 Processor 时未提供原始正文则回退 content UTF-8 字节。展示服务多步 bodyBytes 刷新与字节写回不保证等同 HTTP 链 |
| request | 当前方向的 HTTP 信息辅助函数；响应阶段并不是原始请求对象 |
| ctx | 本次处理的共享值；见作用域限制 |
| Bytes/Crypto/Base64/Hex/Hash | 下表辅助 API |

返回 string 改写对应目标；number/boolean 转字符串；普通 Array 返回原始字节，所有元素必须是 0–255 整数。对象必须 JSON.stringify；任意数组 JSON 必须 JSON.stringify，不能直接 return JSON 数组。null/undefined 不改写目标但先前 ctx 修改仍保留；`return ''` 会清空目标。

```javascript
var obj = JSON.parse(content);
obj.data.count = 3;             // 保持 number，不用 field.to 写字符串
return JSON.stringify(obj);    // 返回完整正文
```

没有 `Packages`、`java`、getClass、require、Buffer、fetch、XMLHttpRequest、crypto.subtle、console.log，也没有 CryptoJS 自动注入。辅助对象仅是普通 JS 函数桥，没有 public Java 对象供脚本反射。脚本错误通过插件日志/追踪排查。

## Bytes

所有 byte[] 在 JS 侧是普通 Array，不是 Java byte[] 或 Uint8Array。辅助函数严格要求完整实参数量；需要无 AAD 时仍传 null。

| 函数 | 参数 → 结果 |
|---|---|
| Bytes.utf8(text) | UTF-8 文本 → bytes |
| Bytes.text(bytes) | bytes → UTF-8 文本；非法序列可能产生替换字符，不能用来保存任意二进制 |
| Bytes.toBase64(bytes) | 标准 Base64，有 padding |
| Bytes.fromBase64(text) | 标准 Base64 → bytes；不是自动 Base64URL |
| Bytes.concat(a,b) | 两个数组 → 新数组；更多数组逐次 concat |
| Bytes.slice(bytes,offset,length) | 第三个参数是 **长度**，不是 end index；越界失败 |

脚本 API 没有 Bytes.fromHex/toHex，也没有 Bytes.toString/Bytes.decode。需要十六进制、Base64URL 时使用这些可复制函数：

```javascript
function fromHex(s) {
  if (typeof s !== 'string' || s.length % 2 || !/^[0-9a-f]*$/i.test(s)) throw new Error('Invalid hex');
  var out=[];
  for(var i=0;i<s.length;i+=2) out.push(parseInt(s.substring(i,i+2),16));
  return out;
}
function toHex(a) {
  return a.map(function(b){return ('0'+b.toString(16)).slice(-2);}).join('');
}
function fromB64Url(s) {
  s=s.replace(/-/g,'+').replace(/_/g,'/');
  if(s.length%4===1) throw new Error('Invalid Base64URL');
  while(s.length%4) s+='=';
  return Bytes.fromBase64(s);
}
function toB64Url(a) {
  return Bytes.toBase64(a).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
```

## Crypto

| 函数 | 结果与限制 |
|---|---|
| Crypto.pbkdf2(password,saltBytes,iterations,bits) | PBKDF2-HMAC-SHA256 → bytes；password 是 String，salt 是 bytes；iterations 1–1000000，bits 8–4096 且为 8 倍数；AES-256 传 256，不是 32 |
| Crypto.hmacSha256(keyBytes,dataBytes) | bytes，注意 **key 在前，data 在后** |
| Crypto.aesGcmEncrypt(keyBytes,ivBytes,plaintextBytes,aadBytesOrNull) | ciphertext||tag bytes，固定 tag 128 bit |
| Crypto.aesGcmDecrypt(keyBytes,ivBytes,ciphertextAndTagBytes,aadBytesOrNull) | plaintext bytes，认证失败抛异常 |
| Crypto.randomBytes(n) | SecureRandom bytes，0–1048576 |

AES key 必须是 16/24/32 字节；IV 通常 12 字节，但必须忠实于协议；不存在密码长度自动补齐或 hash 成 key。pbkdf2 密码编码的非 ASCII 场景需用已知对端向量验证，不以名字相同就宣称字节相同。salt 编码也要明确，`Bytes.utf8('YWJj')` 与 `Bytes.fromBase64('YWJj')` 完全不同。

128-bit tag 分离格式：

```javascript
var encrypted = Crypto.aesGcmEncrypt(key, iv, plaintext, aad);
var ciphertext = Bytes.slice(encrypted, 0, encrypted.length-16);
var tag = Bytes.slice(encrypted, encrypted.length-16, 16);
// 解密时必须重新拼接：
var plain = Crypto.aesGcmDecrypt(key,iv,Bytes.concat(ciphertext,tag),aad);
```

协议为 `salt||iv||ciphertext||tag` 时按明确长度 Bytes.slice 拆分。不要猜测 magic/version、salt 长度、IV 长度、tag 偏移。AAD 必须逐字节一致；JSON.stringify 的键序、空格、转义、Unicode 差异都会导致认证失败。

脚本 Crypto 没有 aesCbcEncrypt、rsaDecrypt、sm4、scrypt、HKDF、Argon2、PBKDF2-SHA1、任意 digest/hmac 参数接口。不要发明这些 API；内置处理器、精确的外部服务或用户允许的插件代码扩展是对应路径。

## Base64 / Hex / Hash

| 调用 | 语义 |
|---|---|
| Base64.encode(text) / decode(text) | UTF-8 文本兼容方法；decode 用 commons-codec，行为比 strict Bytes.fromBase64 更宽松 |
| Base64.encodeBytes(bytes) / decodeBytes(text) | strict 标准 Base64 和字节数组，适合随机数据 |
| Hex.encode(text) / decode(hex) | UTF-8 文本转 hex/hex 转 UTF-8 文本，不是 bytes helper |
| Hash.md5(text) / sha1(text) / sha256(text) | UTF-8 文本摘要，小写 hex |
| Hash.hmacSha1(data,key) / hmacSha256(data,key) / hmacSha512(data,key) | **data 在前，UTF-8 文本 key 在后**；返回 hex |
| Hash.hmacSha256Base64(data,key) | 文本 key/data，返回 Base64 |

`Hash.hmacSha256(data,key)` 与 `Crypto.hmacSha256(keyBytes,dataBytes)` 参数顺序不同。Hash 没有 sha512 函数（内置 crypto 可以 SHA512），不要因 hmacSha512 存在推断普通 sha512 helper。

## request

| 函数 | 返回 |
|---|---|
| getMethod() | 当前 method，缺失空串；响应为发起请求 method |
| getUrl() | URL 字符串，含 query，缺失空串 |
| getPath() | path，不含 query |
| getQuery() | 原始 query，无 `?` |
| getQueryParam(name) | 按 UTF-8 form decode（`+`→空格），重复参数取第一个，缺失空串 |
| getHost() | host |
| getHeaders() | 只读且 lookup 大小写不敏感的 JS object，使用 `request.getHeaders()['content-type']` |
| getHeader(name) | 大小写不敏感的当前方向头值，缺失空串 |
| getOriginalHeader(name) | 请求阶段为本次处理开始时的请求头；响应阶段为关联请求头。大小写不敏感；缺失时空串 |
| getOriginalHeaders() | 同上请求头快照的只读 JS object，大小写不敏感 lookup；不可用时空对象 |

响应侧 getHeaders/getHeader 返回响应头；读取发起请求的 Cookie/Authorization、nonce、AAD 参数必须用 getOriginalHeader/getOriginalHeaders。两条响应入口都从关联的 initiating request 提供快照，不依赖共享变量或先前请求动作；请求头不会参与响应 headers 条件匹配。请求 display/editor-send 和真实 send 链路均在处理开始时保存请求头快照；后续 Header 动作修改 getHeader 的当前值，不修改 getOriginalHeader 的值。快照按每次调用建立，不跨阶段累积。响应阶段提供关联实际请求的头部，不保证是请求发送动作执行之前的值。新 API 不提供请求正文或共享变量恢复。重复头在 Map 中折叠，不提供多值接口。旧版 1.0.0 没有此 API，部署须换成当前修复包。脚本 API 不提供 getStatusCode、getBody、setHeader、setBody、getResponse、getCookie。Header 重复值在模型映射中会折叠，不能据此精确处理多个 Set-Cookie。需要 query 原始排序/编码、全部重复值时自行解析 getQuery，不使用 getQueryParam。

## ctx

| 函数 | 返回/行为 |
|---|---|
| ctx.isRequest() | boolean |
| ctx.getSharedData(name) | 未设置通常 null；可返回字符串、数字、布尔、脚本对象/数组、Java byte[] 转成普通数组 |
| ctx.setSharedData(name,value) | 存储给当前后续步骤；不会修改 HTTP 报文 |

可用 `ctx.setSharedData('key',keyBytes); return null;` 建立同一实际 HTTP 链的后续输入；动态密钥写入内置 crypto 时用 cached_key 的字符串格式，并明确后续 keyFormat。不要把共享 NativeArray 当作 `${variable}` 或 inputSource=variable 后还能保留原字节类型；后者会 String 化。

ctx 不是全局 session store，不保证跨 message、跨编辑器或跨重新显示持续。实际请求/response-send 通过 messageId 可恢复共享数据，最长 10 分钟；响应展示无此继承。

## 实战结构

### 嵌套响应解密，只显示目标明文

```javascript
var obj=JSON.parse(content);
var key=Bytes.fromBase64('REPLACE_WITH_REAL_KEY');
var iv=Bytes.fromBase64(obj.data.iv);
var encrypted=Bytes.fromBase64(obj.data.ciphertext);
return Bytes.text(Crypto.aesGcmDecrypt(key,iv,encrypted,null));
```

这是草案，REPLACE... 不可用；完整可验证样例见 recipes/资产。若希望保留其他 JSON 字段，则赋值 `obj.data.payload=JSON.parse(plain)` 或字符串 plain，再 return JSON.stringify(obj)，不要混淆明文 JSON 对象和包含 JSON 的字符串。

### 幂等的发送加密

```javascript
var obj=JSON.parse(content);
// 按真实协议检查，而不是对所有包含 cipher 一词的报文跳过。
if(typeof obj.ciphertext==='string' && typeof obj.iv==='string' && obj.plaintext===undefined) return null;
var iv=Crypto.randomBytes(12);
var plaintext=Bytes.utf8(JSON.stringify(obj));
var cipher=Crypto.aesGcmEncrypt(key,iv,plaintext,null);
return JSON.stringify({iv:Bytes.toBase64(iv),ciphertext:Bytes.toBase64(cipher)});
```

加密需要协议提供的 key。这段只说明防重逻辑，不自动处理 KDF/salt/AAD/签名外壳。

## 时间和异常

最长约 5 秒的解释器指令观察；死循环即使在 JS try/catch 中也会终止，由处理器边界转换为普通异常。不是 Java native crypto 的可取消 deadline，也不是进程级内存隔离。不要以 try/catch 返回原输入掩盖认证失败并报告“成功解密”；只有协议允许跳过非目标报文时，显式 return null 表示未修改。

bodyBytes 代表当前步骤的完整方向正文，独立于 content 输入来源。编辑器与步骤预览也会在正文步骤之后刷新 bodyBytes，保留 byte[] 结果；文本结果按当前 Content-Type charset 编码。纯展示与撤销恢复仍保留原始明文词法和空白。
