# External API Integration

Universal Crypto Extension can delegate encryption, decryption, signing, and verification to any HTTP service. 现在也可以通过 `cryptoProvider` 切换为内置实现（AES/RSA/Base64），无需外部服务。

**内置模式额外能力**

- `cipherField`/`plainField`/`ivField` 支持 `regex:<pattern>`（正则匹配 JSON 键名，取首个匹配值）。
- `IV Literal Value` 可指定固定 IV，未设置时默认读取报文字段或自动生成。
- 可选 `IV Format` / `Cipher Format` / `Plain Format` 控制编码（base64/hex/plain）。

## Global API Settings

1. Open the **Settings** tab inside the extension UI.
2. In **API Settings** configure:
   - **DeEn_API Endpoint** – base URL of your helper service (for example `http://127.0.0.1:8080/api`).
   - **Timeout (ms)** – request timeout for every outbound call.
3. 点击 **Apply**。如需使用内置算法，可在规则中设置 `"cryptoProvider":"internal"`，外部 API 设置将被忽略。

## Per-action Overrides

Each rule action can specify which HTTP endpoint and method to invoke.

| Action type | Config keys                                  |
|-------------|----------------------------------------------|
| encrypt     | `encryptEndpoint`, `encryptMethod`           |
| decrypt     | `decryptEndpoint`, `decryptMethod`           |
| sign        | `signEndpoint`, `signMethod`                 |
| verify      | `verifyEndpoint`, `verifyMethod`             |
| lookup_key  | `lookupEndpoint`, `lookupHttpMethod`         |

- **Endpoint** – relative path appended to the configured base URL (e.g. `/crypto/encrypt`).
- **Method** – HTTP verb (default `POST`).

> 注意：`lookupMethod` 不是 HTTP Method，而是发送给外部服务的参数（用于描述如何“查找/派生 key”）。HTTP Method 请使用 `lookupHttpMethod`。

## Request/Response Customization (Template / Field Map / Headers)

默认情况下，扩展会发送 JSON：

```json
{
  "action": "...",
  "algorithm": "...",
  "key": "...",
  "data": "...",
  "parameters": { "...": "..." }
}
```

当你要对接“已有接口”且字段名/结构不一致时，可以在 action 的 `config` 中使用以下配置（目前需要手动编辑规则 JSON）：

- `apiRequestTemplate`：自定义请求体模板（字符串），支持占位符：
  - `${action}` `${algorithm}` `${key}` `${data}`
  - `${param.<name>}`（例如 `${param.payload}`）
- `apiFieldMap`：字段映射（对象），用于重命名默认 JSON 的字段名：
  - 支持键：`action` `algorithm` `key` `data` `parameters`
- `apiHeaders`：额外请求头（对象），例如 `{"X-Token":"..."}`
- `apiContentType`：请求体 Content-Type（默认 `application/json`）
- `apiResponsePath`：从 JSON 响应里提取结果（字符串），支持：
  - `$.a.b` / `a.b` / `/a/b` / `items[0]`
  - 未设置时：使用整个响应 body 作为结果

优先级：

- 若设置了 `apiRequestTemplate`，则请求体完全由模板生成（`apiFieldMap` 不参与 body 构造）。
- 否则使用默认 JSON + `apiFieldMap` 重命名字段。
- 若 HTTP 方法为 `GET`/`HEAD`，不会发送请求 body。

## Example: AES-GCM Login Flow

```
POST /login1
Content-Type: application/json
{
  "username": "admin",
  "password": "admin"
}
```

1. Configure rule condition to match `/login1` requests.
2. Request action (encrypt):

   ```json
   {
     "actionType": "encrypt",
     "targetType": "body",
     "processor": "crypto",
     "config": {
       "algorithm": "aes-gcm",
       "keySource": "lookup",
       "lookupEndpoint": "/crypto/key",
       "lookupHttpMethod": "POST",
       "responseKeyPath": "key",
       "encryptEndpoint": "/crypto/encrypt",
       "encryptMethod": "POST"
     }
   }
   ```

3. Optional response action (decrypt):

   ```json
   {
     "actionType": "decrypt",
     "targetType": "body",
     "processor": "crypto",
     "config": {
       "algorithm": "aes-gcm",
       "keySource": "cached",
       "fallbackLookup": true,
       "lookupEndpoint": "/crypto/key",
       "lookupHttpMethod": "POST",
       "responseKeyPath": "key",
       "decryptEndpoint": "/crypto/decrypt",
       "decryptMethod": "POST"
     }
   }
   ```

With this configuration the helper service performs AES-GCM encryption/decryption while Burp users continue to edit plaintext bodies.
