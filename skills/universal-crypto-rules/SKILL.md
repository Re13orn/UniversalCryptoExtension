---
name: universal-crypto-rules
description: Write, migrate, troubleshoot, and validate importable rules for Universal Crypto Extension in Burp Suite. Use for encryption, decryption, signing, encoding, or field transformations based on HTTP messages, client code, protocol documentation, or existing rules.
---

# Universal Crypto Rules

**English** · [简体中文](SKILL.zh-CN.md)

Produce an importable rule file, a protocol explanation, and sanitized test
fixtures. Use the extension's documented APIs and verify behavior against its
Java processors and Rhino runtime.

## Compatibility and references

The current release targets Java 17 or later and uses Rhino 1.8.1. Rule
exports use `schemaVersion=1` and `engineBuild=rhino-1.8.1-sandbox-v1`.
Check the source, the JAR manifest, or startup logs for build-specific
capabilities. Build `2026.11.13.3` has
`Crypto-Provider-Layout: signed-bc-nested-v1` and
`Response-Editor-Phase: response-editor-send`. The signed Bouncy Castle JAR
is embedded at `META-INF/lib/bcprov.jar`. The schema and engine identifiers
are shared with earlier builds.

Read the relevant reference sections. These reference documents are in Chinese.

- [Rule structure and execution phases](references/rule-format.md)
- [Processor settings and external HTTP APIs](references/processors.md)
- [Rhino scripting API and byte handling](references/script-api.md)
- [Protocol recipes](references/recipes.md) and [complete example rules](assets/examples/)
- [Import, validation, and troubleshooting](references/validation.md)

## Authoring workflow

1. Determine the match scope, message direction, and intended write-back from the provided messages, client code, or protocol documentation. Identify framing, encoding, key and IV sources, KDF parameters, padding, tag placement, AAD, and the signature input and output format. Record the evidence and any assumptions.
2. When required parameters are missing, provide a disabled draft and identify the missing values. Use a built-in processor when it matches the protocol. Use a script for custom framing, split tags, or PBKDF2 with AES-GCM and AAD. The script Crypto API provides PBKDF2-HMAC-SHA256, HMAC-SHA256, AES-GCM, and random bytes. AES-CBC, RSA, and SM4 require a built-in processor or an authorized external service.
3. Set the action input and destination explicitly. Header writes and variable extraction often require `inputSource=request-body` or `response-body`. A script targeting a field returns the complete modified body.
4. Select execution phases explicitly. Use a `decrypt` body or field action in `display` with `showInEditor=true` for request plaintext. Add a separate `encrypt` body or field action in `editor-send` to submit edits, with conditions that match the edited message. Use `config.editorOnly=true` for editor-only request encryption on builds `2026.10.14.2` and later. Legacy rules without this setting can also run in the Repeater HTTP callback, so the action must be idempotent or return `null` for valid ciphertext.
5. Use `response-display` for response plaintext and a separate `encrypt` body or field action in `response-editor-send` for edited responses in Intercept. Use `response-send` for automatic changes in the HTTP callback. Read request-derived AAD or nonce with `request.getOriginalHeader(name)`. Reserve `always` for rules that deliberately need it.
6. Serialize the versioned JSON with a JSON serializer to escape multiline `scriptCode` correctly. Export rules with `enabled=false` by default. Writing to the active configuration, enabling rules, and sending traffic require user authorization.
7. Validate the import and action configuration, then exercise matching, execution phases, outputs, signing input, and failure cases with sanitized fixtures. Use the actual engine. If verification cannot run, report the gap and provide the command.

## Runtime behavior

- Scripts run in a Rhino sandbox. Use the documented APIs for byte handling and cryptographic operations. Java interop, reflection, file, process, and network access are unavailable, as are Node.js and browser APIs.
- Use ordinary JavaScript arrays of bytes in the range 0–255 with `Bytes` and `Crypto`. `Base64.decode` and `Hex.decode` decode UTF-8 text. Use byte helpers for ciphertext, IVs, and binary keys.
- Return a string or byte array. `null` and `undefined` leave the target as it was. An empty string clears it. Use `JSON.stringify` for JSON output.
- `Crypto.aesGcm*` accepts and returns ciphertext followed by a 128-bit tag. Handle split tags and IV placement in the rule. Pass `null` as the fourth argument when there is no AAD.
- The built-in HMAC signer reads the key as UTF-8 text. Use `Crypto.hmacSha256(keyBytes, dataBytes)` for a binary key.
- Shared request and response data is scoped to paired live HTTP message IDs and expires after 10 minutes. Display editors and the Playground create independent contexts.
- Original request headers are available in both directions through `request.getOriginalHeader()` and `request.getOriginalHeaders()`. `request.getHeaders()` exposes the current message headers as a read-only object. Write headers with header-target actions and store shared values in `ctx`.
- Template interpolation applies to documented fields. `keyValue` is read as a literal value.
- Live HTTP processing skips failed actions and continues. Editor and display processing stop on failure. Keep dependent decrypt, modify, and sign operations in one script when they must succeed together before write-back.
- The current JAR loads its embedded signed Bouncy Castle provider in isolation. Older shaded builds can fail JCE authentication for AES, SM4, DESede, HMAC, and PBKDF2. SM2 keys use the EC factory with `sm2p256v1`. See the [validation reference](references/validation.md).

## Offline validation

```bash
python3 /path/to/universal-crypto-rules/scripts/check_rule.py \
  --project /path/to/UniversalCryptoExtension --rules rules.json --fixtures fixtures.json

python3 /path/to/universal-crypto-rules/scripts/check_rule.py \
  --jar /path/to/plugin.jar --rules rules.json --fixtures fixtures.json
```

Omit `--fixtures` to check structure only. With `--project`, the default is
source mode using `target/classes`. Add `--runtime packaged` to test the built
JAR. With `--jar`, the checker uses the release JAR directly without the
source tree or Maven. Fixtures enable the supplied rules in temporary memory.
The checker runs Java processors offline. Validate external providers and
key lookup separately using the [processor reference](references/processors.md).

## Troubleshooting and delivery

For live traffic, inspect the forwarded-message snapshot separately from the
plaintext preview. A matched rule may have actions for a different phase.
`response-display` decrypts for display. Regenerate the preview after
changing rules because previews are cached per record.

The HTTP, editor, and preview pipelines share input resolution and generated
header handling. Charset changes reinterpret the original bytes. A failed
action restores headers and top-level shared variable bindings. A
`null` or no-change result can still carry an intentional update to shared
state. Prepared ciphertext is cached by rule revision.

Deliver the rule file, intended match scope, enablement steps, write-back
targets, key and IV formats, validation commands, and observed results.
Use sanitized values in anything shared. Report live Burp verification only
when it was performed.
