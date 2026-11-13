# Universal Crypto Extension

[![Cross-platform build](https://github.com/Re13orn/UniversalCryptoExtension/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/Re13orn/UniversalCryptoExtension/actions/workflows/build.yml)
[![Latest release](https://img.shields.io/github/v/release/Re13orn/UniversalCryptoExtension)](https://github.com/Re13orn/UniversalCryptoExtension/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](BUILD.md)

**English** · [简体中文](README.zh-CN.md)

Universal Crypto Extension is a Burp Suite extension for processing HTTP requests and responses with configurable rules. Use it to inspect encrypted payloads, edit plaintext and re-encrypt it before sending, recalculate signatures, or transform individual fields.

## Install

1. Download `universal-crypto-extension-1.0.0.jar` from the [latest release](https://github.com/Re13orn/UniversalCryptoExtension/releases/latest).
2. In Burp Suite, open **Extensions → Installed → Add**, select **Java**, and load the JAR.
3. Open the **Universal Crypto** tab to create a rule, import one, or add an example from the preset library.

The JAR includes its runtime dependencies. The extension targets Java 17 and uses the runtime that launches Burp. See the [Burp extension loading guide](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/loading-in-burp).

## What you can do

- **Inspect and edit plaintext.** Configure a display action for decrypted content and a matching encryption action for edited messages. Rules support separate phases for display, editor submission, and HTTP forwarding.
- **Recalculate signatures.** Build the signing input from the HTTP method, path, headers, body, or JSON fields. Use a built-in signature processor or a Rhino JavaScript action.
- **Transform messages.** Apply operations to bodies, headers, or JSON fields. Use rule conditions to scope processing to the relevant hosts, paths, methods, and Burp tools.
- **Test rules before enabling them.** Use the Playground or step-by-step preview. The preset library contains 10 synthetic examples for Base64, AES, HMAC, JSON field processing, and plaintext editing. The rule list starts empty, and examples are disabled when added.

Built-in processors work offline. Rules that use an external cryptographic service or key lookup require a configured endpoint.

## Build from source

Install JDK 17 or later and Maven, then run:

```bash
mvn clean verify
```

The build produces `target/universal-crypto-extension-1.0.0.jar`. The CI matrix verifies builds on Linux, macOS, and Windows with Java 17 and 21. The signed Bouncy Castle provider is packaged inside the JAR.

## Documentation

- [Build and release guide (Chinese)](BUILD.md)
- [Verification guide (Chinese)](VERIFICATION.md)
- [Rule authoring manual (Chinese)](docs/规则编写手册.md)
- [Importable examples and offline fixtures](skills/universal-crypto-rules/assets/examples/)

## License

The project is licensed under the [MIT License](LICENSE). See the [third-party notices](THIRD_PARTY_NOTICES.md) for bundled dependencies.
