# Universal Crypto Extension

[![Cross-platform build](https://github.com/Re13orn/UniversalCryptoExtension/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/Re13orn/UniversalCryptoExtension/actions/workflows/build.yml)
[![Latest release](https://img.shields.io/github/v/release/Re13orn/UniversalCryptoExtension)](https://github.com/Re13orn/UniversalCryptoExtension/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](BUILD.md)

[![GitHub stars](https://img.shields.io/github/stars/Re13orn/UniversalCryptoExtension?style=social)](https://github.com/Re13orn/UniversalCryptoExtension/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Re13orn/UniversalCryptoExtension?style=social)](https://github.com/Re13orn/UniversalCryptoExtension/forks)

**English** · [简体中文](README.zh-CN.md)

A Burp Suite extension for testing APIs that encrypt or sign HTTP messages.
Inspect and edit plaintext in Burp, then let rules re-encrypt the message or
recalculate its signature before sending.

## Why

When an API encrypts its payload, Repeater shows ciphertext. Changing a field
can require decrypting the payload, rebuilding it, and signing the result for
every request. Universal Crypto Extension lets you define that workflow once
and apply it to matching messages.

## Features

- **Plaintext editing.** Decrypt requests and responses for inspection. Configure a separate encryption action to submit edits.
- **Request signing.** Build signing input from headers, query parameters, or the body. Write the result to a header or JSON field.
- **Custom processing.** Combine built-in crypto, encoding, and field operations with Rhino JavaScript or a configured external service.
- **Rule testing.** Use the Playground and step preview to check a rule against a sample message before enabling it.

## How it works

Rules match traffic by host, path, method, and Burp tool. Each action runs in a
configured phase. Display actions populate the plaintext tab, editor actions
process edits on submission, and forwarding actions modify messages as they
pass through Burp.

## Install

1. Download `universal-crypto-extension-1.0.0.jar` from the [latest release](https://github.com/Re13orn/UniversalCryptoExtension/releases/latest).
2. In Burp Suite, open **Extensions → Installed → Add**, choose **Java**, and load the JAR.
3. Open the **Universal Crypto** tab to create or import a rule.

The JAR bundles its runtime dependencies and requires Java 17 or later in the
Burp process. The build is tested on Linux, macOS, and Windows with Java 17 and 21.

## Usage

The rule list starts empty. To try the extension, open the preset library and
add one of the 10 synthetic examples. Rules added from the library start
disabled. Set the target scope and protocol parameters, verify the result in
the Playground, and enable the rule.

For an editable plaintext request, pair a decrypt action in the display phase
with an encrypt action in the editor submission phase. Add a signing action
when the protocol requires an updated signature.

Built-in processing works offline. External cryptographic processing and key
lookup require a configured service.

## Build from source

With JDK 17 or later and Maven installed, run:

```sh
git clone https://github.com/Re13orn/UniversalCryptoExtension.git
cd UniversalCryptoExtension
mvn clean verify
```

Load `target/universal-crypto-extension-1.0.0.jar` in Burp.

## Documentation

- [Build and release guide (Chinese)](BUILD.md)
- [Rule authoring manual (Chinese)](docs/规则编写手册.md)
- [Rule authoring skill and offline validation](skills/universal-crypto-rules/SKILL.md)
- [Importable examples and fixtures](skills/universal-crypto-rules/assets/examples/)

## License

[MIT](LICENSE). Bundled libraries are listed in the [third-party notices](THIRD_PARTY_NOTICES.md).
