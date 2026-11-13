#!/usr/bin/env python3
"""Check the actual distribution; exit nonzero on missing capabilities or altered BC."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

BC_SHA256 = "8f3c20e3e2d565d26f33e8d4857a37d0d7f8ac39b62a7026496fcab1bdac30d4"
SPI = "com.universal.crypto.burp.UniversalCryptoExtension"
PRESET_STEMS = (
    "01-text-base64", "02-internal-aes-cbc", "03-pbkdf2-aes-gcm", "04-gcm-split-tag-aad",
    "05-binary-key-hmac", "06-internal-hmac-signature", "07-json-field", "08-raw-binary-gcm",
    "09-shared-wire-context", "10-response-editor-aad",
)
PRESET_ENTRIES = tuple("com/universal/crypto/presets/" + stem + suffix
                       for stem in PRESET_STEMS for suffix in (".rules.json", ".fixtures.json"))
REQUIRED = (
    "com/universal/crypto/burp/UniversalCryptoExtension.class",
    "com/universal/crypto/burp/HttpContextMapper.class",
    "com/universal/crypto/engine/ActionPipeline.class",
    "com/universal/crypto/util/HttpFraming.class",
    "com/universal/crypto/ui/RuleActionDescriber.class",
    "com/universal/crypto/ui/UiTasks.class",
    "com/universal/crypto/ui/FormState.class",
    "com/universal/crypto/ui/CollapsibleSection.class",
    "com/universal/crypto/ui/ActionTestNavigator.class",
    "com/universal/crypto/ui/processor/ScriptHelp.class",
    "com/universal/crypto/ui/SplitPaneLayout.class",
    "com/universal/crypto/ui/editor/EditorMessageSupport.class",
    "com/universal/crypto/ui/editor/PlaintextHttpRequestEditor.class",
    "com/universal/crypto/ui/editor/PlaintextHttpResponseEditor.class",
    "com/universal/crypto/ui/editor/IsolatedSyntaxTextArea.class",
    "org/mozilla/javascript/Context.class",
    "org/fife/ui/rsyntaxtextarea/RSyntaxTextArea.class",
    "com/fasterxml/jackson/core/JsonProcessingException.class",
    "META-INF/uce/LICENSE",
    "META-INF/uce-third-party/README.md",
    "META-INF/uce-third-party/rsyntaxtextarea-LICENSE.txt",
    "META-INF/uce-third-party/bcprov-LICENSE.txt",
    "META-INF/uce-third-party/rhino-LICENSE.txt",
    "META-INF/uce-third-party/httpclient-NOTICE.txt",
    "META-INF/services/burp.api.montoya.BurpExtension",
    "META-INF/lib/bcprov.jar",
) + PRESET_ENTRIES

def manifest(data):
    lines = data.decode("utf-8").replace("\r\n", "\n").splitlines()
    unfolded = []
    for line in lines:
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    return dict(line.split(": ", 1) for line in unfolded if ": " in line)

def verify(path, expected_revision=None):
    path = Path(path)
    with zipfile.ZipFile(path) as archive:
        entries = set(archive.namelist())
        missing = set(REQUIRED) - entries
        if missing:
            raise ValueError("Missing entries: " + ", ".join(sorted(missing)))
        resources = Path(__file__).resolve().parents[1] / "src/main/resources"
        for name in PRESET_ENTRIES:
            source = resources / name
            if source.is_file() and archive.read(name) != source.read_bytes():
                raise ValueError("Packaged preset differs from source: " + name)
        if any(n.startswith("org/bouncycastle/") or n.endswith("module-info.class") for n in entries):
            raise ValueError("BC must remain nested; outer module-info.class is forbidden")
        if archive.read("META-INF/services/burp.api.montoya.BurpExtension").decode().strip() != SPI:
            raise ValueError("Unexpected Burp SPI registration")
        info = manifest(archive.read("META-INF/MANIFEST.MF"))
        if info.get("Crypto-Provider-Layout") != "signed-bc-nested-v1":
            raise ValueError("Missing signed BC provider layout marker")
        if not info.get("UCE-Revision"):
            raise ValueError("Missing extension revision marker")
        if expected_revision is not None and info.get("UCE-Revision") != expected_revision:
            raise ValueError("Stale extension revision: expected " + expected_revision + ", got " + info.get("UCE-Revision", "missing"))
        if info.get("Response-Editor-Phase") != "response-editor-send":
            raise ValueError("Missing response editor capability marker")
        bc = archive.read("META-INF/lib/bcprov.jar")
        if hashlib.sha256(bc).hexdigest() != BC_SHA256:
            raise ValueError("Nested BC is not the unmodified signed BC 1.70 dependency")
        with zipfile.ZipFile(io.BytesIO(bc)) as nested:
            if not any(n.endswith(".SF") for n in nested.namelist()):
                raise ValueError("BC signature metadata missing")
    return {"jar": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "revision": info.get("UCE-Revision", "unknown"), "providerLayout": info["Crypto-Provider-Layout"],
            "responseEditorPhase": info["Response-Editor-Phase"], "bcSha256": BC_SHA256,
            "packagedPresetAssetsChecked": len(PRESET_ENTRIES)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pom-property", choices=["artifactId", "version", "uce.revision"], help="Print project metadata without inspecting a JAR")
    parser.add_argument("--jar", default="target/universal-crypto-extension-1.0.0.jar")
    parser.add_argument("--expected-revision", help="Reject an artifact from a different project revision")
    parser.add_argument("--crypto-classpath", help="Compiled test classes containing PackagedCryptoProbe")
    args = parser.parse_args()
    try:
        if args.pom_property:
            import xml.etree.ElementTree as ET
            root = ET.parse(Path(__file__).resolve().parents[1] / "pom.xml").getroot()
            key = args.pom_property
            value = root.findtext("{*}" + key) if key != "uce.revision" else root.findtext("{*}properties/{*}uce.revision")
            if not value: raise ValueError("Missing pom property: " + key)
            print(value); return 0
        result = verify(args.jar, args.expected_revision)
        if args.crypto_classpath:
            import os
            probe = Path(args.crypto_classpath) / "com/universal/crypto/packaging/PackagedCryptoProbe.class"
            if not probe.is_file():
                raise ValueError("Crypto probe missing; run ./build.sh first")
            run = subprocess.run(["java", "-Djava.awt.headless=true", "-cp",
                                  os.pathsep.join([str(Path(args.jar).resolve()), str(Path(args.crypto_classpath).resolve())]),
                                  "com.universal.crypto.packaging.PackagedCryptoProbe"], capture_output=True, text=True, timeout=60)
            if run.returncode:
                raise ValueError("Packaged crypto probe failed: " + (run.stderr or run.stdout)[-1600:])
            result["cryptoServicesPassed"] = 18
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.TimeoutExpired) as error:
        print("Distribution verification failed: " + str(error), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
