#!/usr/bin/env python3
"""Package the verified JAR, portable Skill and maintained documentation."""
import json
from pathlib import Path
import zipfile
from verify_distribution import verify

ROOT = Path(__file__).resolve().parents[1]

def main():
    import xml.etree.ElementTree as ET
    from sync_skill import check
    errors = check()
    if errors:
        import sys
        print("Skill consistency check failed; synchronize before packaging:\n" + "\n".join(errors),file=sys.stderr)
        return 1
    pom = ET.parse(ROOT / "pom.xml").getroot()
    artifact, version = pom.findtext("{*}artifactId"), pom.findtext("{*}version")
    jar = ROOT / "target" / (artifact + "-" + version + ".jar")
    metadata = verify(jar, pom.findtext("{*}properties/{*}uce.revision"))
    release = ROOT / "target" / (artifact + "-" + metadata["revision"] + "-release.zip")
    with zipfile.ZipFile(release, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(jar, jar.name)
        archive.writestr("distribution-verification.json", json.dumps(metadata, indent=2) + "\n")
        for name in ("README.md", "README.zh-CN.md", "BUILD.md", "VERIFICATION.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
            archive.write(ROOT / name, name)
        for folder in (ROOT / "skills/universal-crypto-rules", ROOT / "docs"):
            for file in sorted(folder.rglob("*")):
                if not file.is_file() or file.name == ".DS_Store" or "__pycache__" in file.parts: continue
                if folder.name == "docs" and ("universal-crypto-rules" in file.parts or file.name == "universal-crypto-rules.zip"): continue
                archive.write(file, file.relative_to(ROOT))
        notice_directory = ROOT / "src/main/resources/META-INF/uce-third-party"
        for notice in sorted(notice_directory.iterdir()):
            if notice.is_file() and notice.suffix in (".md", ".txt"):
                archive.write(notice, notice.relative_to(ROOT))
        archive.writestr("QUICKSTART.txt", "Load the root JAR in Burp Extensions.\n"
                          "Rule validation needs Python 3 and JDK 17+, but no Maven/source checkout:\n"
                          "python3 skills/universal-crypto-rules/scripts/check_rule.py --jar " + jar.name
                          + " --rules skills/universal-crypto-rules/assets/examples/01-text-base64.rules.json --fixtures skills/universal-crypto-rules/assets/examples/01-text-base64.fixtures.json\n")
    print(release)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
