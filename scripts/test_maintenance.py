#!/usr/bin/env python3
"""Regression checks for release failure signals and Skill drift detection."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from unittest.mock import patch

import sync_skill
import verify_distribution

ROOT = Path(__file__).resolve().parents[1]
JAR = ROOT / "target/universal-crypto-extension-1.0.0.jar"

class MaintenanceTests(unittest.TestCase):
    def changed_jar(self, output, omit=None, replace=None):
        with zipfile.ZipFile(JAR) as source, zipfile.ZipFile(output,"w",zipfile.ZIP_DEFLATED) as target:
            for info in source.infolist():
                if info.filename != omit:
                    target.writestr(info, (replace or {}).get(info.filename, source.read(info.filename)))

    def test_actual_distribution_is_verified(self):
        expected = ET.parse(ROOT / "pom.xml").getroot().findtext("{*}properties/{*}uce.revision")
        self.assertEqual(expected, verify_distribution.verify(JAR, expected)["revision"])

    def test_stale_revision_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Stale extension revision"):
            verify_distribution.verify(JAR, "different-project-revision")

    def test_missing_response_editor_class_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            broken = Path(folder)/"broken.jar"
            self.changed_jar(broken,omit="com/universal/crypto/ui/editor/PlaintextHttpResponseEditor.class")
            with self.assertRaisesRegex(ValueError,"Missing entries"):
                verify_distribution.verify(broken)

    def test_missing_preset_fixture_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            broken = Path(folder) / "broken.jar"
            self.changed_jar(broken, omit="com/universal/crypto/presets/10-response-editor-aad.fixtures.json")
            with self.assertRaisesRegex(ValueError, "Missing entries"):
                verify_distribution.verify(broken)

    def test_every_packaged_preset_resource_is_required(self):
        for stem in verify_distribution.PRESET_STEMS:
            with self.subTest(stem=stem), tempfile.TemporaryDirectory() as folder:
                broken = Path(folder) / "missing.jar"
                self.changed_jar(broken, omit="com/universal/crypto/presets/" + stem + ".rules.json")
                with self.assertRaisesRegex(ValueError, "Missing entries"):
                    verify_distribution.verify(broken)

    def test_packaged_preset_content_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            broken = Path(folder) / "stale.jar"
            self.changed_jar(broken, replace={"com/universal/crypto/presets/07-json-field.rules.json": b"{}"})
            with self.assertRaisesRegex(ValueError, "Packaged preset differs from source"):
                verify_distribution.verify(broken)

    def test_removed_source_contract_inputs_are_detected(self):
        current = sync_skill.source_hashes()
        current.pop("src/main/java/com/universal/crypto/ui/FormState.java")
        with patch.object(sync_skill, "source_hashes", return_value=current):
            self.assertIn("source contract contains removed input: src/main/java/com/universal/crypto/ui/FormState.java", sync_skill.check([]))

    def test_packaged_preset_drift_is_detected(self):
        original = Path.read_bytes
        with patch.object(Path, "read_bytes", new=lambda path: b"drift" if path.parent.name == "presets" and path.name == "01-text-base64.rules.json" else original(path)):
            self.assertIn("packaged preset: 01-text-base64.rules.json", sync_skill.check([]))

    def test_altered_nested_bc_fails_checksum(self):
        with tempfile.TemporaryDirectory() as folder:
            broken = Path(folder)/"broken.jar"
            self.changed_jar(broken,replace={"META-INF/lib/bcprov.jar":b"unsigned dependency"})
            with self.assertRaisesRegex(ValueError,"unmodified signed BC"):
                verify_distribution.verify(broken)

    def test_cli_failure_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as folder:
            broken = Path(folder)/"broken.jar"
            self.changed_jar(broken,replace={"META-INF/services/burp.api.montoya.BurpExtension":b"missing.Extension"})
            result = subprocess.run([sys.executable,str(ROOT/"scripts/verify_distribution.py"),"--jar",str(broken)],capture_output=True,text=True)
            self.assertNotEqual(0,result.returncode)
            self.assertIn("SPI",result.stderr)

    def test_skill_checker_detects_changed_mirror(self):
        with tempfile.TemporaryDirectory() as folder:
            mirror = Path(folder)/"mirror"; shutil.copytree(sync_skill.SKILL,mirror)
            entry = mirror/"SKILL.md"; entry.write_text(entry.read_text(encoding="utf-8")+"\nStale mirror fixture.\n", encoding="utf-8")
            errors = sync_skill.check([mirror])
            self.assertTrue(any(str(mirror) in e and "SKILL.md" in e for e in errors))

    def test_skill_checker_detects_stale_source_contract(self):
        with patch.object(sync_skill,"source_hashes",return_value={"pom.xml":"invalid-checksum"}):
            self.assertIn("source contract: pom.xml",sync_skill.check([]))

if __name__ == "__main__":
    unittest.main()
