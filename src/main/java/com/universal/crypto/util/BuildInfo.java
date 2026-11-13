package com.universal.crypto.util;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarFile;

/** Reads the manifest of this extension, rather than Burp's parent-loader manifest. */
public final class BuildInfo {
    private BuildInfo() { }
    public static String revision() {
        try {
            var source = BuildInfo.class.getProtectionDomain().getCodeSource();
            if (source == null || !"file".equals(source.getLocation().getProtocol())) return "unknown";
            Path path = Path.of(source.getLocation().toURI());
            if (!Files.isRegularFile(path)) return "development";
            try (var jar = new JarFile(path.toFile())) {
                var manifest = jar.getManifest();
                String revision = manifest == null ? null : manifest.getMainAttributes().getValue("UCE-Revision");
                return revision == null ? "legacy" : revision;
            }
        } catch (Exception error) { return "unknown"; }
    }
}
