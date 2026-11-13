package com.universal.crypto.packaging;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarFile;

import static org.junit.jupiter.api.Assertions.*;

/** Run a fresh JVM with ONLY the built extension and the probe, never Maven's dependency classpath. */
class PackagedCryptoIT {
    @TempDir Path temp;

    @Test
    void distributionPreservesSignedBcAndPassesCryptoRegression() throws Exception {
        runProbe(false);
    }

    @Test
    void existingHostBcCannotOverrideTheExtensionsSignedProvider() throws Exception {
        runProbe(true);
    }

    private void runProbe(boolean hostBc) throws Exception {
        Path jar = Path.of("target/universal-crypto-extension-1.0.0.jar").toAbsolutePath();
        try (JarFile archive = new JarFile(jar.toFile())) {
            assertNotNull(archive.getJarEntry("META-INF/lib/bcprov.jar"));
            assertFalse(archive.stream().anyMatch(e -> e.getName().startsWith("org/bouncycastle/")), "BC must not be shaded");
        }
        Path output = temp.resolve("packaged-crypto.log");
        String classpath = jar + java.io.File.pathSeparator + Path.of("target/test-classes").toAbsolutePath();
        var command = new java.util.ArrayList<>(java.util.List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Djava.awt.headless=true", "-cp", classpath, PackagedCryptoProbe.class.getName()));
        if (hostBc) command.add("host-bc");
        var process = new ProcessBuilder(command)
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            fail("Packaged crypto probe exceeded 60 seconds");
        }
        String report = Files.readString(output);
        Files.copy(output, Path.of(hostBc ? "target/packaged-crypto-host-bc.log" : "target/packaged-crypto.log"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        assertEquals(0, process.exitValue(), report);
        assertTrue(report.contains("\"servicesPassed\":18"), report);
    }
}
