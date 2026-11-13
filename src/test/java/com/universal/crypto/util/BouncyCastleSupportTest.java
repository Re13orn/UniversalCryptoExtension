package com.universal.crypto.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class BouncyCastleSupportTest {
    @TempDir Path temp;

    @Test
    void concurrentRequestsShareOneSignedProvider() throws Exception {
        var executor = Executors.newFixedThreadPool(8);
        try {
            var requests = new ArrayList<Callable<Provider>>();
            for (int i = 0; i < 32; i++) requests.add(BouncyCastleSupport::getProvider);
            Provider expected = BouncyCastleSupport.getProvider();
            for (var future : executor.invokeAll(requests)) assertSame(expected, future.get());
            assertTrue(expected.getClass().getProtectionDomain().getCodeSource().getCertificates().length > 0);
        } finally { executor.shutdownNow(); }
    }

    private URLClassLoader isolatedLoader() throws Exception {
        Path destination = temp.resolve("com/universal/crypto/util/BouncyCastleSupport.class");
        Files.createDirectories(destination.getParent());
        try (var source = BouncyCastleSupport.class.getResourceAsStream("BouncyCastleSupport.class")) {
            Files.copy(source, destination);
        }
        return new URLClassLoader(new URL[]{temp.toUri().toURL()}, ClassLoader.getPlatformClassLoader());
    }

    @Test
    void missingEmbeddedDependencyFailsClearly() throws Exception {
        try (var loader = isolatedLoader()) {
            var method = loader.loadClass(BouncyCastleSupport.class.getName()).getMethod("getProvider");
            var exception = assertThrows(InvocationTargetException.class, () -> method.invoke(null));
            assertInstanceOf(GeneralSecurityException.class, exception.getCause());
            assertTrue(exception.getCause().getMessage().contains("Signed BC dependency missing"));
        }
    }

    @Test
    void tamperedSignedProviderIsRejectedInsteadOfUsingUnsignedClasses() throws Exception {
        Path nested = temp.resolve("META-INF/lib/bcprov.jar");
        Files.createDirectories(nested.getParent());
        Path original = Path.of("target/classes/META-INF/lib/bcprov.jar");
        try (JarFile signed = new JarFile(original.toFile()); ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(nested))) {
            for (var entries = signed.entries(); entries.hasMoreElements();) {
                var entry = entries.nextElement();
                output.putNextEntry(new ZipEntry(entry.getName()));
                byte[] bytes;
                try (var input = signed.getInputStream(entry)) { bytes = input.readAllBytes(); }
                // A multi-release JAR can load a different provider class on Java 17.
                if (entry.getName().endsWith("org/bouncycastle/jce/provider/BouncyCastleProvider.class")) {
                    bytes[0] ^= 1;
                }
                output.write(bytes);
                output.closeEntry();
            }
        }
        try (var loader = isolatedLoader()) {
            var method = loader.loadClass(BouncyCastleSupport.class.getName()).getMethod("getProvider");
            var exception = assertThrows(InvocationTargetException.class, () -> method.invoke(null));
            assertInstanceOf(GeneralSecurityException.class, exception.getCause());
            assertTrue(exception.getCause().getMessage().contains("Cannot load the embedded signed BC provider"));
        }
    }
}
