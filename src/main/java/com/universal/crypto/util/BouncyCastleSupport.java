package com.universal.crypto.util;

import javax.crypto.Mac;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.cert.Certificate;

/** Loads the unmodified signed provider without registering it in Burp's global provider list. */
public final class BouncyCastleSupport {
    private static final String RESOURCE = "/META-INF/lib/bcprov.jar";
    private static Provider provider;
    private static URLClassLoader loader;
    private static Path extractedJar;
    private static boolean closed;

    private BouncyCastleSupport() { }

    public static synchronized Provider getProvider() throws GeneralSecurityException {
        if (closed) {
            throw new GeneralSecurityException("Crypto provider is closed after extension unload");
        }
        if (provider != null) {
            return provider;
        }
        Path file = null;
        URLClassLoader candidate = null;
        try (InputStream resource = BouncyCastleSupport.class.getResourceAsStream(RESOURCE)) {
            if (resource == null) {
                throw new GeneralSecurityException("Signed BC dependency missing: " + RESOURCE + "; rebuild the extension");
            }
            // JCE authenticates a provider's on-disk code source, not a nested jar URL.
            file = Files.createTempFile("uce-bc-", ".jar");
            file.toFile().deleteOnExit();
            // Keep createTempFile's owner-only permissions instead of replacing the file.
            try (var output = Files.newOutputStream(file)) {
                resource.transferTo(output);
            }
            // Parent excludes both Burp and other extensions' BC classes.
            candidate = new URLClassLoader(new URL[]{file.toUri().toURL()}, ClassLoader.getPlatformClassLoader());
            Class<?> type = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider", true, candidate);
            Certificate[] certificates = type.getProtectionDomain().getCodeSource().getCertificates();
            if (certificates == null || certificates.length == 0) {
                throw new GeneralSecurityException("Embedded BC provider has no signing certificates; rebuild with the original signed BC JAR");
            }
            Provider loaded = (Provider) type.getDeclaredConstructor().newInstance();
            // Exercise the JCE authentication gate before caching the provider.
            Mac.getInstance("HmacSHA256", loaded);
            provider = loaded;
            loader = candidate;
            extractedJar = file;
            return provider;
        } catch (IOException | ReflectiveOperationException | SecurityException e) {
            throw new GeneralSecurityException("Cannot load the embedded signed BC provider: " + e.getMessage(), e);
        } finally {
            if (provider == null) {
                release(candidate, file);
            }
        }
    }

    /** Called once by Burp's extension unloading handler. */
    public static synchronized void close() {
        closed = true;
        provider = null;
        release(loader, extractedJar);
        loader = null;
        extractedJar = null;
    }

    private static void release(URLClassLoader classLoader, Path file) {
        if (classLoader != null) {
            try {
                classLoader.close();
            } catch (IOException e) {
                Logger.getInstance().warn("Cannot close BC class loader: " + e.getMessage());
            }
        }
        if (file != null) {
            try {
                Files.deleteIfExists(file);
            } catch (IOException e) {
                // deleteOnExit remains as a fallback (e.g. a Windows file lock).
                Logger.getInstance().warn("Cannot delete temporary BC JAR: " + e.getMessage());
            }
        }
    }
}
