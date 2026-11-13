package com.universal.crypto.packaging;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorException;
import com.universal.crypto.processor.impl.InternalCryptoEngine;
import com.universal.crypto.processor.impl.InternalSignatureEngine;
import com.universal.crypto.util.BouncyCastleSupport;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/** Standalone regression probe suitable for both Maven and build.sh distributions. */
public final class PackagedCryptoProbe {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final byte[] MESSAGE = "packaged crypto / 中文".getBytes(StandardCharsets.UTF_8);
    private static final Map<String, String> results = new LinkedHashMap<>();

    private interface Checked { void run() throws Exception; }
    private static void check(String name, Checked test) {
        try { test.run(); results.put(name, "passed"); }
        catch (Exception | AssertionError e) { results.put(name, "FAILED: " + e); }
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
    private static byte[] hex(String text) { return HexFormat.of().parseHex(text); }
    private static ProcessingAction action(Map<String, Object> config) {
        ProcessingAction action = new ProcessingAction();
        action.setConfig(new HashMap<>(config));
        return action;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("host-bc")) {
            Security.insertProviderAt(new Provider("BC", "0", "Simulated unrelated host provider") { }, 1);
        }
        Provider globalBc = Security.getProvider("BC");
        Provider provider = BouncyCastleSupport.getProvider();
        var source = provider.getClass().getProtectionDomain().getCodeSource();
        int certificateCount = source.getCertificates() == null ? 0 : source.getCertificates().length;
        require(certificateCount > 0, "BC code source must be signed");
        require(provider == BouncyCastleSupport.getProvider(), "Provider must be reused");
        require(globalBc == Security.getProvider("BC"), "Extension must not register or replace global BC");
        Path extracted = Path.of(source.getLocation().toURI());
        require(Files.isRegularFile(extracted), "JCE code source must be a real signed JAR");

        try {
            for (String transformation : List.of("AES/CBC/PKCS5Padding", "AES/GCM/NoPadding", "AES/ECB/PKCS5Padding",
                    "DES/CBC/PKCS5Padding", "DESede/CBC/PKCS5Padding", "SM4/ECB/NoPadding")) {
                check("Cipher " + transformation, () -> symmetric(provider, transformation));
            }
            KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA", provider);
            rsaGenerator.initialize(2048);
            KeyPair rsa = rsaGenerator.generateKeyPair();
            for (String transformation : List.of("RSA/ECB/PKCS1Padding", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding")) {
                check("Cipher " + transformation, () -> {
                    Cipher cipher = Cipher.getInstance(transformation, provider);
                    cipher.init(Cipher.ENCRYPT_MODE, rsa.getPublic());
                    byte[] encrypted = cipher.doFinal(MESSAGE);
                    cipher.init(Cipher.DECRYPT_MODE, rsa.getPrivate());
                    require(Arrays.equals(MESSAGE, cipher.doFinal(encrypted)), "RSA roundtrip");
                });
            }
            check("EC factory/generator sm2p256v1", () -> {
                var generator = KeyPairGenerator.getInstance("EC", provider);
                generator.initialize(new ECGenParameterSpec("sm2p256v1"));
                var pair = generator.generateKeyPair();
                var decoded = KeyFactory.getInstance("EC", provider).generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()));
                require(Arrays.equals(pair.getPublic().getEncoded(), decoded.getEncoded()), "SM2 EC key decoding");
            });
            check("Cipher SM2 independent OpenSSL vector", () -> sm2Engine(provider));
            for (String algorithm : List.of("HmacSHA256", "HmacSHA1", "HmacSHA512", "HmacMD5", "HmacSM3")) {
                check("Mac " + algorithm, () -> {
                    Mac mac = Mac.getInstance(algorithm, provider);
                    mac.init(new SecretKeySpec("key".getBytes(StandardCharsets.UTF_8), algorithm));
                    byte[] actual = mac.doFinal(MESSAGE);
                    if (!algorithm.equals("HmacSM3")) {
                        Mac oracle = Mac.getInstance(algorithm, "SunJCE");
                        oracle.init(new SecretKeySpec("key".getBytes(StandardCharsets.UTF_8), algorithm));
                        require(Arrays.equals(oracle.doFinal(MESSAGE), actual), "HMAC independent provider oracle");
                    } else {
                        require(actual.length == 32, "SM3 MAC size");
                    }
                    String signature = InternalSignatureEngine.sign(action(Map.of("algorithm", algorithm)),
                            new String(MESSAGE, StandardCharsets.UTF_8), "key");
                    require(signature.equals(HexFormat.of().formatHex(actual)), "Internal HMAC engine output");
                });
            }
            check("SecretKeyFactory PBKDF2WithHmacSHA256", () -> {
                byte[] derived = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", provider)
                        .generateSecret(new PBEKeySpec("password".toCharArray(), "salt".getBytes(StandardCharsets.UTF_8), 1, 256)).getEncoded();
                require(Arrays.equals(hex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"), derived), "PBKDF2 vector");
            });
            check("MessageDigest SHA-256", () -> require(Arrays.equals(MessageDigest.getInstance("SHA-256").digest(MESSAGE),
                    MessageDigest.getInstance("SHA-256", provider).digest(MESSAGE)), "SHA256 oracle"));
            check("MessageDigest SM3", () -> require(Arrays.equals(hex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
                    MessageDigest.getInstance("SM3", provider).digest("abc".getBytes(StandardCharsets.UTF_8))), "SM3 vector"));

            Map<String, Object> report = new LinkedHashMap<>();
            report.put("javaVersion", System.getProperty("java.version"));
            report.put("bcVersion", provider.getVersionStr());
            report.put("bcCertificates", certificateCount);
            report.put("servicesPassed", results.values().stream().filter("passed"::equals).count());
            report.put("results", results);
            System.out.println(JSON.writeValueAsString(report));
            require(results.size() == 18 && results.values().stream().allMatch("passed"::equals), "Packaged service regression failed");
        } finally {
            BouncyCastleSupport.close();
            require(!Files.exists(extracted), "Unload must delete extracted signed JAR");
            require(globalBc == Security.getProvider("BC"), "Unload must not change Burp provider list");
        }
    }

    private static void symmetric(Provider provider, String transformation) throws Exception {
        String algorithm = transformation.split("/")[0];
        byte[] keyBytes = algorithm.equals("DES") ? hex("133457799bbcdff1")
                : algorithm.equals("DESede") ? hex("0123456789abcdeffedcba987654321089abcdef01234567")
                : hex("0123456789abcdeffedcba9876543210");
        var key = new SecretKeySpec(keyBytes, algorithm);
        int ivSize = transformation.contains("GCM") ? 12 : (algorithm.equals("DES") || algorithm.equals("DESede")) ? 8 : 16;
        byte[] iv = new byte[ivSize];
        byte[] input = algorithm.equals("SM4") ? keyBytes : MESSAGE;
        java.security.spec.AlgorithmParameterSpec params = transformation.contains("ECB") ? null
                : transformation.contains("GCM") ? new GCMParameterSpec(128, iv) : new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(transformation, provider);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] encrypted = cipher.doFinal(input);
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        require(Arrays.equals(input, cipher.doFinal(encrypted)), "Symmetric roundtrip");
        if (algorithm.equals("SM4")) {
            require(Arrays.equals(hex("681edf34d206965e86b3e94f536e4246"), encrypted), "SM4 standard vector");
        } else {
            Cipher oracle = Cipher.getInstance(transformation, "SunJCE");
            oracle.init(Cipher.ENCRYPT_MODE, key, params);
            require(Arrays.equals(oracle.doFinal(input), encrypted), "SunJCE oracle");
        }
        var config = new HashMap<String, Object>();
        config.put("algorithm", algorithm.toLowerCase(Locale.ROOT));
        config.put("aesMode", transformation.split("/")[1]);
        config.put("padding", transformation.split("/")[2]);
        config.put("keyFormat", "hex");
        config.put("ivFormat", "hex");
        config.put("ivLiteralValue", HexFormat.of().formatHex(iv));
        config.put("cipherField", "data");
        config.put("plainField", "data");
        config.put("plainFormat", "hex");
        config.put("cipherFormat", "hex");
        ProcessingAction action = action(config);
        String json = "{\"data\":\"" + HexFormat.of().formatHex(input) + "\"}";
        String result = InternalCryptoEngine.process(action, "encrypt", json, HexFormat.of().formatHex(keyBytes)).content();
        require(JSON.readTree(result).get("data").asText().equals(HexFormat.of().formatHex(encrypted)), "Internal crypto engine oracle");
    }

    private static void sm2Engine(Provider provider) throws Exception {
        com.fasterxml.jackson.databind.JsonNode vector;
        try (var resource = PackagedCryptoProbe.class.getResourceAsStream("/crypto/sm2-openssl-vector.json")) {
            vector = JSON.readTree(resource);
        }
        var decrypt = action(Map.of("algorithm", "sm2", "payloadFormat", "raw",
                "rsaPrivateKey", vector.get("privateKeyBase64").asText()));
        String ciphertext = vector.get("ciphertextBase64").asText();
        require(vector.get("plaintextUtf8").asText().equals(InternalCryptoEngine.process(decrypt, "decrypt", ciphertext, null).content()), "SM2 independent vector");
        var encrypt = action(Map.of("algorithm", "sm2", "payloadFormat", "raw", "rsaPublicKey", vector.get("publicKeyBase64").asText()));
        String encrypted = InternalCryptoEngine.process(encrypt, "encrypt", "SM2 packaged 中文", null).content();
        require("SM2 packaged 中文".equals(InternalCryptoEngine.process(decrypt, "decrypt", encrypted, null).content()), "SM2 engine encrypt/decrypt");
        byte[] tampered = Base64.getDecoder().decode(ciphertext);
        tampered[tampered.length - 1] ^= 1;
        try {
            InternalCryptoEngine.process(decrypt, "decrypt", Base64.getEncoder().encodeToString(tampered), null);
            throw new AssertionError("Tampered SM2 digest accepted");
        } catch (ProcessorException expected) { /* SM2 integrity check must remain active. */ }
    }
}
