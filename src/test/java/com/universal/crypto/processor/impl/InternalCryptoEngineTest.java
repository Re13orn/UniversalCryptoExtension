package com.universal.crypto.processor.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.processor.ProcessorResult;
import com.universal.crypto.processor.impl.InternalCryptoEngine.InternalResult;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class InternalCryptoEngineTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String SAMPLE_KEY = "gx8ZD5wTjguSHKcMDKibelYOmZpxTPDaGOgadSE69lU=";
    private static final String SAMPLE_JSON = "{" +
            "\"username\":\"admin\"," +
            "\"iv_b64\":\"HUOmx+m6b9pNkuzO\"," +
            "\"ciphertext_b64\":\"cKi7wEBiPhOKrmsk5x8xA4wzeiCx\"}";

    @Test
    void decryptsAesGcmJsonPayload() throws Exception {
        ProcessingAction action = buildAction(Constants.ActionType.DECRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "aes-gcm",
                Constants.ConfigKey.PAYLOAD_FORMAT, "json",
                Constants.ConfigKey.CIPHER_FIELD, "ciphertext_b64",
                Constants.ConfigKey.IV_FIELD, "iv_b64",
                Constants.ConfigKey.PLAIN_FIELD, "ciphertext_b64",
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal"
        ));

        InternalResult result = InternalCryptoEngine.process(action,
                Constants.ActionType.DECRYPT,
                SAMPLE_JSON,
                SAMPLE_KEY);

        JsonNode node = OBJECT_MAPPER.readTree(result.content());
        assertEquals("admin", node.get("ciphertext_b64").asText());
    }

    @Test
    void encryptsAesGcmJsonPayload() throws Exception {
        String plaintextJson = "{" +
                "\"username\":\"admin\"," +
                "\"iv_b64\":\"HUOmx+m6b9pNkuzO\"," +
                "\"ciphertext_b64\":\"admin\"}";

        ProcessingAction action = buildAction(Constants.ActionType.ENCRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "aes-gcm",
                Constants.ConfigKey.PAYLOAD_FORMAT, "json",
                Constants.ConfigKey.CIPHER_FIELD, "ciphertext_b64",
                Constants.ConfigKey.IV_FIELD, "iv_b64",
                Constants.ConfigKey.PLAIN_FIELD, "ciphertext_b64",
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal"
        ));

        InternalResult result = InternalCryptoEngine.process(action,
                Constants.ActionType.ENCRYPT,
                plaintextJson,
                SAMPLE_KEY);

        JsonNode node = OBJECT_MAPPER.readTree(result.content());
        assertEquals("cKi7wEBiPhOKrmsk5x8xA4wzeiCx", node.get("ciphertext_b64").asText());
    }

    @Test
    void decryptsAesWithRegexFields() throws Exception {
        String json = "{" +
                "\"cipher_value\":\"cKi7wEBiPhOKrmsk5x8xA4wzeiCx\"," +
                "\"dynamic_iv\":\"HUOmx+m6b9pNkuzO\"}";

        ProcessingAction action = buildAction(Constants.ActionType.DECRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "aes-gcm",
                Constants.ConfigKey.PAYLOAD_FORMAT, "json",
                Constants.ConfigKey.CIPHER_FIELD, "regex:^cipher_.*",
                Constants.ConfigKey.PLAIN_FIELD, "regex:^cipher_.*",
                Constants.ConfigKey.IV_FIELD, "regex:^dynamic_.*",
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal"
        ));

        InternalResult result = InternalCryptoEngine.process(action,
                Constants.ActionType.DECRYPT,
                json,
                SAMPLE_KEY);

        JsonNode node = OBJECT_MAPPER.readTree(result.content());
        assertEquals("admin", node.get("cipher_value").asText());
    }

    @Test
    void encryptsAesWithLiteralIv() throws Exception {
        String plaintextJson = "{" +
                "\"ciphertext_b64\":\"admin\"}";

        ProcessingAction action = buildAction(Constants.ActionType.ENCRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "aes-gcm",
                Constants.ConfigKey.PAYLOAD_FORMAT, "json",
                Constants.ConfigKey.CIPHER_FIELD, "ciphertext_b64",
                Constants.ConfigKey.PLAIN_FIELD, "ciphertext_b64",
                Constants.ConfigKey.IV_FIELD, "iv_literal",
                Constants.ConfigKey.IV_LITERAL_VALUE, "HUOmx+m6b9pNkuzO",
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal"
        ));

        InternalResult result = InternalCryptoEngine.process(action,
                Constants.ActionType.ENCRYPT,
                plaintextJson,
                SAMPLE_KEY);

        JsonNode node = OBJECT_MAPPER.readTree(result.content());
        assertEquals("HUOmx+m6b9pNkuzO", node.get("iv_literal").asText());
        assertEquals("cKi7wEBiPhOKrmsk5x8xA4wzeiCx", node.get("ciphertext_b64").asText());
    }

    @Test
    void roundTripRsaEncryption() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        String publicPem = toPem("PUBLIC KEY", keyPair.getPublic());
        String privatePem = toPem("PRIVATE KEY", keyPair.getPrivate());

        String originalJson = "{" +
                "\"payload\":\"hello-world\"}";

        ProcessingAction encryptAction = buildAction(Constants.ActionType.ENCRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "rsa",
                Constants.ConfigKey.PAYLOAD_FORMAT, "json",
                Constants.ConfigKey.CIPHER_FIELD, "payload",
                Constants.ConfigKey.PLAIN_FIELD, "payload",
                Constants.ConfigKey.RSA_PUBLIC_KEY, publicPem,
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal"
        ));

        InternalResult encrypted = InternalCryptoEngine.process(encryptAction,
                Constants.ActionType.ENCRYPT,
                originalJson,
                null);

        JsonNode cipherNode = OBJECT_MAPPER.readTree(encrypted.content());
        String cipherText = cipherNode.get("payload").asText();
        assertNotNull(cipherText);

        ProcessingAction decryptAction = buildAction(Constants.ActionType.DECRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "rsa",
                Constants.ConfigKey.PAYLOAD_FORMAT, "json",
                Constants.ConfigKey.CIPHER_FIELD, "payload",
                Constants.ConfigKey.PLAIN_FIELD, "payload",
                Constants.ConfigKey.RSA_PRIVATE_KEY, privatePem,
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal"
        ));

        InternalResult decrypted = InternalCryptoEngine.process(decryptAction,
                Constants.ActionType.DECRYPT,
                encrypted.content(),
                null);

        JsonNode resultNode = OBJECT_MAPPER.readTree(decrypted.content());
        assertEquals("hello-world", resultNode.get("payload").asText());
    }

    @Test
    void base64JsonRoundTrip() throws Exception {
        String json = "{" +
                "\"ciphertext\":\"aGVsbG8=\"}";

        ProcessingAction decryptAction = buildAction(Constants.ActionType.DECRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "base64",
                Constants.ConfigKey.PAYLOAD_FORMAT, "json",
                Constants.ConfigKey.CIPHER_FIELD, "ciphertext",
                Constants.ConfigKey.PLAIN_FIELD, "ciphertext",
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal"
        ));

        InternalResult decrypted = InternalCryptoEngine.process(decryptAction,
                Constants.ActionType.DECRYPT,
                json,
                null);

        JsonNode node = OBJECT_MAPPER.readTree(decrypted.content());
        assertEquals("hello", node.get("ciphertext").asText());

        ProcessingAction encryptAction = buildAction(Constants.ActionType.ENCRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "base64",
                Constants.ConfigKey.PAYLOAD_FORMAT, "json",
                Constants.ConfigKey.CIPHER_FIELD, "ciphertext",
                Constants.ConfigKey.PLAIN_FIELD, "ciphertext",
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal"
        ));

        InternalResult encrypted = InternalCryptoEngine.process(encryptAction,
                Constants.ActionType.ENCRYPT,
                decrypted.content(),
                null);

        JsonNode encryptedNode = OBJECT_MAPPER.readTree(encrypted.content());
        assertEquals("aGVsbG8=", encryptedNode.get("ciphertext").asText());
    }

    @Test
    void desCbcJsonRoundTrip() throws Exception {
        String json = "{\"payload\":\"legacy-secret\"}";
        ProcessingAction action = buildAction(Constants.ActionType.ENCRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "DES-CBC",
                Constants.ConfigKey.PAYLOAD_FORMAT, "json",
                Constants.ConfigKey.CIPHER_FIELD, "payload",
                Constants.ConfigKey.PLAIN_FIELD, "payload",
                Constants.ConfigKey.IV_LITERAL_VALUE, "12345678",
                Constants.ConfigKey.IV_FORMAT, "plain",
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal"
        ));

        String key = Base64.getEncoder().encodeToString("12345678".getBytes());
        InternalResult encrypted = InternalCryptoEngine.process(action, Constants.ActionType.ENCRYPT, json, key);
        InternalResult decrypted = InternalCryptoEngine.process(action, Constants.ActionType.DECRYPT, encrypted.content(), key);

        JsonNode node = OBJECT_MAPPER.readTree(decrypted.content());
        assertEquals("legacy-secret", node.get("payload").asText());
    }

    @Test
    void tripleDesCbcJsonRoundTrip() throws Exception {
        String json = "{\"payload\":\"legacy-3des\"}";
        ProcessingAction action = buildAction(Constants.ActionType.ENCRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "3DES-CBC",
                Constants.ConfigKey.PAYLOAD_FORMAT, "json",
                Constants.ConfigKey.CIPHER_FIELD, "payload",
                Constants.ConfigKey.PLAIN_FIELD, "payload",
                Constants.ConfigKey.IV_LITERAL_VALUE, "12345678",
                Constants.ConfigKey.IV_FORMAT, "plain",
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal"
        ));

        String key = Base64.getEncoder().encodeToString("123456789012345678901234".getBytes());
        InternalResult encrypted = InternalCryptoEngine.process(action, Constants.ActionType.ENCRYPT, json, key);
        InternalResult decrypted = InternalCryptoEngine.process(action, Constants.ActionType.DECRYPT, encrypted.content(), key);

        JsonNode node = OBJECT_MAPPER.readTree(decrypted.content());
        assertEquals("legacy-3des", node.get("payload").asText());
    }

    @Test
    void hexRawRoundTrip() throws Exception {
        ProcessingAction action = buildAction(Constants.ActionType.ENCRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "Hex",
                Constants.ConfigKey.PAYLOAD_FORMAT, "raw",
                Constants.ConfigKey.PLAIN_FORMAT, "plain",
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal"
        ));

        InternalResult encoded = InternalCryptoEngine.process(action, Constants.ActionType.ENCRYPT, "hello", null);
        assertEquals("68656c6c6f", encoded.content());

        InternalResult decoded = InternalCryptoEngine.process(action, Constants.ActionType.DECRYPT, encoded.content(), null);
        assertEquals("hello", decoded.content());
    }

    @Test
    void urlJsonRoundTrip() throws Exception {
        String json = "{\"value\":\"a b+c/中文\"}";
        ProcessingAction action = buildAction(Constants.ActionType.ENCRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "URL",
                Constants.ConfigKey.PAYLOAD_FORMAT, "json",
                Constants.ConfigKey.CIPHER_FIELD, "value",
                Constants.ConfigKey.PLAIN_FIELD, "value",
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal"
        ));

        InternalResult encoded = InternalCryptoEngine.process(action, Constants.ActionType.ENCRYPT, json, null);
        JsonNode encodedNode = OBJECT_MAPPER.readTree(encoded.content());
        assertEquals("a+b%2Bc%2F%E4%B8%AD%E6%96%87", encodedNode.get("value").asText());

        InternalResult decoded = InternalCryptoEngine.process(action, Constants.ActionType.DECRYPT, encoded.content(), null);
        JsonNode decodedNode = OBJECT_MAPPER.readTree(decoded.content());
        assertEquals("a b+c/中文", decodedNode.get("value").asText());
    }

    @Test
    void cryptoProcessorAllowsDigestWithoutKey() throws Exception {
        ProcessingAction action = buildAction(Constants.ActionType.ENCRYPT, Map.of(
                Constants.ConfigKey.ALGORITHM, "SHA-256",
                Constants.ConfigKey.CRYPTO_PROVIDER, "internal",
                Constants.ConfigKey.KEY_SOURCE, "none",
                Constants.ConfigKey.PAYLOAD_FORMAT, "raw",
                Constants.ConfigKey.CIPHER_FORMAT, "hex"
        ));

        CryptoProcessor processor = new CryptoProcessor(null);
        ProcessorContext context = ProcessorContext.forRequest("POST", new URL("https://example.com"), Map.of(), "REPEATER").build();

        ProcessorResult result = processor.process(action, "hello", context);
        assertEquals(DigestUtils.sha256Hex("hello"), result.getProcessedContent());
    }

    private ProcessingAction buildAction(String actionType, Map<String, Object> configs) {
        ProcessingAction action = new ProcessingAction();
        action.setActionType(actionType);
        Map<String, Object> map = new HashMap<>(configs);
        action.setConfig(map);
        return action;
    }

    private String toPem(String type, PublicKey key) {
        return toPem(type, key.getEncoded());
    }

    private String toPem(String type, PrivateKey key) {
        return toPem(type, key.getEncoded());
    }

    private String toPem(String type, byte[] encoded) {
        String base64 = Base64.getEncoder().encodeToString(encoded);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        sb.append(base64);
        sb.append("\n-----END ").append(type).append("-----");
        return sb.toString();
    }
}
