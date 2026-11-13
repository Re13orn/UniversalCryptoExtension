package com.universal.crypto.processor.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorException;
import com.universal.crypto.util.BouncyCastleSupport;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class Sm2CryptoTest {
    private JsonNode vector() throws Exception {
        try (var input = getClass().getResourceAsStream("/crypto/sm2-openssl-vector.json")) {
            return new ObjectMapper().readTree(input);
        }
    }

    private ProcessingAction action(String type, String format, String keyName, String key) {
        ProcessingAction action = new ProcessingAction();
        action.setActionType(type);
        action.setConfig(new HashMap<>(Map.of("algorithm", "sm2", "cryptoProvider", "internal",
                "payloadFormat", format, "cipherFormat", "base64", "cipherField", "payload",
                "plainField", "payload", keyName, key)));
        return action;
    }

    @Test
    void decryptsIndependentOpenSslCiphertextUsingEcPkcs8Key() throws Exception {
        JsonNode v = vector();
        ProcessingAction decrypt = action("decrypt", "raw", "rsaPrivateKey", v.get("privateKeyBase64").asText());
        String result = InternalCryptoEngine.process(decrypt, "decrypt", v.get("ciphertextBase64").asText(), null).content();
        assertEquals(v.get("plaintextUtf8").asText(), result);
    }

    @Test
    void acceptsPemKeysAndEncryptsJsonWithSpkiPublicKey() throws Exception {
        JsonNode v = vector();
        String publicPem = "-----BEGIN PUBLIC KEY-----\n" + v.get("publicKeyBase64").asText() + "\n-----END PUBLIC KEY-----";
        String privatePem = "-----BEGIN PRIVATE KEY-----\n" + v.get("privateKeyBase64").asText() + "\n-----END PRIVATE KEY-----";
        String json = "{\"payload\":\"SM2 中文\",\"keep\":123}";
        var encrypt = action("encrypt", "json", "rsaPublicKey", publicPem);
        String encrypted = InternalCryptoEngine.process(encrypt, "encrypt", json, null).content();
        JsonNode cipher = new ObjectMapper().readTree(encrypted);
        assertEquals(123, cipher.get("keep").asInt());
        // Decrypt directly through EC-loaded JCE key, independently of the engine's decrypt path.
        var factory = KeyFactory.getInstance("EC", BouncyCastleSupport.getProvider());
        var key = factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(v.get("privateKeyBase64").asText())));
        Cipher oracle = Cipher.getInstance("SM2", BouncyCastleSupport.getProvider());
        oracle.init(Cipher.DECRYPT_MODE, key);
        assertEquals("SM2 中文", new String(oracle.doFinal(Base64.getDecoder().decode(cipher.get("payload").asText())), StandardCharsets.UTF_8));
        var decrypt = action("decrypt", "json", "rsaPrivateKey", privatePem);
        assertEquals(json, InternalCryptoEngine.process(decrypt, "decrypt", encrypted, null).content());
    }

    @Test
    void rejectsTamperedSm2AuthenticationDigest() throws Exception {
        JsonNode v = vector();
        byte[] ciphertext = Base64.getDecoder().decode(v.get("ciphertextBase64").asText());
        ciphertext[ciphertext.length - 1] ^= 1;
        var decrypt = action("decrypt", "raw", "rsaPrivateKey", v.get("privateKeyBase64").asText());
        assertThrows(ProcessorException.class, () -> InternalCryptoEngine.process(decrypt, "decrypt", Base64.getEncoder().encodeToString(ciphertext), null));
    }
}
