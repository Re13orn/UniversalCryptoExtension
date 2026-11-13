package com.universal.crypto.engine;

import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.Constants;
import com.universal.crypto.processor.impl.InternalCryptoEngine;
import org.junit.jupiter.api.Test;
import java.util.Base64;
import javax.crypto.Cipher;

import static org.junit.jupiter.api.Assertions.*;

public class InternalCryptoEngineTest {


    @Test
    public void testAesEncryptionDecryption() throws Exception {
        String originalContent = "{\"data\":\"secret\"}";
        String key = "MTIzNDU2Nzg5MDEyMzQ1Ng=="; // Base64 of "1234567890123456"
        
        ProcessingAction action = new ProcessingAction();
        action.setConfig(new java.util.HashMap<>());
        action.getConfig().put(Constants.ConfigKey.ALGORITHM, "AES");
        action.getConfig().put(Constants.ConfigKey.AES_MODE, "CBC");
        action.getConfig().put(Constants.ConfigKey.PADDING, "PKCS5Padding");
        action.getConfig().put(Constants.ConfigKey.CIPHER_FIELD, "data");
        action.getConfig().put(Constants.ConfigKey.PLAIN_FIELD, "data");
        action.getConfig().put(Constants.ConfigKey.IV_LITERAL_VALUE, "0000000000000000"); // 16 * '0'
        action.getConfig().put(Constants.ConfigKey.IV_FORMAT, "plain");
        action.getConfig().put(Constants.ConfigKey.KEY_FORMAT, "base64");
        action.getConfig().put(Constants.ConfigKey.PAYLOAD_FORMAT, "json");

        // Encrypt
        InternalCryptoEngine.InternalResult encryptedResult = InternalCryptoEngine.process(action, "ENCRYPT", originalContent, key);
        String encryptedJson = encryptedResult.content();
        
        // Decrypt
        InternalCryptoEngine.InternalResult decryptedResult = InternalCryptoEngine.process(action, "DECRYPT", encryptedJson, key);
        
        // Verify round trip
        assertTrue(decryptedResult.content().contains("\"data\":\"secret\""));
    }

    @Test
    public void testAesGcm() throws Exception {
        String originalContent = "{\"data\":\"sensitive\"}";
        String key = "MTIzNDU2Nzg5MDEyMzQ1Ng==";
        
        ProcessingAction action = new ProcessingAction();
        action.setConfig(new java.util.HashMap<>());
        action.getConfig().put(Constants.ConfigKey.ALGORITHM, "AES");
        action.getConfig().put(Constants.ConfigKey.AES_MODE, "GCM");
        action.getConfig().put(Constants.ConfigKey.PADDING, "NoPadding");
        action.getConfig().put(Constants.ConfigKey.CIPHER_FIELD, "data");
        action.getConfig().put(Constants.ConfigKey.PLAIN_FIELD, "data");
        action.getConfig().put(Constants.ConfigKey.IV_LITERAL_VALUE, "123456789012"); // 12 bytes
        action.getConfig().put(Constants.ConfigKey.IV_FORMAT, "plain");
        action.getConfig().put(Constants.ConfigKey.KEY_FORMAT, "base64");
        action.getConfig().put(Constants.ConfigKey.PAYLOAD_FORMAT, "json");
        action.getConfig().put(Constants.ConfigKey.GCM_TAG_LENGTH, 128);

        InternalCryptoEngine.InternalResult enc = InternalCryptoEngine.process(action, "ENCRYPT", originalContent, key);
        InternalCryptoEngine.InternalResult dec = InternalCryptoEngine.process(action, "DECRYPT", enc.content(), key);

        assertTrue(dec.content().contains("\"data\":\"sensitive\""));
    }

}
