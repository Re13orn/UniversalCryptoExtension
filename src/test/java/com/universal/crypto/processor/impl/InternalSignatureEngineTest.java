package com.universal.crypto.processor.impl;

import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.Constants.ConfigKey;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class InternalSignatureEngineTest {

    @Test
    void testHmacSha256() throws Exception {
        ProcessingAction action = new ProcessingAction();
        Map<String, Object> config = new HashMap<>();
        config.put(ConfigKey.ALGORITHM, "HmacSHA256");
        action.setConfig(config);
        
        String data = "Hello World";
        String key = "secret";
        
        String signature = InternalSignatureEngine.sign(action, data, key);
        assertNotNull(signature);
    }

    @Test
    void testRsaSha256() throws Exception {
        ProcessingAction action = new ProcessingAction();
        Map<String, Object> config = new HashMap<>();
        config.put(ConfigKey.ALGORITHM, "SHA256withRSA");
        action.setConfig(config);
        
        String data = "Hello World";
        
        String signature = InternalSignatureEngine.sign(action, data, generatePkcs8PrivateKeyPem());
        assertNotNull(signature);
        assertFalse(signature.isEmpty());
    }

    private String generatePkcs8PrivateKeyPem() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        String encoded = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(keyPair.getPrivate().getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + encoded + "\n-----END PRIVATE KEY-----";
    }
}
