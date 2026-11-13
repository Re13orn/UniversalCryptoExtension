package com.universal.crypto.engine;

import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.Constants;
import com.universal.crypto.processor.impl.InternalSignatureEngine;
import org.junit.jupiter.api.Test;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

public class InternalSignatureEngineTest {

    @Test
    public void testHmacSha256() throws Exception {
        String data = "Message";
        String key = "Secret";
        // SHA256("Message", "Secret") -> 
        // We can check against known good value or just property
        
        ProcessingAction action = new ProcessingAction();
        action.setConfig(new HashMap<>());
        action.getConfig().put(Constants.ConfigKey.ALGORITHM, "HMAC-SHA256");
        action.getConfig().put(Constants.ConfigKey.CIPHER_FORMAT, "hex");

        String signature = InternalSignatureEngine.sign(action, data, key);
        
        assertNotNull(signature);
        assertEquals(64, signature.length()); // SHA256 hex is 64 chars
    }

    @Test
    public void testHmacMd5() throws Exception {
        String data = "data";
        String key = "key";
        
        ProcessingAction action = new ProcessingAction();
        action.setConfig(new HashMap<>());
        action.getConfig().put(Constants.ConfigKey.ALGORITHM, "HMAC-MD5");
        action.getConfig().put(Constants.ConfigKey.CIPHER_FORMAT, "base64");

        String signature = InternalSignatureEngine.sign(action, data, key);
        
        assertNotNull(signature);
        // MD5 is 16 bytes = 24 chars in base64 (approx)
    }

    @Test
    public void testSimpleHash() throws Exception {
        // "MD5" -> likely treated as Salted Hash in the engine
        String data = "data";
        String key = "salt";
        
        ProcessingAction action = new ProcessingAction();
        action.setConfig(new HashMap<>());
        action.getConfig().put(Constants.ConfigKey.ALGORITHM, "MD5");
        action.getConfig().put(Constants.ConfigKey.CIPHER_FORMAT, "hex");

        String signature = InternalSignatureEngine.sign(action, data, key);
        
        assertNotNull(signature);
        assertEquals(32, signature.length()); // MD5 hex is 32 chars
    }

    @Test
    public void testPlainHashUppercaseWithoutKey() throws Exception {
        ProcessingAction action = new ProcessingAction();
        action.setConfig(new HashMap<>());
        action.getConfig().put(Constants.ConfigKey.ALGORITHM, "SHA-256");
        action.getConfig().put(Constants.ConfigKey.CIPHER_FORMAT, "hex");
        action.getConfig().put(Constants.ConfigKey.HASH_KEY_PLACEMENT, "none");
        action.getConfig().put(Constants.ConfigKey.SIGNATURE_HEX_CASE, "upper");

        String signature = InternalSignatureEngine.sign(action, "abc", "");

        assertEquals("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", signature);
    }
}
