package com.universal.crypto.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;

class ProcessingActionTest {

    private ProcessingAction action;

    @BeforeEach
    void setUp() {
        action = new ProcessingAction();
    }

    @Test void nestedConfigurationCloneDoesNotShareTemplatesOrLists() {
        var nested=new java.util.HashMap<String,Object>();nested.put("items",new java.util.ArrayList<>(java.util.List.of("original")));
        action.setConfig(java.util.Map.of("headerTemplates",nested));
        var copy=action.clone();
        var clonedMap=(java.util.Map<String,Object>)copy.getConfig("headerTemplates");
        ((java.util.List<String>)clonedMap.get("items")).set(0,"changed");
        var originalMap=(java.util.Map<?,?>)action.getConfig("headerTemplates");
        assertEquals("original",((java.util.List<?>)originalMap.get("items")).get(0));
        assertEquals("original",((java.util.List<?>)nested.get("items")).get(0));
    }

    @Test void configurationOwnsAMutableCopyInsteadOfCallerMap() {
        var supplied=new java.util.HashMap<String,Object>();supplied.put("algorithm","Hex");
        action.setConfig(supplied);supplied.put("algorithm","Base64");assertEquals("Hex",action.getConfigString("algorithm"));
        action.setConfig(java.util.Map.of("algorithm","Hex"));action.setConfig("algorithm","Base64");assertEquals("Base64",action.getConfigString("algorithm"));
    }

    @Test
    void testDefaultConstructor() {
        ProcessingAction newAction = new ProcessingAction();
        assertTrue(newAction.isEnabled());
        assertNotNull(newAction.getConfig());
        assertTrue(newAction.getConfig().isEmpty());
    }

    @Test
    void testConstructorWithBasicProperties() {
        ProcessingAction newAction = new ProcessingAction("decrypt", "body", "crypto");
        assertEquals("decrypt", newAction.getActionType());
        assertEquals("body", newAction.getTargetType());
        assertEquals("crypto", newAction.getProcessor());
        assertTrue(newAction.isEnabled());
        assertNotNull(newAction.getConfig());
    }

    @Test
    void testConstructorWithTargetName() {
        ProcessingAction newAction = new ProcessingAction("sign", "header", "X-Signature", "signature");
        assertEquals("sign", newAction.getActionType());
        assertEquals("header", newAction.getTargetType());
        assertEquals("X-Signature", newAction.getTargetName());
        assertEquals("signature", newAction.getProcessor());
    }

    @Test
    void testBasicProperties() {
        action.setActionType("encrypt");
        action.setTargetType("field");
        action.setTargetName("$.data.value");
        action.setProcessor("crypto");
        action.setEnabled(false);
        action.setDescription("Encrypt field value");

        assertEquals("encrypt", action.getActionType());
        assertEquals("field", action.getTargetType());
        assertEquals("$.data.value", action.getTargetName());
        assertEquals("crypto", action.getProcessor());
        assertFalse(action.isEnabled());
        assertEquals("Encrypt field value", action.getDescription());
    }

    @Test
    void testConfigManagement() {
        Map<String, Object> config = new HashMap<>();
        config.put("algorithm", "aes-256");
        config.put("key", "secret-key");

        action.setConfig(config);
        assertEquals(config, action.getConfig());
        assertEquals("aes-256", action.getConfig("algorithm"));
        assertEquals("secret-key", action.getConfig("key"));
    }

    @Test
    void testConfigWithNullValue() {
        action.setConfig(null);
        assertNotNull(action.getConfig());
        assertTrue(action.getConfig().isEmpty());
    }

    @Test
    void testIndividualConfigMethods() {
        action.setConfig("algorithm", "aes-gcm");
        action.setConfig("keySize", 256);
        action.setConfig("enabled", true);

        assertEquals("aes-gcm", action.getConfig("algorithm"));
        assertEquals(256, action.getConfig("keySize"));
        assertEquals(true, action.getConfig("enabled"));

        assertNull(action.getConfig("nonexistent"));
    }

    @Test
    void testConfigWithDefault() {
        action.setConfig("timeout", 5000);

        assertEquals(5000, action.getConfig("timeout", 3000));
        assertEquals(3000, action.getConfig("nonexistent", 3000));
        assertEquals("default", action.getConfig("missing", "default"));
    }

    @Test
    void testConfigString() {
        action.setConfig("algorithm", "aes-256");
        action.setConfig("count", 100);

        assertEquals("aes-256", action.getConfigString("algorithm"));
        assertEquals("100", action.getConfigString("count"));
        assertNull(action.getConfigString("missing"));

        assertEquals("aes-256", action.getConfigString("algorithm", "default"));
        assertEquals("default", action.getConfigString("missing", "default"));
    }

    @Test
    void testHasConfig() {
        assertFalse(action.hasConfig("algorithm"));

        action.setConfig("algorithm", "aes-256");
        assertTrue(action.hasConfig("algorithm"));
        assertFalse(action.hasConfig("key"));
    }

    @Test
    void testRemoveConfig() {
        action.setConfig("algorithm", "aes-256");
        action.setConfig("key", "secret");

        assertTrue(action.hasConfig("algorithm"));
        Object removed = action.removeConfig("algorithm");
        assertEquals("aes-256", removed);
        assertFalse(action.hasConfig("algorithm"));

        assertNull(action.removeConfig("nonexistent"));
    }

    @Test
    void testIsValid() {
        assertFalse(action.isValid());

        action.setActionType("decrypt");
        assertFalse(action.isValid());

        action.setTargetType("body");
        assertFalse(action.isValid());

        action.setProcessor("crypto");
        assertTrue(action.isValid());

        // Test with empty strings
        action.setActionType("");
        assertFalse(action.isValid());

        action.setActionType("decrypt");
        action.setTargetType("");
        assertFalse(action.isValid());

        action.setTargetType("body");
        action.setProcessor("");
        assertFalse(action.isValid());

        // Test with null values
        action.setProcessor("crypto");
        action.setActionType(null);
        assertFalse(action.isValid());
    }

    @Test
    void testClone() {
        action.setActionType("sign");
        action.setTargetType("header");
        action.setTargetName("X-Signature");
        action.setProcessor("signature");
        action.setEnabled(false);
        action.setDescription("Add HMAC signature");
        action.setConfig("algorithm", "hmac-sha256");
        action.setConfig("key", "secret-key");

        ProcessingAction cloned = action.clone();

        assertEquals(action.getActionType(), cloned.getActionType());
        assertEquals(action.getTargetType(), cloned.getTargetType());
        assertEquals(action.getTargetName(), cloned.getTargetName());
        assertEquals(action.getProcessor(), cloned.getProcessor());
        assertEquals(action.isEnabled(), cloned.isEnabled());
        assertEquals(action.getDescription(), cloned.getDescription());
        assertEquals(action.getConfig(), cloned.getConfig());

        // Verify deep copy
        assertNotSame(action, cloned);
        assertNotSame(action.getConfig(), cloned.getConfig());

        // Verify independence
        cloned.setConfig("newKey", "newValue");
        assertFalse(action.hasConfig("newKey"));
    }

    @Test
    void testEquals() {
        ProcessingAction action1 = new ProcessingAction("decrypt", "body", "crypto");
        action1.setEnabled(false);
        action1.setConfig("algorithm", "aes-256");

        ProcessingAction action2 = new ProcessingAction("decrypt", "body", "crypto");
        action2.setEnabled(false);
        action2.setConfig("algorithm", "aes-256");

        assertEquals(action1, action2);
        assertEquals(action1.hashCode(), action2.hashCode());

        action2.setTargetName("different");
        assertNotEquals(action1, action2);
    }

    @Test
    void testToString() {
        action.setActionType("decrypt");
        action.setTargetType("body");
        action.setProcessor("crypto");
        action.setEnabled(false);
        action.setConfig("algorithm", "aes-256");

        String str = action.toString();
        assertTrue(str.contains("decrypt"));
        assertTrue(str.contains("body"));
        assertTrue(str.contains("crypto"));
        assertTrue(str.contains("enabled=false"));
        assertTrue(str.contains("algorithm=aes-256"));
    }

    @Test
    void testToStringWithTargetName() {
        action.setActionType("sign");
        action.setTargetType("header");
        action.setTargetName("X-Signature");
        action.setProcessor("signature");

        String str = action.toString();
        assertTrue(str.contains("X-Signature"));
    }

    @Test
    void testConfigTypeCasting() {
        action.setConfig("stringValue", "test");
        action.setConfig("intValue", 42);
        action.setConfig("boolValue", true);

        // Test with correct type
        assertEquals("test", action.getConfig("stringValue", "default"));
        assertEquals(42, action.getConfig("intValue", 0));
        assertEquals(true, action.getConfig("boolValue", false));

        // Test with wrong type - should return default
        assertEquals(999, action.getConfig("stringValue", 999));
        assertEquals("default", action.getConfig("intValue", "default"));
    }
}