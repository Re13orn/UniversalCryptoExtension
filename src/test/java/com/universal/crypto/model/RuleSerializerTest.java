package com.universal.crypto.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;

class RuleSerializerTest {

    private ProcessingRule rule;
    private RuleCondition condition;
    private ProcessingAction action;

    @Test void responseEditorSendRoundTripsThroughImportExport() {
        var responseRule = new ProcessingRule("response-editor"); responseRule.setCondition(new RuleCondition());
        var encrypt = new ProcessingAction("encrypt", "body", "script");
        encrypt.setConfig("executionPhase", "response-editor-send"); encrypt.setConfig("scriptCode", "return Base64.encode(content);");
        responseRule.addResponseAction(encrypt);
        var imported = RuleSerializer.importRules(RuleSerializer.exportRules(List.of(responseRule)));
        assertEquals("response-editor-send", imported.get(0).getResponseActions().get(0).getConfigString("executionPhase"));
        assertFalse(imported.get(0).isEnabled());
    }

    @BeforeEach
    void setUp() {
        rule = new ProcessingRule("test-rule");
        rule.setName("Test Rule");
        rule.setDescription("Test Description");
        rule.setEnabled(true);
        rule.setPriority(10);

        condition = new RuleCondition();
        condition.addHost("example.com");
        condition.addMethod("POST");
        condition.setContentType("application/json");
        rule.setCondition(condition);

        action = new ProcessingAction("decrypt", "body", "crypto");
        action.setDescription("Decrypt body content");
        action.setConfig("algorithm", "aes-256");
        action.setConfig("keySource", "lookup");
        rule.addRequestAction(action);
    }

    @Test
    void testRuleToJson() {
        String json = RuleSerializer.toJson(rule);
        assertNotNull(json);
        assertFalse(json.isEmpty());
        assertTrue(json.contains("test-rule"));
        assertTrue(json.contains("Test Rule"));
        assertTrue(json.contains("example.com"));
        assertTrue(json.contains("POST"));
        assertTrue(json.contains("decrypt"));
        assertTrue(json.contains("aes-256"));
    }

    @Test
    void testRuleToJsonWithNull() {
        String json = RuleSerializer.toJson((ProcessingRule) null);
        assertEquals("null", json);
    }

    @Test
    void testRuleFromJson() {
        String json = RuleSerializer.toJson(rule);
        ProcessingRule deserializedRule = RuleSerializer.fromJson(json);

        assertNotNull(deserializedRule);
        assertEquals(rule.getId(), deserializedRule.getId());
        assertEquals(rule.getName(), deserializedRule.getName());
        assertEquals(rule.getDescription(), deserializedRule.getDescription());
        assertEquals(rule.isEnabled(), deserializedRule.isEnabled());
        assertEquals(rule.getPriority(), deserializedRule.getPriority());

        assertNotNull(deserializedRule.getCondition());
        assertEquals(rule.getCondition().getHosts(), deserializedRule.getCondition().getHosts());
        assertEquals(rule.getCondition().getMethods(), deserializedRule.getCondition().getMethods());

        assertEquals(rule.getRequestActionCount(), deserializedRule.getRequestActionCount());
        if (rule.hasRequestActions() && deserializedRule.hasRequestActions()) {
            ProcessingAction originalAction = rule.getRequestActions().get(0);
            ProcessingAction deserializedAction = deserializedRule.getRequestActions().get(0);
            assertEquals(originalAction.getActionType(), deserializedAction.getActionType());
            assertEquals(originalAction.getTargetType(), deserializedAction.getTargetType());
            assertEquals(originalAction.getProcessor(), deserializedAction.getProcessor());
        }
    }

    @Test
    void testRuleFromJsonWithNull() {
        assertNull(RuleSerializer.fromJson(null));
        assertNull(RuleSerializer.fromJson(""));
        assertNull(RuleSerializer.fromJson("   "));
        assertNull(RuleSerializer.fromJson("null"));
    }

    @Test
    void testRuleFromJsonWithInvalidJson() {
        assertThrows(RuntimeException.class, () -> {
            RuleSerializer.fromJson("invalid json {");
        });
    }

    @Test
    void testRuleListToJson() {
        ProcessingRule rule2 = new ProcessingRule("test-rule-2");
        rule2.setName("Test Rule 2");
        List<ProcessingRule> rules = Arrays.asList(rule, rule2);

        String json = RuleSerializer.toJson(rules);
        assertNotNull(json);
        assertTrue(json.contains("test-rule"));
        assertTrue(json.contains("test-rule-2"));
        assertTrue(json.startsWith("["));
        assertTrue(json.endsWith("]"));
    }

    @Test
    void testRuleListToJsonWithNull() {
        String json = RuleSerializer.toJson((List<ProcessingRule>) null);
        assertEquals("null", json);
    }

    @Test
    void testRuleListFromJson() {
        ProcessingRule rule2 = new ProcessingRule("test-rule-2");
        rule2.setName("Test Rule 2");
        List<ProcessingRule> originalRules = Arrays.asList(rule, rule2);

        String json = RuleSerializer.toJson(originalRules);
        List<ProcessingRule> deserializedRules = RuleSerializer.fromJsonList(json);

        assertNotNull(deserializedRules);
        assertEquals(2, deserializedRules.size());

        assertEquals(originalRules.get(0).getId(), deserializedRules.get(0).getId());
        assertEquals(originalRules.get(0).getName(), deserializedRules.get(0).getName());
        assertEquals(originalRules.get(1).getId(), deserializedRules.get(1).getId());
        assertEquals(originalRules.get(1).getName(), deserializedRules.get(1).getName());
    }

    @Test
    void testRuleListFromJsonWithNull() {
        assertNull(RuleSerializer.fromJsonList(null));
        assertNull(RuleSerializer.fromJsonList("null"));

        // Empty strings now return empty list (not null)
        List<ProcessingRule> emptyResult = RuleSerializer.fromJsonList("");
        assertNotNull(emptyResult);
        assertTrue(emptyResult.isEmpty());

        List<ProcessingRule> emptyResult2 = RuleSerializer.fromJsonList("   ");
        assertNotNull(emptyResult2);
        assertTrue(emptyResult2.isEmpty());
    }

    @Test
    void testRuleListFromJsonWithInvalidJson() {
        assertThrows(RuntimeException.class, () -> {
            RuleSerializer.fromJsonList("invalid json [");
        });
    }

    @Test
    void testIsValidJson() {
        assertTrue(RuleSerializer.isValidJson("{}"));
        assertTrue(RuleSerializer.isValidJson("[]"));
        assertTrue(RuleSerializer.isValidJson("{\"key\": \"value\"}"));
        assertTrue(RuleSerializer.isValidJson("[1, 2, 3]"));

        assertFalse(RuleSerializer.isValidJson(null));
        assertFalse(RuleSerializer.isValidJson(""));
        assertFalse(RuleSerializer.isValidJson("   "));
        assertFalse(RuleSerializer.isValidJson("invalid json"));
        assertFalse(RuleSerializer.isValidJson("{key: value}"));
    }

    @Test
    void testIsValidRuleJson() {
        String validRuleJson = RuleSerializer.toJson(rule);
        assertTrue(RuleSerializer.isValidRuleJson(validRuleJson));

        assertFalse(RuleSerializer.isValidRuleJson(null));
        assertFalse(RuleSerializer.isValidRuleJson("{}"));
        assertFalse(RuleSerializer.isValidRuleJson("{\"name\": \"test\"}"));
        assertFalse(RuleSerializer.isValidRuleJson("invalid json"));

        // Rule without ID should be invalid
        String ruleWithoutId = "{\"name\": \"Test Rule\", \"enabled\": true}";
        assertFalse(RuleSerializer.isValidRuleJson(ruleWithoutId));

        // Rule with empty ID should be invalid
        String ruleWithEmptyId = "{\"id\": \"\", \"name\": \"Test Rule\", \"enabled\": true}";
        assertFalse(RuleSerializer.isValidRuleJson(ruleWithEmptyId));
    }

    @Test
    void testIsValidRuleListJson() {
        List<ProcessingRule> rules = Arrays.asList(rule);
        String validRuleListJson = RuleSerializer.toJson(rules);
        assertTrue(RuleSerializer.isValidRuleListJson(validRuleListJson));

        assertTrue(RuleSerializer.isValidRuleListJson("[]"));

        assertFalse(RuleSerializer.isValidRuleListJson(null));
        assertFalse(RuleSerializer.isValidRuleListJson("{}"));
        assertFalse(RuleSerializer.isValidRuleListJson("invalid json"));
        assertFalse(RuleSerializer.isValidRuleListJson("[invalid json]"));
    }

    @Test
    void testPrettyPrint() {
        String compactJson = "{\"id\":\"test\",\"name\":\"Test\"}";
        String prettyJson = RuleSerializer.prettyPrint(compactJson);

        assertNotNull(prettyJson);
        assertTrue(prettyJson.contains("\n"));
        assertTrue(prettyJson.contains("  "));
        assertTrue(prettyJson.contains("test"));
        assertTrue(prettyJson.contains("Test"));
    }

    @Test
    void testPrettyPrintWithInvalidJson() {
        assertThrows(RuntimeException.class, () -> {
            RuleSerializer.prettyPrint("invalid json");
        });
    }

    @Test
    void testGetObjectMapper() {
        assertNotNull(RuleSerializer.getObjectMapper());
        assertSame(RuleSerializer.getObjectMapper(), RuleSerializer.getObjectMapper());
    }

    @Test
    void testComplexRuleSerialization() {
        // Create a complex rule with multiple actions and conditions
        ProcessingRule complexRule = new ProcessingRule("complex-rule");
        complexRule.setName("Complex Rule");
        complexRule.setDescription("A complex rule for testing");
        complexRule.setEnabled(false);
        complexRule.setPriority(5);

        RuleCondition complexCondition = new RuleCondition();
        complexCondition.addHost("*.example.com");
        complexCondition.addHost("test.com");
        complexCondition.addPath("/api/*");
        complexCondition.addPath("/secure/*");
        complexCondition.addMethod("POST");
        complexCondition.addMethod("PUT");
        complexCondition.addHeader("Content-Type", "application/json");
        complexCondition.addHeader("Authorization", "Bearer *");
        complexCondition.setContentPattern("encrypted");
        complexCondition.setToolSource("PROXY");
        complexRule.setCondition(complexCondition);

        ProcessingAction requestAction1 = new ProcessingAction("decrypt", "body", "crypto");
        requestAction1.setDescription("Decrypt request body");
        requestAction1.setConfig("algorithm", "aes-gcm");
        requestAction1.setConfig("keySource", "lookup");
        requestAction1.setConfig("lookupMethod", "md5-hash");
        complexRule.addRequestAction(requestAction1);

        ProcessingAction requestAction2 = new ProcessingAction("sign", "header", "X-Signature", "signature");
        requestAction2.setDescription("Add signature header");
        requestAction2.setConfig("algorithm", "hmac-sha256");
        requestAction2.setConfig("keySource", "static");
        requestAction2.setConfig("keyValue", "secret-key");
        complexRule.addRequestAction(requestAction2);

        ProcessingAction responseAction = new ProcessingAction("decrypt", "body", "crypto");
        responseAction.setDescription("Decrypt response body");
        responseAction.setConfig("algorithm", "aes-gcm");
        responseAction.setConfig("keySource", "cached");
        complexRule.addResponseAction(responseAction);

        // Serialize and deserialize
        String json = RuleSerializer.toJson(complexRule);
        ProcessingRule deserializedRule = RuleSerializer.fromJson(json);

        // Verify complex structure is preserved
        assertEquals(complexRule.getId(), deserializedRule.getId());
        assertEquals(complexRule.getName(), deserializedRule.getName());
        assertEquals(complexRule.isEnabled(), deserializedRule.isEnabled());
        assertEquals(complexRule.getPriority(), deserializedRule.getPriority());

        assertEquals(complexRule.getCondition().getHosts().size(),
                    deserializedRule.getCondition().getHosts().size());
        assertEquals(complexRule.getCondition().getPaths().size(),
                    deserializedRule.getCondition().getPaths().size());
        assertEquals(complexRule.getCondition().getMethods().size(),
                    deserializedRule.getCondition().getMethods().size());
        assertEquals(complexRule.getCondition().getHeaders().size(),
                    deserializedRule.getCondition().getHeaders().size());

        assertEquals(complexRule.getRequestActionCount(), deserializedRule.getRequestActionCount());
        assertEquals(complexRule.getResponseActionCount(), deserializedRule.getResponseActionCount());
    }
}