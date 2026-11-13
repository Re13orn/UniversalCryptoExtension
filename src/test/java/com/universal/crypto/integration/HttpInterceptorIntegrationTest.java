package com.universal.crypto.integration;

import com.universal.crypto.engine.RuleConfigStorage;
import com.universal.crypto.engine.RuleMatchEngine;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.handler.HttpInterceptor;
import com.universal.crypto.handler.HttpRequestContext;
import com.universal.crypto.handler.HttpResponseContext;
import com.universal.crypto.model.Constants.ActionType;
import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.Constants.TargetType;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleCondition;
import com.universal.crypto.processor.ProcessorFactory;
import com.universal.crypto.processor.ProcessorManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Integration test for the complete HTTP processing pipeline
 */
class HttpInterceptorIntegrationTest {

    private HttpInterceptor interceptor;
    private RuleManager ruleManager;

    @BeforeEach
    void setUp() throws Exception {
        // Initialize components
        RuleConfigStorage storage = new RuleConfigStorage();
        ruleManager = new RuleManager(storage);
        RuleMatchEngine matchEngine = new RuleMatchEngine();
        ProcessorManager processorManager = ProcessorFactory.createTestProcessorManager();

        interceptor = new HttpInterceptor(ruleManager, matchEngine, processorManager);
    }

    @Test
    void testRequestProcessingWithFieldReplacement() throws Exception {
        // Create a rule for field replacement
        ProcessingRule rule = new ProcessingRule("test-field-replace");
        rule.setName("Test Field Replacement");
        rule.setEnabled(true);
        rule.setPriority(1);

        // Rule condition: match specific host and POST method
        RuleCondition condition = new RuleCondition();
        condition.addHost("api.example.com");
        condition.addMethod("POST");
        rule.setCondition(condition);

        // Action: replace userId field
        ProcessingAction action = new ProcessingAction(ActionType.REPLACE, TargetType.FIELD, "field");
        action.setEnabled(true);
        action.setConfig(ConfigKey.OPERATION, ActionType.REPLACE);
        action.setConfig(ConfigKey.FIELD_PATH, "$.userId");
        action.setConfig(ConfigKey.FROM, "auto");
        action.setConfig(ConfigKey.TO, "admin");
        rule.addRequestAction(action);

        // Add rule to manager
        ruleManager.addRule(rule);

        // Create request context
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        HttpRequestContext requestContext = HttpRequestContext.builder()
                .method("POST")
                .url(new URL("https://api.example.com/users"))
                .headers(headers)
                .body("{\"userId\": \"user123\", \"name\": \"test\"}")
                .toolSource("PROXY")
                .build();

        // Process request
        HttpRequestContext result = interceptor.processRequest(requestContext);

        // Verify field was replaced
        assertFalse(result.hasError());
        assertTrue(result.getBody().contains("\"userId\":\"admin\""));
        assertFalse(result.getBody().contains("\"userId\":\"user123\""));
        assertTrue(result.getBody().contains("\"name\":\"test\""));
    }



    @Test
    void testResponseProcessingWithDecryption() throws Exception {
        // Create a rule for decryption
        ProcessingRule rule = new ProcessingRule("test-decrypt");
        rule.setName("Test Decryption");
        rule.setEnabled(true);
        rule.setPriority(1);

        // Rule condition: match specific host
        RuleCondition condition = new RuleCondition();
        condition.addHost("api.example.com");
        rule.setCondition(condition);

        // Action: decrypt response body
        ProcessingAction action = new ProcessingAction(ActionType.DECRYPT, TargetType.BODY, "crypto");
        action.setEnabled(true);
        action.setConfig(ConfigKey.ALGORITHM, "aes-gcm");
        action.setConfig(ConfigKey.KEY_SOURCE, "static");
        action.setConfig(ConfigKey.KEY_VALUE, "test-key");
        action.setConfig(ConfigKey.EXECUTION_PHASE, "response-send");
        rule.addResponseAction(action);

        // Add rule to manager
        ruleManager.addRule(rule);

        // Create response context with encrypted content
        HttpResponseContext responseContext = HttpResponseContext.builder()
                .method("GET")
                .url(new URL("https://api.example.com/data"))
                .body("encrypted_testdata")
                .statusCode(200)
                .toolSource("PROXY")
                .build();

        // Process response
        HttpResponseContext result = interceptor.processResponse(responseContext);

        // Verify decryption succeeded
        assertFalse(result.hasError());
        assertEquals("testdata", result.getBody()); // MockApiClient removes "encrypted_" prefix
    }

    @Test
    void testNoMatchingRules() throws Exception {
        // Create a rule that won't match
        ProcessingRule rule = new ProcessingRule("no-match");
        rule.setName("No Match Rule");
        rule.setEnabled(true);
        rule.setPriority(1);

        // Rule condition: match different host
        RuleCondition condition = new RuleCondition();
        condition.addHost("different.com");
        rule.setCondition(condition);

        // Action doesn't matter since rule won't match
        // Action doesn't matter since rule won't match
        ProcessingAction action = new ProcessingAction(ActionType.ADD, TargetType.HEADER, "X-Test");
        action.setEnabled(true);
        action.setConfig(ConfigKey.KEY_VALUE, "Should not see this");
        rule.addRequestAction(action);

        // Add rule to manager
        ruleManager.addRule(rule);

        // Create request context
        HttpRequestContext requestContext = HttpRequestContext.builder()
                .method("GET")
                .url(new URL("https://example.com/test"))
                .body("original content")
                .toolSource("PROXY")
                .build();

        // Process request
        HttpRequestContext result = interceptor.processRequest(requestContext);

        // Verify no processing occurred
        assertFalse(result.hasError());
        assertEquals("original content", result.getBody());
        assertEquals(requestContext.getMethod(), result.getMethod());
        assertEquals(requestContext.getUrl(), result.getUrl());
    }

    @Test
    void testSignatureCanGenerateHeadersBeforeSigning() throws Exception {
        ProcessingRule rule = new ProcessingRule("test-sign-headers");
        rule.setName("Test Signature Headers");
        rule.setEnabled(true);
        rule.setPriority(1);

        RuleCondition condition = new RuleCondition();
        condition.addHost("api.example.test");
        rule.setCondition(condition);

        ProcessingAction action = new ProcessingAction(ActionType.SIGN, TargetType.HEADER, "Sign", "signature");
        action.setEnabled(true);
        action.setConfig(ConfigKey.CRYPTO_PROVIDER, "internal");
        action.setConfig(ConfigKey.ALGORITHM, "SHA-256");
        action.setConfig(ConfigKey.KEY_SOURCE, "none");
        action.setConfig(ConfigKey.CIPHER_FORMAT, "hex");
        action.setConfig(ConfigKey.HASH_KEY_PLACEMENT, "none");
        action.setConfig(ConfigKey.SIGNATURE_HEX_CASE, "upper");
        action.setConfig(ConfigKey.SIGN_CONTENT, "custom");
        action.setConfig(ConfigKey.CUSTOM_SIGN_TEMPLATE,
                "secret${header.Timestamp}${header.X-Request-Id}${stablejson:payload}");
        Map<String, String> headerTemplates = new LinkedHashMap<>();
        headerTemplates.put("Timestamp", "${timestamp}");
        headerTemplates.put("X-Request-Id", "fixed-trace");
        action.setConfig(ConfigKey.HEADER_TEMPLATES, headerTemplates);
        rule.addRequestAction(action);
        ruleManager.addRule(rule);

        HttpRequestContext requestContext = HttpRequestContext.builder()
                .method("GET")
                .url(new URL("https://api.example.test/api/test"))
                .headers(new HashMap<>())
                .body("")
                .toolSource("PROXY")
                .build();

        HttpRequestContext result = interceptor.processRequest(requestContext);

        assertFalse(result.hasError());
        assertNotNull(result.getHeaderIgnoreCase("Timestamp"));
        assertEquals("fixed-trace", result.getHeaderIgnoreCase("X-Request-Id"));
        String signedContent = "secret" + result.getHeaderIgnoreCase("Timestamp") + "fixed-trace{}";
        assertEquals(sha256Upper(signedContent), result.getHeaderIgnoreCase("Sign"));
    }

    @Test
    void testDisabledRule() throws Exception {
        // Create a disabled rule
        ProcessingRule rule = new ProcessingRule("disabled-rule");
        rule.setName("Disabled Rule");
        rule.setEnabled(false); // Disabled
        rule.setPriority(1);

        // Rule condition: match any request
        RuleCondition condition = new RuleCondition();
        rule.setCondition(condition);

        // Action
        // Action
        ProcessingAction action = new ProcessingAction(ActionType.ADD, TargetType.HEADER, "X-Test");
        action.setEnabled(true);
        action.setConfig(ConfigKey.KEY_VALUE, "Should not process");
        rule.addRequestAction(action);

        // Add rule to manager
        ruleManager.addRule(rule);

        // Create request context
        HttpRequestContext requestContext = HttpRequestContext.builder()
                .method("GET")
                .url(new URL("https://example.com/test"))
                .body("original content")
                .toolSource("PROXY")
                .build();

        // Process request
        HttpRequestContext result = interceptor.processRequest(requestContext);

        // Verify no processing occurred
        assertFalse(result.hasError());
        assertEquals("original content", result.getBody());
    }

    @Test
    void testStatistics() {
        // Test statistics reporting
        HttpInterceptor.ProcessingStats stats = interceptor.getStats();

        assertNotNull(stats);
        assertTrue(stats.getTotalRules() >= 0);
        assertTrue(stats.getEnabledRules() >= 0);
        assertTrue(stats.getProcessors() > 0);
        assertTrue(stats.getEnabledRules() <= stats.getTotalRules());
    }

    private static String sha256Upper(String content) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(content.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
