package com.universal.crypto.engine;

import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleCondition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class RuleMatchEngineTest {

    private RuleMatchEngine engine;
    private ProcessingRule rule;
    private RuleCondition condition;

    @BeforeEach
    void setUp() {
        engine = new RuleMatchEngine();
        rule = new ProcessingRule("test-rule");
        rule.setName("Test Rule");
        rule.setEnabled(true);
        condition = new RuleCondition();
        rule.setCondition(condition);
    }

    @Test
    void testMatchesWithNullRule() {
        RuleMatchEngine.MatchContext context = createTestContext();
        assertFalse(engine.matches(null, context));
    }

    @Test
    void testMatchesWithDisabledRule() {
        rule.setEnabled(false);
        RuleMatchEngine.MatchContext context = createTestContext();
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesWithNullContext() {
        assertFalse(engine.matches(rule, null));
    }

    @Test
    void testMatchesWithNullCondition() {
        rule.setCondition(null);
        RuleMatchEngine.MatchContext context = createTestContext();
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesEmptyCondition() {
        // Empty condition should match everything
        RuleMatchEngine.MatchContext context = createTestContext();
        assertTrue(engine.matches(rule, context));
    }

    @Test
    void testMatchesHost() throws Exception {
        condition.addHost("example.com");

        // Exact match
        RuleMatchEngine.MatchContext context = createContext("GET", "https://example.com/path", null, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        // Different host
        context = createContext("GET", "https://other.example.test/path", null, null, "PROXY");
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesHostWildcard() throws Exception {
        condition.addHost("*.example.com");

        // Wildcard match
        RuleMatchEngine.MatchContext context = createContext("GET", "https://api.example.com/path", null, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        // Subdomain match
        context = createContext("GET", "https://test.api.example.com/path", null, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        // No match
        context = createContext("GET", "https://example.org/path", null, null, "PROXY");
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesPath() throws Exception {
        condition.addPath("/api/*");

        // Wildcard match
        RuleMatchEngine.MatchContext context = createContext("GET", "https://example.com/api/users", null, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        // Nested path match
        context = createContext("GET", "https://example.com/api/v1/users", null, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        // No match
        context = createContext("GET", "https://example.com/other/path", null, null, "PROXY");
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesMethod() throws Exception {
        condition.addMethod("POST");

        // Exact match
        RuleMatchEngine.MatchContext context = createContext("POST", "https://example.com/path", null, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        // Case insensitive
        context = createContext("post", "https://example.com/path", null, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        // No match
        context = createContext("GET", "https://example.com/path", null, null, "PROXY");
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesMultipleMethods() throws Exception {
        condition.setMethods(Arrays.asList("POST", "PUT"));

        RuleMatchEngine.MatchContext context = createContext("POST", "https://example.com/path", null, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        context = createContext("PUT", "https://example.com/path", null, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        context = createContext("GET", "https://example.com/path", null, null, "PROXY");
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesHeaders() throws Exception {
        condition.addHeader("Content-Type", "application/json");

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        RuleMatchEngine.MatchContext context = createContext("POST", "https://example.com/path", headers, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        // Wrong header value
        headers.put("Content-Type", "application/xml");
        context = createContext("POST", "https://example.com/path", headers, null, "PROXY");
        assertFalse(engine.matches(rule, context));

        // Missing header
        headers.clear();
        context = createContext("POST", "https://example.com/path", headers, null, "PROXY");
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesHeadersWildcard() throws Exception {
        condition.addHeader("Authorization", "Bearer *");

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer abc123");

        RuleMatchEngine.MatchContext context = createContext("POST", "https://example.com/path", headers, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        headers.put("Authorization", "Basic xyz789");
        context = createContext("POST", "https://example.com/path", headers, null, "PROXY");
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesContentType() throws Exception {
        condition.setContentType("application/json");

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        RuleMatchEngine.MatchContext context = createContext("POST", "https://example.com/path", headers, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        // With charset parameter
        headers.put("Content-Type", "application/json; charset=utf-8");
        context = createContext("POST", "https://example.com/path", headers, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        // Wrong content type
        headers.put("Content-Type", "application/xml");
        context = createContext("POST", "https://example.com/path", headers, null, "PROXY");
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesContentPattern() throws Exception {
        condition.setContentPattern("encrypted_data");

        RuleMatchEngine.MatchContext context = createContext("POST", "https://example.com/path", null,
                "{\"encrypted_data\": \"abc123\"}", "PROXY");
        assertTrue(engine.matches(rule, context));

        context = createContext("POST", "https://example.com/path", null,
                "{\"regular_data\": \"abc123\"}", "PROXY");
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesContentPatternRegex() throws Exception {
        condition.setContentPattern("\"data\":\\s*\"[^\"]+\"");

        RuleMatchEngine.MatchContext context = createContext("POST", "https://example.com/path", null,
                "{\"data\": \"some_value\"}", "PROXY");
        assertTrue(engine.matches(rule, context));

        context = createContext("POST", "https://example.com/path", null,
                "{\"data\":\"another_value\"}", "PROXY");
        assertTrue(engine.matches(rule, context));

        context = createContext("POST", "https://example.com/path", null,
                "{\"other\": \"value\"}", "PROXY");
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesToolSource() throws Exception {
        condition.setToolSource("PROXY");

        RuleMatchEngine.MatchContext context = createContext("GET", "https://example.com/path", null, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        context = createContext("GET", "https://example.com/path", null, null, "SCANNER");
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testMatchesToolSourceAny() throws Exception {
        condition.setToolSource("ANY");

        RuleMatchEngine.MatchContext context = createContext("GET", "https://example.com/path", null, null, "PROXY");
        assertTrue(engine.matches(rule, context));

        context = createContext("GET", "https://example.com/path", null, null, "SCANNER");
        assertTrue(engine.matches(rule, context));

        context = createContext("GET", "https://example.com/path", null, null, "INTRUDER");
        assertTrue(engine.matches(rule, context));
    }

    @Test
    void testMatchesComplexCondition() throws Exception {
        // Complex condition with multiple criteria
        condition.addHost("*.api.example.com");
        condition.addPath("/v1/*");
        condition.setMethods(Arrays.asList("POST", "PUT"));
        condition.addHeader("Content-Type", "application/json");
        condition.setContentPattern("\"action\":");
        condition.setToolSource("PROXY");

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        // All conditions match
        RuleMatchEngine.MatchContext context = createContext("POST", "https://user.api.example.com/v1/users",
                headers, "{\"action\": \"create\"}", "PROXY");
        assertTrue(engine.matches(rule, context));

        // Wrong host
        context = createContext("POST", "https://other.example.com/v1/users",
                headers, "{\"action\": \"create\"}", "PROXY");
        assertFalse(engine.matches(rule, context));

        // Wrong method
        context = createContext("GET", "https://user.api.example.com/v1/users",
                headers, "{\"action\": \"create\"}", "PROXY");
        assertFalse(engine.matches(rule, context));
    }

    @Test
    void testFindMatchingRules() throws Exception {
        ProcessingRule rule1 = new ProcessingRule("rule-1");
        rule1.setEnabled(true);
        RuleCondition condition1 = new RuleCondition();
        condition1.addHost("example.com");
        rule1.setCondition(condition1);

        ProcessingRule rule2 = new ProcessingRule("rule-2");
        rule2.setEnabled(true);
        RuleCondition condition2 = new RuleCondition();
        condition2.addMethod("POST");
        rule2.setCondition(condition2);

        ProcessingRule rule3 = new ProcessingRule("rule-3");
        rule3.setEnabled(false); // Disabled
        RuleCondition condition3 = new RuleCondition();
        condition3.addHost("example.com");
        rule3.setCondition(condition3);

        List<ProcessingRule> rules = Arrays.asList(rule1, rule2, rule3);

        RuleMatchEngine.MatchContext context = createContext("POST", "https://example.com/path", null, null, "PROXY");
        List<ProcessingRule> matches = engine.findMatchingRules(rules, context);

        assertEquals(2, matches.size());
        assertTrue(matches.contains(rule1)); // Matches host
        assertTrue(matches.contains(rule2)); // Matches method
        assertFalse(matches.contains(rule3)); // Disabled
    }

    @Test
    void diagnoseExplainsMatchedRuleConditions() throws Exception {
        condition.addHost("*.example.com");
        condition.addPath("/api/*");
        condition.addMethod("GET");

        RuleMatchEngine.MatchContext context = createContext("GET", "https://api.example.com/api/users", null, null, "REPEATER");
        RuleMatchEngine.MatchDiagnostic diagnostic = engine.diagnose(rule, context);

        assertTrue(diagnostic.isMatched());
        assertEquals("test-rule", diagnostic.getRuleId());
        assertEquals("All rule conditions matched", diagnostic.getSummary());
        assertTrue(diagnostic.getChecks().stream()
                .filter(check -> "Host".equals(check.getName()))
                .allMatch(RuleMatchEngine.ConditionDiagnostic::isMatched));
    }

    @Test
    void diagnoseExplainsFailedRuleConditions() throws Exception {
        condition.addHost("api.example.com");
        condition.addPath("/api/*");
        condition.addMethod("POST");

        RuleMatchEngine.MatchContext context = createContext("GET", "https://other.example.com/public", null, null, "REPEATER");
        RuleMatchEngine.MatchDiagnostic diagnostic = engine.diagnose(rule, context);

        assertFalse(diagnostic.isMatched());
        assertTrue(diagnostic.getChecks().stream()
                .anyMatch(check -> "Host".equals(check.getName())
                        && !check.isMatched()
                        && check.getActual().contains("other.example.com")));
        assertTrue(diagnostic.getChecks().stream()
                .anyMatch(check -> "Method".equals(check.getName())
                        && !check.isMatched()
                        && check.getExpected().contains("POST")));
    }

    @Test
    void testCreateRequestContext() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        URL url = new URL("https://example.com/path");

        RuleMatchEngine.MatchContext context = RuleMatchEngine.createRequestContext(
                "POST", url, headers, "{\"data\": \"test\"}", "PROXY");

        assertEquals("POST", context.getMethod());
        assertEquals(url, context.getUrl());
        assertEquals("example.com", context.getHost());
        assertEquals("/path", context.getPath());
        assertEquals(headers, context.getHeaders());
        assertEquals("application/json", context.getContentType());
        assertEquals("{\"data\": \"test\"}", context.getBody());
        assertEquals("PROXY", context.getToolSource());
    }

    @Test
    void testCreateResponseContext() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        URL url = new URL("https://example.com/path");

        RuleMatchEngine.MatchContext context = RuleMatchEngine.createResponseContext(
                "POST", url, headers, "{\"result\": \"success\"}", "PROXY");

        assertEquals("POST", context.getMethod());
        assertEquals(url, context.getUrl());
        assertEquals("example.com", context.getHost());
        assertEquals("/path", context.getPath());
        assertEquals("application/json", context.getContentType());
        assertEquals("{\"result\": \"success\"}", context.getBody());
    }

    private RuleMatchEngine.MatchContext createTestContext() {
        try {
            return createContext("GET", "https://example.com/test", null, null, "PROXY");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private RuleMatchEngine.MatchContext createContext(String method, String urlString,
                                                      Map<String, String> headers,
                                                      String body, String toolSource) throws Exception {
        URL url = new URL(urlString);
        String contentType = headers != null ? headers.get("Content-Type") : null;
        return new RuleMatchEngine.MatchContext(method, url, headers, contentType, body, toolSource);
    }
}
