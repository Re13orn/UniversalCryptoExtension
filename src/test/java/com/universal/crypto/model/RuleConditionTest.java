package com.universal.crypto.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

class RuleConditionTest {

    private RuleCondition condition;

    @BeforeEach
    void setUp() {
        condition = new RuleCondition();
    }

    @Test
    void testDefaultConstructor() {
        RuleCondition newCondition = new RuleCondition();
        assertNotNull(newCondition.getHosts());
        assertNotNull(newCondition.getPaths());
        assertNotNull(newCondition.getMethods());
        assertNotNull(newCondition.getHeaders());
        assertTrue(newCondition.getHosts().isEmpty());
        assertTrue(newCondition.getPaths().isEmpty());
        assertTrue(newCondition.getMethods().isEmpty());
        assertTrue(newCondition.getHeaders().isEmpty());
    }

    @Test
    void testHostsManagement() {
        assertTrue(condition.getHosts().isEmpty());

        condition.addHost("example.com");
        assertEquals(1, condition.getHosts().size());
        assertTrue(condition.getHosts().contains("example.com"));

        condition.addHost("*.api.example.com");
        assertEquals(2, condition.getHosts().size());

        condition.setHosts(Arrays.asList("test.com", "demo.com"));
        assertEquals(2, condition.getHosts().size());
        assertTrue(condition.getHosts().contains("test.com"));
        assertTrue(condition.getHosts().contains("demo.com"));
        assertFalse(condition.getHosts().contains("example.com"));
    }

    @Test
    void testPathsManagement() {
        assertTrue(condition.getPaths().isEmpty());

        condition.addPath("/api/users");
        assertEquals(1, condition.getPaths().size());
        assertTrue(condition.getPaths().contains("/api/users"));

        condition.addPath("/api/orders/*");
        assertEquals(2, condition.getPaths().size());

        condition.setPaths(Arrays.asList("/test", "/demo"));
        assertEquals(2, condition.getPaths().size());
        assertTrue(condition.getPaths().contains("/test"));
        assertTrue(condition.getPaths().contains("/demo"));
    }

    @Test
    void testMethodsManagement() {
        assertTrue(condition.getMethods().isEmpty());

        condition.addMethod("POST");
        assertEquals(1, condition.getMethods().size());
        assertTrue(condition.getMethods().contains("POST"));

        condition.addMethod("GET");
        assertEquals(2, condition.getMethods().size());

        condition.setMethods(Arrays.asList("PUT", "DELETE"));
        assertEquals(2, condition.getMethods().size());
        assertTrue(condition.getMethods().contains("PUT"));
        assertTrue(condition.getMethods().contains("DELETE"));
        assertFalse(condition.getMethods().contains("POST"));
    }

    @Test
    void testHeadersManagement() {
        assertTrue(condition.getHeaders().isEmpty());

        condition.addHeader("Content-Type", "application/json");
        assertEquals(1, condition.getHeaders().size());
        assertEquals("application/json", condition.getHeaders().get("Content-Type"));

        condition.addHeader("Authorization", "Bearer token");
        assertEquals(2, condition.getHeaders().size());

        Map<String, String> newHeaders = new HashMap<>();
        newHeaders.put("X-Custom", "value");
        newHeaders.put("Accept", "application/xml");

        condition.setHeaders(newHeaders);
        assertEquals(2, condition.getHeaders().size());
        assertEquals("value", condition.getHeaders().get("X-Custom"));
        assertEquals("application/xml", condition.getHeaders().get("Accept"));
        assertNull(condition.getHeaders().get("Content-Type"));
    }

    @Test
    void testContentPattern() {
        assertNull(condition.getContentPattern());

        condition.setContentPattern("encrypted_data");
        assertEquals("encrypted_data", condition.getContentPattern());

        condition.setContentPattern(null);
        assertNull(condition.getContentPattern());
    }

    @Test
    void testContentType() {
        assertNull(condition.getContentType());

        condition.setContentType("application/json");
        assertEquals("application/json", condition.getContentType());

        condition.setContentType("");
        assertEquals("", condition.getContentType());
    }

    @Test
    void testToolSource() {
        assertNull(condition.getToolSource());

        condition.setToolSource("PROXY");
        assertEquals("PROXY", condition.getToolSource());

        condition.setToolSource("ANY");
        assertEquals("ANY", condition.getToolSource());
    }

    @Test
    void testHasConditions() {
        assertFalse(condition.hasConditions());

        condition.addHost("example.com");
        assertTrue(condition.hasConditions());

        condition.setHosts(Arrays.asList());
        condition.addPath("/api");
        assertTrue(condition.hasConditions());

        condition.setPaths(Arrays.asList());
        condition.addMethod("POST");
        assertTrue(condition.hasConditions());

        condition.setMethods(Arrays.asList());
        condition.addHeader("Content-Type", "application/json");
        assertTrue(condition.hasConditions());

        condition.setHeaders(new HashMap<>());
        condition.setContentPattern("pattern");
        assertTrue(condition.hasConditions());

        condition.setContentPattern(null);
        condition.setContentType("application/json");
        assertTrue(condition.hasConditions());

        condition.setContentType(null);
        condition.setToolSource("PROXY");
        assertTrue(condition.hasConditions());

        condition.setToolSource(null);
        assertFalse(condition.hasConditions());
    }

    @Test
    void testClone() {
        condition.addHost("example.com");
        condition.addPath("/api");
        condition.addMethod("POST");
        condition.addHeader("Content-Type", "application/json");
        condition.setContentPattern("test_pattern");
        condition.setContentType("application/json");
        condition.setToolSource("PROXY");

        RuleCondition cloned = condition.clone();

        assertEquals(condition.getHosts(), cloned.getHosts());
        assertEquals(condition.getPaths(), cloned.getPaths());
        assertEquals(condition.getMethods(), cloned.getMethods());
        assertEquals(condition.getHeaders(), cloned.getHeaders());
        assertEquals(condition.getContentPattern(), cloned.getContentPattern());
        assertEquals(condition.getContentType(), cloned.getContentType());
        assertEquals(condition.getToolSource(), cloned.getToolSource());

        // Verify deep copy
        assertNotSame(condition, cloned);
        assertNotSame(condition.getHosts(), cloned.getHosts());
        assertNotSame(condition.getPaths(), cloned.getPaths());
        assertNotSame(condition.getMethods(), cloned.getMethods());
        assertNotSame(condition.getHeaders(), cloned.getHeaders());
    }

    @Test
    void testEquals() {
        RuleCondition condition1 = new RuleCondition();
        condition1.addHost("example.com");
        condition1.addMethod("POST");

        RuleCondition condition2 = new RuleCondition();
        condition2.addHost("example.com");
        condition2.addMethod("POST");

        assertEquals(condition1, condition2);
        assertEquals(condition1.hashCode(), condition2.hashCode());

        condition2.addPath("/api");
        assertNotEquals(condition1, condition2);
    }

    @Test
    void testToString() {
        condition.addHost("example.com");
        condition.addMethod("POST");
        condition.setContentType("application/json");

        String str = condition.toString();
        assertTrue(str.contains("example.com"));
        assertTrue(str.contains("POST"));
        assertTrue(str.contains("application/json"));
    }

    @Test
    void testNullAndEmptyHandling() {
        // Test null collections
        condition.setHosts(null);
        assertNotNull(condition.getHosts());
        assertTrue(condition.getHosts().isEmpty());

        condition.setPaths(null);
        assertNotNull(condition.getPaths());
        assertTrue(condition.getPaths().isEmpty());

        condition.setMethods(null);
        assertNotNull(condition.getMethods());
        assertTrue(condition.getMethods().isEmpty());

        condition.setHeaders(null);
        assertNotNull(condition.getHeaders());
        assertTrue(condition.getHeaders().isEmpty());

        // Test empty string conditions
        condition.setContentPattern("");
        assertEquals("", condition.getContentPattern());

        condition.setContentType("");
        assertEquals("", condition.getContentType());

        condition.setToolSource("");
        assertEquals("", condition.getToolSource());
    }
}