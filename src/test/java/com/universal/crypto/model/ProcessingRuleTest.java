package com.universal.crypto.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

class ProcessingRuleTest {

    private ProcessingRule rule;
    private RuleCondition condition;
    private ProcessingAction requestAction;
    private ProcessingAction responseAction;

    @BeforeEach
    void setUp() {
        rule = new ProcessingRule();
        condition = new RuleCondition();
        requestAction = new ProcessingAction("decrypt", "body", "crypto");
        responseAction = new ProcessingAction("decrypt", "body", "crypto");
    }

    @Test
    void testDefaultConstructor() {
        ProcessingRule newRule = new ProcessingRule();
        assertTrue(newRule.isEnabled());
        assertEquals(100, newRule.getPriority());
        assertNotNull(newRule.getRequestActions());
        assertNotNull(newRule.getResponseActions());
        assertTrue(newRule.getRequestActions().isEmpty());
        assertTrue(newRule.getResponseActions().isEmpty());
    }

    @Test
    void testConstructorWithId() {
        ProcessingRule newRule = new ProcessingRule("test-rule-1");
        assertEquals("test-rule-1", newRule.getId());
        assertTrue(newRule.isEnabled());
        assertEquals(100, newRule.getPriority());
    }

    @Test
    void testBasicProperties() {
        rule.setId("test-rule");
        rule.setName("Test Rule");
        rule.setDescription("Test Description");
        rule.setEnabled(false);
        rule.setPriority(50);

        assertEquals("test-rule", rule.getId());
        assertEquals("Test Rule", rule.getName());
        assertEquals("Test Description", rule.getDescription());
        assertFalse(rule.isEnabled());
        assertEquals(50, rule.getPriority());
    }

    @Test
    void testConditionManagement() {
        assertNull(rule.getCondition());

        rule.setCondition(condition);
        assertNotNull(rule.getCondition());
        assertEquals(condition, rule.getCondition());
    }

    @Test
    void testRequestActionsManagement() {
        assertFalse(rule.hasRequestActions());
        assertEquals(0, rule.getRequestActionCount());

        rule.addRequestAction(requestAction);
        assertTrue(rule.hasRequestActions());
        assertEquals(1, rule.getRequestActionCount());
        assertTrue(rule.getRequestActions().contains(requestAction));

        rule.removeRequestAction(requestAction);
        assertFalse(rule.hasRequestActions());
        assertEquals(0, rule.getRequestActionCount());
    }

    @Test
    void testResponseActionsManagement() {
        assertFalse(rule.hasResponseActions());
        assertEquals(0, rule.getResponseActionCount());

        rule.addResponseAction(responseAction);
        assertTrue(rule.hasResponseActions());
        assertEquals(1, rule.getResponseActionCount());
        assertTrue(rule.getResponseActions().contains(responseAction));

        rule.removeResponseAction(responseAction);
        assertFalse(rule.hasResponseActions());
        assertEquals(0, rule.getResponseActionCount());
    }

    @Test
    void testSetRequestActions() {
        ProcessingAction action1 = new ProcessingAction("decrypt", "body", "crypto");
        ProcessingAction action2 = new ProcessingAction("sign", "header", "signature");

        rule.setRequestActions(Arrays.asList(action1, action2));
        assertEquals(2, rule.getRequestActionCount());
        assertTrue(rule.getRequestActions().contains(action1));
        assertTrue(rule.getRequestActions().contains(action2));
    }

    @Test
    void testSetResponseActions() {
        ProcessingAction action1 = new ProcessingAction("decrypt", "body", "crypto");
        ProcessingAction action2 = new ProcessingAction("replace", "field", "field");

        rule.setResponseActions(Arrays.asList(action1, action2));
        assertEquals(2, rule.getResponseActionCount());
        assertTrue(rule.getResponseActions().contains(action1));
        assertTrue(rule.getResponseActions().contains(action2));
    }

    @Test
    void testClearActions() {
        rule.addRequestAction(requestAction);
        rule.addResponseAction(responseAction);

        assertTrue(rule.hasRequestActions());
        assertTrue(rule.hasResponseActions());

        rule.clearRequestActions();
        rule.clearResponseActions();

        assertFalse(rule.hasRequestActions());
        assertFalse(rule.hasResponseActions());
    }

    @Test
    void testHasActions() {
        assertFalse(rule.hasActions());

        rule.addRequestAction(requestAction);
        assertTrue(rule.hasActions());

        rule.clearRequestActions();
        rule.addResponseAction(responseAction);
        assertTrue(rule.hasActions());

        rule.clearResponseActions();
        assertFalse(rule.hasActions());
    }

    @Test
    void testClone() {
        rule.setId("original-rule");
        rule.setName("Original Rule");
        rule.setEnabled(false);
        rule.setPriority(25);
        rule.setCondition(condition);
        rule.addRequestAction(requestAction);
        rule.addResponseAction(responseAction);

        ProcessingRule cloned = rule.clone();

        assertEquals(rule.getId(), cloned.getId());
        assertEquals(rule.getName(), cloned.getName());
        assertEquals(rule.isEnabled(), cloned.isEnabled());
        assertEquals(rule.getPriority(), cloned.getPriority());
        assertEquals(rule.getRequestActionCount(), cloned.getRequestActionCount());
        assertEquals(rule.getResponseActionCount(), cloned.getResponseActionCount());

        // Verify deep copy
        assertNotSame(rule, cloned);
        assertNotSame(rule.getRequestActions(), cloned.getRequestActions());
        assertNotSame(rule.getResponseActions(), cloned.getResponseActions());
    }

    @Test
    void testEquals() {
        ProcessingRule rule1 = new ProcessingRule("test-rule");
        rule1.setName("Test Rule");
        rule1.setEnabled(false);

        ProcessingRule rule2 = new ProcessingRule("test-rule");
        rule2.setName("Test Rule");
        rule2.setEnabled(false);

        assertEquals(rule1, rule2);
        assertEquals(rule1.hashCode(), rule2.hashCode());

        rule2.setName("Different Name");
        // Equality is based on rule id only.
        assertEquals(rule1, rule2);
    }

    @Test
    void testToString() {
        rule.setId("test-rule");
        rule.setName("Test Rule");
        rule.setEnabled(false);

        String str = rule.toString();
        assertTrue(str.contains("test-rule"));
        assertTrue(str.contains("Test Rule"));
        assertTrue(str.contains("enabled=false"));
    }
}
