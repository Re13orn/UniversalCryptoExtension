package com.universal.crypto.engine;

import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleCondition;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

class DefaultRuleFactoryTest {

    @Test
    void testGetAllDefaultRules() {
        List<ProcessingRule> allRules = DefaultRuleFactory.getAllDefaultRules();

        assertNotNull(allRules);
        assertEquals(10, allRules.size());

        // Verify no duplicate IDs
        long uniqueIds = allRules.stream().map(ProcessingRule::getId).distinct().count();
        assertEquals(10, uniqueIds);

        assertTrue(allRules.stream().noneMatch(ProcessingRule::isEnabled),
                "Preset rules must be disabled by default so they cannot modify traffic until the user enables them.");
    }

    @Test
    void testGetEssentialDefaultRules() {
        List<ProcessingRule> essentialRules = DefaultRuleFactory.getEssentialDefaultRules();

        assertNotNull(essentialRules);
        assertTrue(essentialRules.isEmpty());
    }

    @Test
    void testValidateRuleWithValidRule() {
        ProcessingRule validRule = DefaultRuleFactory.getAllDefaultRules().get(0);
        assertTrue(DefaultRuleFactory.validateRule(validRule));
    }

    @Test
    void testValidateRuleWithNull() {
        assertFalse(DefaultRuleFactory.validateRule(null));
    }

    @Test
    void testValidateRuleWithMissingId() {
        ProcessingRule rule = new ProcessingRule();
        rule.setName("Test Rule");
        RuleCondition condition = new RuleCondition();
        condition.addHost("example.com");
        rule.setCondition(condition);
        ProcessingAction action = new ProcessingAction("decrypt", "body", "crypto");
        rule.addRequestAction(action);

        assertFalse(DefaultRuleFactory.validateRule(rule));
    }

    @Test
    void testValidateRuleWithEmptyId() {
        ProcessingRule rule = new ProcessingRule("");
        rule.setName("Test Rule");
        RuleCondition condition = new RuleCondition();
        condition.addHost("example.com");
        rule.setCondition(condition);
        ProcessingAction action = new ProcessingAction("decrypt", "body", "crypto");
        rule.addRequestAction(action);

        assertFalse(DefaultRuleFactory.validateRule(rule));
    }

    @Test
    void testValidateRuleWithMissingName() {
        ProcessingRule rule = new ProcessingRule("test-rule");
        RuleCondition condition = new RuleCondition();
        condition.addHost("example.com");
        rule.setCondition(condition);
        ProcessingAction action = new ProcessingAction("decrypt", "body", "crypto");
        rule.addRequestAction(action);

        assertFalse(DefaultRuleFactory.validateRule(rule));
    }

    @Test
    void testValidateRuleWithEmptyName() {
        ProcessingRule rule = new ProcessingRule("test-rule");
        rule.setName("");
        RuleCondition condition = new RuleCondition();
        condition.addHost("example.com");
        rule.setCondition(condition);
        ProcessingAction action = new ProcessingAction("decrypt", "body", "crypto");
        rule.addRequestAction(action);

        assertFalse(DefaultRuleFactory.validateRule(rule));
    }

    @Test
    void testValidateRuleWithMissingCondition() {
        ProcessingRule rule = new ProcessingRule("test-rule");
        rule.setName("Test Rule");
        ProcessingAction action = new ProcessingAction("decrypt", "body", "crypto");
        rule.addRequestAction(action);

        assertFalse(DefaultRuleFactory.validateRule(rule));
    }

    @Test
    void testValidateRuleWithNoActions() {
        ProcessingRule rule = new ProcessingRule("test-rule");
        rule.setName("Test Rule");
        RuleCondition condition = new RuleCondition();
        condition.addHost("example.com");
        rule.setCondition(condition);

        assertFalse(DefaultRuleFactory.validateRule(rule));
    }

    @Test
    void testValidateRuleWithInvalidRequestAction() {
        ProcessingRule rule = new ProcessingRule("test-rule");
        rule.setName("Test Rule");
        RuleCondition condition = new RuleCondition();
        condition.addHost("example.com");
        rule.setCondition(condition);

        ProcessingAction invalidAction = new ProcessingAction();
        // Missing required fields - actionType, targetType, processor
        rule.addRequestAction(invalidAction);

        assertFalse(DefaultRuleFactory.validateRule(rule));
    }

    @Test
    void testValidateRuleWithInvalidResponseAction() {
        ProcessingRule rule = new ProcessingRule("test-rule");
        rule.setName("Test Rule");
        RuleCondition condition = new RuleCondition();
        condition.addHost("example.com");
        rule.setCondition(condition);

        ProcessingAction validAction = new ProcessingAction("decrypt", "body", "crypto");
        rule.addRequestAction(validAction);

        ProcessingAction invalidAction = new ProcessingAction();
        // Missing required fields
        rule.addResponseAction(invalidAction);

        assertFalse(DefaultRuleFactory.validateRule(rule));
    }

    @Test
    void testValidateRuleWithOnlyRequestActions() {
        ProcessingRule rule = new ProcessingRule("test-rule");
        rule.setName("Test Rule");
        RuleCondition condition = new RuleCondition();
        condition.addHost("example.com");
        rule.setCondition(condition);

        ProcessingAction action = new ProcessingAction("decrypt", "body", "crypto");
        rule.addRequestAction(action);

        assertTrue(DefaultRuleFactory.validateRule(rule));
    }

    @Test
    void testValidateRuleWithOnlyResponseActions() {
        ProcessingRule rule = new ProcessingRule("test-rule");
        rule.setName("Test Rule");
        RuleCondition condition = new RuleCondition();
        condition.addHost("example.com");
        rule.setCondition(condition);

        ProcessingAction action = new ProcessingAction("decrypt", "body", "crypto");
        rule.addResponseAction(action);

        assertTrue(DefaultRuleFactory.validateRule(rule));
    }



    @Test
    void testAllDefaultRulesAreValid() {
        List<ProcessingRule> allRules = DefaultRuleFactory.getAllDefaultRules();

        for (ProcessingRule rule : allRules) {
            assertTrue(DefaultRuleFactory.validateRule(rule),
                      "Rule " + rule.getId() + " should be valid");
        }
    }

    @Test
    void testEssentialDefaultRulesAreValid() {
        List<ProcessingRule> essentialRules = DefaultRuleFactory.getEssentialDefaultRules();

        for (ProcessingRule rule : essentialRules) {
            assertTrue(DefaultRuleFactory.validateRule(rule),
                      "Essential rule " + rule.getId() + " should be valid");
        }
    }

    @Test
    void testDefaultRulesHaveUniqueIds() {
        List<ProcessingRule> allRules = DefaultRuleFactory.getAllDefaultRules();
        long uniqueIdCount = allRules.stream()
                .map(ProcessingRule::getId)
                .distinct()
                .count();

        assertEquals(allRules.size(), uniqueIdCount,
                    "All default rules should have unique IDs");
    }

    @Test
    void testDefaultRulesHaveUniqueNames() {
        List<ProcessingRule> allRules = DefaultRuleFactory.getAllDefaultRules();
        long uniqueNameCount = allRules.stream()
                .map(ProcessingRule::getName)
                .distinct()
                .count();

        assertEquals(allRules.size(), uniqueNameCount,
                    "All default rules should have unique names");
    }
}
