package com.universal.crypto.model;

import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

public class RuleImportExportTest {

    @Test
    public void testRuleSerialization() {
        // Create a complex rule
        ProcessingRule rule = new ProcessingRule("test-rule", "Test Rule", true, 100);
        rule.setCategory("test");
        
        // Add action with variable config
        ProcessingAction action = new ProcessingAction();
        action.setActionType(Constants.ActionType.ENCRYPT);
        action.setTargetType(Constants.TargetType.VARIABLE); // New feature
        action.setTargetName("myVar");
        action.setProcessor(Constants.ProcessorType.CRYPTO);
        action.setConfig(Constants.ConfigKey.INPUT_SOURCE, Constants.InputSource.VARIABLE); // New feature
        action.setConfig(Constants.ConfigKey.INPUT_NAME, "inputVar");
        
        rule.addRequestAction(action);
        
        // Serialize
        String json = RuleSerializer.toJson(rule);
        assertNotNull(json);
        assertTrue(json.contains("myVar"));
        assertTrue(json.contains("inputVar"));
        
        // Deserialize
        ProcessingRule restored = RuleSerializer.fromJson(json);
        assertNotNull(restored);
        assertEquals(rule.getId(), restored.getId());
        assertEquals(rule.getName(), restored.getName());
        assertEquals(1, restored.getRequestActions().size());
        
        ProcessingAction restoredAction = restored.getRequestActions().get(0);
        assertEquals(Constants.TargetType.VARIABLE, restoredAction.getTargetType());
        assertEquals("myVar", restoredAction.getTargetName());
        assertEquals(Constants.InputSource.VARIABLE, restoredAction.getConfigString(Constants.ConfigKey.INPUT_SOURCE));
    }
    
    @Test
    public void testRuleListSerialization() {
        List<ProcessingRule> rules = new ArrayList<>();
        rules.add(new ProcessingRule("rule1", "Rule 1", true, 1));
        rules.add(new ProcessingRule("rule2", "Rule 2", false, 2));
        
        String json = RuleSerializer.toJson(rules);
        assertNotNull(json);
        
        List<ProcessingRule> restored = RuleSerializer.fromJsonList(json);
        assertNotNull(restored);
        assertEquals(2, restored.size());
        assertEquals("rule1", restored.get(0).getId());
        assertEquals("rule2", restored.get(1).getId());
    }
}
