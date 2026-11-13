package com.universal.crypto.model;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;
class RuleImportSafetyTest {
    private ProcessingRule rule(String code) {
        ProcessingRule rule = new ProcessingRule("import-test"); rule.setEnabled(true);
        ProcessingAction action = new ProcessingAction("process", "body", "script");
        action.setConfig(Constants.ConfigKey.SCRIPT_CODE, code);
        rule.addRequestAction(action); return rule;
    }
    @Test void legacyAndEnvelopeImportsAreDisabled() {
        ProcessingRule rule = rule("return content;");
        assertFalse(RuleSerializer.importRules(RuleSerializer.toJson(List.of(rule))).get(0).isEnabled());
        assertFalse(RuleSerializer.importRules(RuleSerializer.exportRules(List.of(rule))).get(0).isEnabled());
        assertTrue(RuleSerializer.fromJsonList(RuleSerializer.toJson(List.of(rule))).get(0).isEnabled());
    }
    @Test void rejectsInvalidSyntaxEnumsAndVersion() {
        assertThrows(RuntimeException.class, () -> RuleSerializer.importRules(RuleSerializer.toJson(List.of(rule("return {;")))));
        ProcessingRule bad = rule("return content;");
        bad.getRequestActions().get(0).setConfig(Constants.ConfigKey.EXECUTION_PHASE, "sned");
        assertThrows(RuntimeException.class, () -> RuleSerializer.importRules(RuleSerializer.toJson(List.of(bad))));
        assertThrows(RuntimeException.class, () -> RuleSerializer.importRules("{\"schemaVersion\":999,\"rules\":[]}"));
    }
}
