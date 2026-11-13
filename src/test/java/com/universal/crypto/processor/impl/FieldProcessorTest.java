package com.universal.crypto.processor.impl;

import com.universal.crypto.model.Constants.ActionType;
import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.processor.ProcessorResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.net.URL;

class FieldProcessorTest {

    private FieldProcessor processor;
    private ProcessorContext context;

    @BeforeEach
    void setUp() throws Exception {
        processor = new FieldProcessor();
        context = ProcessorContext.forRequest("POST", new URL("https://example.com"), null, "PROXY").build();
    }

    @Test
    void testCanHandle() {
        assertTrue(processor.canHandle(ActionType.REPLACE));
        assertTrue(processor.canHandle(ActionType.ADD));
        assertTrue(processor.canHandle(ActionType.REMOVE));
        assertFalse(processor.canHandle(ActionType.ENCRYPT));
    }

    @Test
    void testGetProcessorType() {
        assertEquals("field", processor.getProcessorType());
    }

    @Test
    void testValidateConfiguration() {
        ProcessingAction validAction = new ProcessingAction(ActionType.REPLACE, "field", "field");
        validAction.setConfig(ConfigKey.OPERATION, "replace");
        validAction.setConfig(ConfigKey.FIELD_PATH, "$.userId");
        validAction.setConfig(ConfigKey.TO, "newValue");

        assertTrue(processor.validateConfiguration(validAction));

        ProcessingAction invalidAction = new ProcessingAction(ActionType.REPLACE, "field", "field");
        assertFalse(processor.validateConfiguration(invalidAction));
    }

    @Test
    void testReplaceField() throws Exception {
        String jsonContent = "{\"userId\": \"old123\", \"name\": \"test\"}";

        ProcessingAction action = new ProcessingAction(ActionType.REPLACE, "field", "field");
        action.setConfig(ConfigKey.OPERATION, "replace");
        action.setConfig(ConfigKey.FIELD_PATH, "$.userId");
        action.setConfig(ConfigKey.FROM, "old123");
        action.setConfig(ConfigKey.TO, "new456");

        ProcessorResult result = processor.process(action, jsonContent, context);

        assertTrue(result.isSuccess());
        assertTrue(result.getProcessedContent().contains("new456"));
        assertFalse(result.getProcessedContent().contains("old123"));
        assertEquals("replace", result.getMetadata("operation"));
        assertEquals("old123", result.getMetadata("oldValue"));
        assertEquals("new456", result.getMetadata("newValue"));
    }

    @Test
    void testReplaceFieldAuto() throws Exception {
        String jsonContent = "{\"userId\": \"old123\", \"name\": \"test\"}";

        ProcessingAction action = new ProcessingAction(ActionType.REPLACE, "field", "field");
        action.setConfig(ConfigKey.OPERATION, "replace");
        action.setConfig(ConfigKey.FIELD_PATH, "$.userId");
        action.setConfig(ConfigKey.FROM, "auto");
        action.setConfig(ConfigKey.TO, "new456");

        ProcessorResult result = processor.process(action, jsonContent, context);

        assertTrue(result.isSuccess());
        assertTrue(result.getProcessedContent().contains("new456"));
    }

    @Test
    void testAddField() throws Exception {
        String jsonContent = "{\"name\": \"test\"}";

        ProcessingAction action = new ProcessingAction(ActionType.ADD, "field", "field");
        action.setConfig(ConfigKey.OPERATION, "add");
        action.setConfig(ConfigKey.FIELD_PATH, "$.userId");
        action.setConfig(ConfigKey.TO, "new123");

        ProcessorResult result = processor.process(action, jsonContent, context);

        assertTrue(result.isSuccess());
        assertTrue(result.getProcessedContent().contains("new123"));
        assertTrue(result.getProcessedContent().contains("userId"));
        assertEquals("add", result.getMetadata("operation"));
        assertEquals("new123", result.getMetadata("newValue"));
    }

    @Test
    void testRemoveField() throws Exception {
        String jsonContent = "{\"userId\": \"123\", \"name\": \"test\"}";

        ProcessingAction action = new ProcessingAction(ActionType.REMOVE, "field", "field");
        action.setConfig(ConfigKey.OPERATION, "remove");
        action.setConfig(ConfigKey.FIELD_PATH, "$.userId");

        ProcessorResult result = processor.process(action, jsonContent, context);

        assertTrue(result.isSuccess());
        assertFalse(result.getProcessedContent().contains("userId"));
        assertTrue(result.getProcessedContent().contains("name"));
        assertEquals("remove", result.getMetadata("operation"));
        assertEquals("123", result.getMetadata("oldValue"));
    }

    @Test
    void testRemoveNonExistentField() throws Exception {
        String jsonContent = "{\"name\": \"test\"}";

        ProcessingAction action = new ProcessingAction(ActionType.REMOVE, "field", "field");
        action.setConfig(ConfigKey.OPERATION, "remove");
        action.setConfig(ConfigKey.FIELD_PATH, "$.userId");

        ProcessorResult result = processor.process(action, jsonContent, context);

        assertFalse(result.isSuccess());
        assertTrue(result.getErrorMessage().contains("Field not found"));
    }

    @Test
    void testRemoveNonExistentFieldWithIgnore() throws Exception {
        String jsonContent = "{\"name\": \"test\"}";

        ProcessingAction action = new ProcessingAction(ActionType.REMOVE, "field", "field");
        action.setConfig(ConfigKey.OPERATION, "remove");
        action.setConfig(ConfigKey.FIELD_PATH, "$.userId");
        action.setConfig(ConfigKey.IGNORE_NOT_FOUND, true);

        ProcessorResult result = processor.process(action, jsonContent, context);

        assertTrue(result.isSuccess());
        assertEquals(false, result.getMetadata("found"));
    }

    @Test
    void testInvalidJsonPath() {
        ProcessingAction action = new ProcessingAction(ActionType.REPLACE, "field", "field");
        action.setConfig(ConfigKey.OPERATION, "replace");
        action.setConfig(ConfigKey.FIELD_PATH, "invalid.path");
        action.setConfig(ConfigKey.TO, "value");

        assertFalse(processor.validateConfiguration(action));
    }

    @Test
    void testEmptyContent() throws Exception {
        ProcessingAction action = new ProcessingAction(ActionType.REPLACE, "field", "field");
        action.setConfig(ConfigKey.OPERATION, "replace");
        action.setConfig(ConfigKey.FIELD_PATH, "$.userId");
        action.setConfig(ConfigKey.TO, "value");

        ProcessorResult result = processor.process(action, "", context);

        assertFalse(result.isSuccess());
        assertTrue(result.getErrorMessage().contains("Content is empty"));
    }

    @Test
    void testInvalidJson() throws Exception {
        ProcessingAction action = new ProcessingAction(ActionType.REPLACE, "field", "field");
        action.setConfig(ConfigKey.OPERATION, "replace");
        action.setConfig(ConfigKey.FIELD_PATH, "$.userId");
        action.setConfig(ConfigKey.TO, "value");

        ProcessorResult result = processor.process(action, "invalid json", context);

        assertFalse(result.isSuccess());
        assertTrue(result.getErrorMessage().contains("JSON processing failed"));
    }

    @Test
    void testNestedFieldPath() throws Exception {
        String jsonContent = "{\"user\": {\"id\": \"123\", \"profile\": {\"name\": \"test\"}}}";

        ProcessingAction action = new ProcessingAction(ActionType.REPLACE, "field", "field");
        action.setConfig(ConfigKey.OPERATION, "replace");
        action.setConfig(ConfigKey.FIELD_PATH, "$.user.profile.name");
        action.setConfig(ConfigKey.FROM, "auto");
        action.setConfig(ConfigKey.TO, "newname");

        ProcessorResult result = processor.process(action, jsonContent, context);

        assertTrue(result.isSuccess());
        assertTrue(result.getProcessedContent().contains("newname"));
        assertFalse(result.getProcessedContent().contains("\"name\":\"test\""));
    }
}