package com.universal.crypto.processor;

import com.universal.crypto.model.Constants.ActionType;
import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.impl.FieldProcessor;
// Removed LoggerProcessor import
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.net.URL;
import java.util.List;
import java.util.Map;

class ProcessorManagerTest {

    private ProcessorManager manager;
    private ProcessorInterface testProcessor;

    @BeforeEach
    void setUp() {
        manager = new ProcessorManager();
        testProcessor = new TestProcessor();
    }

    @Test
    void testRegisterProcessor() {
        manager.registerProcessor(testProcessor);
        assertEquals(1, manager.getProcessorCount());
        assertTrue(manager.hasProcessors());
        assertEquals(testProcessor, manager.getProcessor("test"));
    }

    @Test
    void testRegisterNullProcessor() {
        assertThrows(IllegalArgumentException.class, () -> {
            manager.registerProcessor(null);
        });
    }

    @Test
    void testUnregisterProcessor() {
        manager.registerProcessor(testProcessor);
        assertTrue(manager.unregisterProcessor("test"));
        assertEquals(0, manager.getProcessorCount());
        assertFalse(manager.hasProcessors());
        assertNull(manager.getProcessor("test"));
    }

    @Test
    void testUnregisterNonExistentProcessor() {
        assertFalse(manager.unregisterProcessor("nonexistent"));
        assertFalse(manager.unregisterProcessor(null));
    }

    @Test
    void testFindProcessorForAction() {
        manager.registerProcessor(testProcessor);

        ProcessorInterface found = manager.findProcessorForAction(ActionType.REPLACE);
        assertEquals(testProcessor, found);

        assertNull(manager.findProcessorForAction(ActionType.ENCRYPT));
        assertNull(manager.findProcessorForAction(null));
    }

    @Test
    void testProcessWithValidAction() throws Exception {
        manager.registerProcessor(testProcessor);

        ProcessingAction action = new ProcessingAction(ActionType.REPLACE, "body", "test");
        action.setConfig(ConfigKey.OPERATION, "replace");

        ProcessorContext context = ProcessorContext.builder()
                .method("GET")
                .url(new URL("https://example.com"))
                .isRequest(true)
                .build();

        ProcessorResult result = manager.process(action, "test content", context);

        assertTrue(result.isSuccess());
        assertEquals("processed: test content", result.getProcessedContent());
    }

    @Test
    void testProcessWithNullAction() {
        assertThrows(ProcessorException.class, () -> {
            manager.process(null, "content", null);
        });
    }

    @Test
    void testProcessWithNoMatchingProcessor() {
        ProcessingAction action = new ProcessingAction(ActionType.ENCRYPT, "body", "crypto");
        ProcessorContext context = ProcessorContext.builder().build();

        assertThrows(ProcessorException.class, () -> {
            manager.process(action, "content", context);
        });
    }

    @Test
    void testCanProcess() {
        manager.registerProcessor(testProcessor);

        ProcessingAction validAction = new ProcessingAction(ActionType.REPLACE, "body", "test");
        validAction.setConfig(ConfigKey.OPERATION, "replace");
        assertTrue(manager.canProcess(validAction));

        ProcessingAction invalidAction = new ProcessingAction(ActionType.ENCRYPT, "body", "crypto");
        assertFalse(manager.canProcess(invalidAction));

        assertFalse(manager.canProcess(null));
    }

    @Test
    void testGetConfigurationRequirements() {
        manager.registerProcessor(testProcessor);

        Map<String, String> requirements = manager.getConfigurationRequirements(ActionType.REPLACE, "test");
        assertNotNull(requirements);
        assertTrue(requirements.containsKey(ConfigKey.OPERATION));

        assertNull(manager.getConfigurationRequirements(ActionType.ENCRYPT, null));
        assertNull(manager.getConfigurationRequirements(ActionType.REPLACE, "nonexistent"));
    }

    @Test
    void testWithRealProcessors() {
        FieldProcessor fieldProcessor = new FieldProcessor();

        manager.registerProcessor(fieldProcessor);

        assertEquals(1, manager.getProcessorCount());
        assertTrue(manager.isActionTypeSupported(ActionType.REPLACE));
        // ActionType.LOG is removed, so we check REPLACE

        List<String> supportedActions = manager.getSupportedActionTypes();
        assertTrue(supportedActions.contains(ActionType.REPLACE));
    }

    @Test
    void testClearProcessors() {
        manager.registerProcessor(testProcessor);
        assertEquals(1, manager.getProcessorCount());

        manager.clearProcessors();
        assertEquals(0, manager.getProcessorCount());
        assertFalse(manager.hasProcessors());
    }

    private static class TestProcessor implements ProcessorInterface {

        @Override
        public ProcessorResult process(ProcessingAction action, String content, ProcessorContext context)
                throws ProcessorException {
            if (!validateConfiguration(action)) {
                throw new ProcessorException("Invalid configuration");
            }
            return ProcessorResult.success("processed: " + content).build();
        }

        @Override
        public boolean canHandle(String actionType) {
            return ActionType.REPLACE.equals(actionType);
        }

        @Override
        public String getProcessorType() {
            return "test";
        }

        @Override
        public boolean validateConfiguration(ProcessingAction action) {
            return action != null && action.hasConfig(ConfigKey.OPERATION);
        }

        @Override
        public Map<String, String> getRequiredParameters() {
            return Map.of(ConfigKey.OPERATION, "Operation parameter");
        }

        @Override
        public boolean isAvailable() {
            return true;
        }
    }
}