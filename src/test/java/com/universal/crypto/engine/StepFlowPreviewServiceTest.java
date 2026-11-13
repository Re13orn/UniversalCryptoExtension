package com.universal.crypto.engine;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.processor.impl.CryptoProcessor;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StepFlowPreviewServiceTest {

    @Test
    void previewRunsStepFlowAndShowsVariableBridge() throws Exception {
        ProcessorManager processorManager = new ProcessorManager();
        processorManager.registerProcessor(new CryptoProcessor(null));
        StepFlowPreviewService service = new StepFlowPreviewService(processorManager);

        ProcessingAction decodeToVariable = codecAction(Constants.ActionType.DECRYPT, "Base64",
                Constants.TargetType.VARIABLE, "plain",
                Map.of(
                        Constants.ConfigKey.INPUT_SOURCE, Constants.InputSource.REQUEST_BODY,
                        Constants.ConfigKey.VARIABLE_NAME, "plain"
                ));

        ProcessingAction encodeFromVariable = codecAction(Constants.ActionType.ENCRYPT, "Hex",
                Constants.TargetType.BODY, "",
                Map.of(
                        Constants.ConfigKey.INPUT_SOURCE, Constants.InputSource.VARIABLE,
                        Constants.ConfigKey.INPUT_NAME, "plain"
                ));

        StepFlowPreviewService.PreviewResult result = service.preview(
                java.util.List.of(decodeToVariable, encodeFromVariable),
                "aGVsbG8=",
                "POST",
                new URL("https://example.com/api"),
                Map.of("Content-Type", "text/plain"),
                Constants.ToolSource.REPEATER,
                true,
                Constants.ExecutionPhase.DISPLAY
        );

        assertTrue(result.isSuccess());
        assertEquals("68656c6c6f", result.getFinalBody());
        assertEquals(2, result.getSteps().size());
        assertEquals("executed", result.getSteps().get(0).getStatus());
        assertEquals("hello", result.getVariables().get("plain"));
        assertEquals("executed", result.getSteps().get(1).getStatus());
    }

    @Test
    void previewExplainsSkippedPhase() throws Exception {
        ProcessorManager processorManager = new ProcessorManager();
        processorManager.registerProcessor(new CryptoProcessor(null));
        StepFlowPreviewService service = new StepFlowPreviewService(processorManager);

        ProcessingAction sendOnlyAction = codecAction(Constants.ActionType.DECRYPT, "Base64",
                Constants.TargetType.BODY, "",
                Map.of(Constants.ConfigKey.EXECUTION_PHASE, Constants.ExecutionPhase.SEND));

        StepFlowPreviewService.PreviewResult result = service.preview(
                java.util.List.of(sendOnlyAction),
                "aGVsbG8=",
                "POST",
                new URL("https://example.com/api"),
                Map.of(),
                Constants.ToolSource.REPEATER,
                true,
                Constants.ExecutionPhase.DISPLAY
        );

        assertTrue(result.isSuccess());
        assertEquals("aGVsbG8=", result.getFinalBody());
        assertEquals("skipped", result.getSteps().get(0).getStatus());
        assertTrue(result.getSteps().get(0).getMessage().contains(Constants.ExecutionPhase.DISPLAY));
    }

    private ProcessingAction codecAction(String actionType,
                                         String algorithm,
                                         String targetType,
                                         String targetName,
                                         Map<String, Object> extraConfig) {
        ProcessingAction action = new ProcessingAction();
        action.setActionType(actionType);
        action.setTargetType(targetType);
        action.setTargetName(targetName);
        action.setProcessor(Constants.ProcessorType.CRYPTO);
        action.setEnabled(true);

        Map<String, Object> config = new HashMap<>();
        config.put(Constants.ConfigKey.ALGORITHM, algorithm);
        config.put(Constants.ConfigKey.CRYPTO_PROVIDER, "internal");
        config.put(Constants.ConfigKey.KEY_SOURCE, "none");
        config.put(Constants.ConfigKey.PAYLOAD_FORMAT, "raw");
        config.put(Constants.ConfigKey.PLAIN_FORMAT, "plain");
        config.put(Constants.ConfigKey.EXECUTION_PHASE, Constants.ExecutionPhase.DISPLAY);
        config.putAll(extraConfig);
        action.setConfig(config);
        return action;
    }
}
