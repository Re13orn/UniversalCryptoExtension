package com.universal.crypto.engine;

import com.universal.crypto.handler.HttpRequestContext;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleCondition;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.processor.impl.CryptoProcessor;
import com.universal.crypto.processor.impl.ScriptProcessor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URL;
import java.nio.file.Path;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuleProcessingServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void requestPhaseCanPassIntermediateValueThroughVariable() throws Exception {
        RuleManager ruleManager = new RuleManager(new RuleConfigStorage(tempDir.toString()));
        ProcessingRule rule = new ProcessingRule("pipeline-rule");
        rule.setName("Pipeline Rule");
        rule.setEnabled(true);
        rule.setPriority(1);

        RuleCondition condition = new RuleCondition();
        condition.addHost("example.com");
        condition.addMethod("POST");
        rule.setCondition(condition);

        rule.addRequestAction(codecAction(Constants.ActionType.DECRYPT, "Base64",
                Constants.TargetType.VARIABLE, "plain",
                Map.of(
                        Constants.ConfigKey.INPUT_SOURCE, Constants.InputSource.REQUEST_BODY,
                        Constants.ConfigKey.VARIABLE_NAME, "plain"
                )));

        rule.addRequestAction(codecAction(Constants.ActionType.ENCRYPT, "Hex",
                Constants.TargetType.BODY, "",
                Map.of(
                        Constants.ConfigKey.INPUT_SOURCE, Constants.InputSource.VARIABLE,
                        Constants.ConfigKey.INPUT_NAME, "plain"
                )));

        ruleManager.addRule(rule);

        ProcessorManager processorManager = new ProcessorManager();
        processorManager.registerProcessor(new CryptoProcessor(null));

        RuleProcessingService service = new RuleProcessingService(
                ruleManager,
                new RuleMatchEngine(),
                processorManager
        );

        HttpRequestContext context = HttpRequestContext.builder()
                .method("POST")
                .url(new URL("https://example.com/api"))
                .headers(Map.of("Content-Type", "text/plain"))
                .body("aGVsbG8=")
                .toolSource(Constants.ToolSource.REPEATER)
                .build();

        RuleProcessingService.ProcessingOutcome outcome = service.processRequestForPhase(
                context,
                context.getBody(),
                Constants.ExecutionPhase.DISPLAY
        );

        assertTrue(outcome.isSuccess());
        assertEquals("68656c6c6f", outcome.getContent());
        assertEquals(2, outcome.getExecutedActions().size());
    }

    @Test
    void headerDisplayActionsReplaceRequestAndResponseValuesWithoutChangingContext() throws Exception {
        RuleManager ruleManager = new RuleManager(new RuleConfigStorage(tempDir.toString()));
        ProcessingRule rule = new ProcessingRule("header-display", "Header display", true, 1);
        rule.setShowInEditor(true);
        RuleCondition condition = new RuleCondition();
        condition.addHeader("*", "*staging.example.test*");
        rule.setCondition(condition);
        rule.addRequestAction(replaceAction("display"));
        rule.addResponseAction(replaceAction("response-display"));
        ruleManager.addRule(rule);

        ProcessorManager processors = new ProcessorManager();
        processors.registerProcessor(new ScriptProcessor());
        RuleProcessingService service = new RuleProcessingService(ruleManager, new RuleMatchEngine(), processors);

        Map<String, String> requestHeaders = Map.of(
                "Host", "api.example.test",
                "Referer", "https://staging.example.test/request"
        );
        HttpRequestContext request = HttpRequestContext.builder()
                .method("GET")
                .url(new URL("https://api.example.test/demo"))
                .headers(requestHeaders)
                .body("")
                .toolSource(Constants.ToolSource.REPEATER)
                .build();
        String requestPrefix = "GET /demo HTTP/1.1\r\nHost: api.example.test\r\n"
                + "Referer: https://staging.example.test/request\r\n\r\n";
        RuleProcessingService.HeaderDisplayOutcome requestDisplay =
                service.processRequestHeadersForDisplay(request, requestPrefix);

        assertTrue(requestDisplay.isSuccess());
        assertEquals("GET /demo HTTP/1.1\r\nHost: api.example.test\r\n"
                        + "Referer: https://example.test/request\r\n\r\n",
                requestDisplay.getContent());
        assertEquals("https://staging.example.test/request", request.getHeaders().get("Referer"));
        assertTrue(service.shouldProvidePlaintextRequestEditor(request));

        Map<String, String> responseHeaders = Map.of(
                "Content-Type", "application/json",
                "Location", "https://staging.example.test/response"
        );
        var response = com.universal.crypto.handler.HttpResponseContext.builder()
                .method("GET")
                .url(new URL("https://api.example.test/demo"))
                .requestHeaders(requestHeaders)
                .headers(responseHeaders)
                .statusCode(302)
                .body("{}")
                .toolSource(Constants.ToolSource.REPEATER)
                .build();
        String responsePrefix = "HTTP/1.1 302 Found\r\nContent-Type: application/json\r\n"
                + "Location: https://staging.example.test/response\r\n\r\n";
        RuleProcessingService.HeaderDisplayOutcome responseDisplay =
                service.processResponseHeadersForDisplay(response, responsePrefix);

        assertTrue(responseDisplay.isSuccess());
        assertEquals("HTTP/1.1 302 Found\r\nContent-Type: application/json\r\n"
                        + "Location: https://example.test/response\r\n\r\n",
                responseDisplay.getContent());
        assertEquals("https://staging.example.test/response", response.getHeaders().get("Location"));
        assertFalse(responseDisplay.getExecutedActions().isEmpty());
    }

    private ProcessingAction replaceAction(String phase) {
        ProcessingAction action = new ProcessingAction(
                Constants.ActionType.DECRYPT, Constants.TargetType.HEADER, "*", Constants.ProcessorType.SCRIPT);
        action.setEnabled(true);
        action.setConfig(Constants.ConfigKey.EXECUTION_PHASE, phase);
        action.setConfig(Constants.ConfigKey.INPUT_SOURCE, Constants.InputSource.HEADER);
        action.setConfig(Constants.ConfigKey.INPUT_NAME, "*");
        action.setConfig(Constants.ConfigKey.SCRIPT_CODE,
                "if (typeof content !== 'string') return null;\n"
                        + "if (content.indexOf('staging.example.test') === -1) return null;\n"
                        + "return content.split('staging.example.test').join('example.test');");
        return action;
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
