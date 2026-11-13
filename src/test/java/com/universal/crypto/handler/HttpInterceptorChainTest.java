package com.universal.crypto.handler;

import com.universal.crypto.engine.RuleConfigStorage;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.engine.RuleMatchEngine;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.processor.impl.ScriptProcessor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class HttpInterceptorChainTest {

    private RuleManager ruleManager;
    private ProcessorManager processorManager;
    private HttpInterceptor interceptor;
    private RuleMatchEngine matchEngine;

    @BeforeEach
    public void setUp() {
        // Create an anonymous subclass of RuleConfigStorage that overrides methods to do nothing
        RuleConfigStorage dummyStorage = new RuleConfigStorage() {
            @Override
            public void saveRules(List<ProcessingRule> rules) throws IOException {
                // Do nothing
            }
            @Override
            public List<ProcessingRule> loadRules() throws IOException { 
                return new ArrayList<>(); 
            }
        };
        
        ruleManager = new RuleManager(dummyStorage);
        processorManager = new ProcessorManager();
        matchEngine = new RuleMatchEngine();
        
        // Register processors
        processorManager.registerProcessor(new ScriptProcessor());
        
        interceptor = new HttpInterceptor(ruleManager, matchEngine, processorManager);
    }

    @Test
    public void testVariableExtractionAndUsage() throws Exception {
        // 1. Define Rule
        ProcessingRule rule = new ProcessingRule("test-chain", "Test Chain Rule", true, 100);
        
        // Ensure rule has a condition that matches everything
        com.universal.crypto.model.RuleCondition condition = new com.universal.crypto.model.RuleCondition();
        rule.setCondition(condition);
        
        // Action 1: Extract ID from JSON body to variable
        ProcessingAction extractAction = new ProcessingAction();
        extractAction.setActionType("execute");
        extractAction.setTargetType(Constants.TargetType.VARIABLE);
        extractAction.setTargetName("temp_id");
        extractAction.setProcessor(Constants.ProcessorType.SCRIPT);
        // Script to extract "id" from JSON
        extractAction.setConfig(Constants.ConfigKey.SCRIPT_CODE, 
            "return '12345';");
        
        // Action 2: Sign the ID and put in header
        ProcessingAction signAction = new ProcessingAction();
        signAction.setActionType("execute");
        signAction.setTargetType(Constants.TargetType.HEADER);
        signAction.setTargetName("X-Signature");
        signAction.setProcessor(Constants.ProcessorType.SCRIPT);
        // Read from variable (Input Source)
        signAction.setConfig(Constants.ConfigKey.INPUT_SOURCE, Constants.InputSource.VARIABLE);
        signAction.setConfig(Constants.ConfigKey.INPUT_NAME, "temp_id");
        // Script to sign (simple append)
        signAction.setConfig(Constants.ConfigKey.SCRIPT_CODE, 
            "return content + '-signed';");
            
        rule.addRequestAction(extractAction);
        rule.addRequestAction(signAction);
        
        ruleManager.addRule(rule);
        
        // 2. Prepare Request
        String requestBody = "{\"id\": \"12345\", \"data\": \"test\"}";
        List<ProcessingRule> matchingRules = Collections.singletonList(rule);
        
        HttpRequestContext request = HttpRequestContext.fromMontoya(
            "POST", 
            new java.net.URL("http://example.com/api"), 
            new HashMap<>(), 
            requestBody, 
            "PROXY"
        );
        
        // 3. Process
        HttpRequestContext result = interceptor.processRequest(request);
        
        // 4. Verify
        // The body should be unchanged (we targeted variable and header)
        assertEquals(requestBody, result.getBody());
        
        // Check if header is added
        String sig = result.getHeaderIgnoreCase("X-Signature");
        assertEquals("12345-signed", sig);
    }
    @Test public void traceListsOnlyRulesWithActionsForTheObservedDirectionAndMarksDisplayPhases() throws Exception {
        var rule = new ProcessingRule("response-only", "Response only", true, 1);
        rule.setCondition(new com.universal.crypto.model.RuleCondition());
        rule.addResponseAction(script("return 'plaintext';", "body", "response-display"));
        ruleManager.addRule(rule);
        var events = new java.util.ArrayList<String>();
        interceptor.addTrafficListener((method, url, status, info, before, after) -> events.add(status + "|" + info));
        var url = new java.net.URL("https://example.test/");
        interceptor.processRequest(HttpRequestContext.builder().method("GET").url(url).body("").toolSource("PROXY").build());
        assertEquals(0, events.size(), "A response-only rule is not a request processing event");
        var original = HttpResponseContext.builder().method("GET").url(url).body("ciphertext").statusCode(200).toolSource("PROXY").build();
        var result = interceptor.processResponse(original);
        org.junit.jupiter.api.Assertions.assertSame(original, result);
        assertEquals(1, events.size());
        org.junit.jupiter.api.Assertions.assertTrue(events.get(0).contains("Response Observed"));
        org.junit.jupiter.api.Assertions.assertTrue(events.get(0).contains("[response-display]"));
    }

    private ProcessingAction script(String code, String target, String phase) {
        ProcessingAction action = new ProcessingAction("execute", target, "script");
        action.setConfig(Constants.ConfigKey.SCRIPT_CODE, code);
        action.setConfig(Constants.ConfigKey.EXECUTION_PHASE, phase);
        return action;
    }

    @Test public void failingActionPreservesEarlierAndLaterChanges() throws Exception {
        ProcessingRule rule = new ProcessingRule("failure-isolation", "Isolation", true, 1);
        rule.setCondition(new com.universal.crypto.model.RuleCondition());
        rule.addRequestAction(script("return content+'-first';", "body", "send"));
        rule.addRequestAction(script("throw new Error('failure');", "body", "send"));
        rule.addRequestAction(script("return content+'-last';", "body", "send"));
        ruleManager.addRule(rule);
        HttpRequestContext result = interceptor.processRequest(HttpRequestContext.builder().method("POST").url(new java.net.URL("http://example.com/")).body("input").toolSource("PROXY").build());
        org.junit.jupiter.api.Assertions.assertFalse(result.hasError());
        assertEquals("input-first-last", result.getBody());
    }

    @Test public void messageIdsSeparateCollidingBodiesAndSurviveMoreThan1000Exchanges() throws Exception {
        ProcessingRule rule = new ProcessingRule("correlation", "Correlation", true, 1);
        rule.setCondition(new com.universal.crypto.model.RuleCondition());
        rule.addRequestAction(script("ctx.setSharedData('value',content); return content;", "body", "send"));
        rule.addResponseAction(script("return ctx.getSharedData('value');", "body", "response-send"));
        ruleManager.addRule(rule);
        java.net.URL url = new java.net.URL("http://example.com/");
        for (int id=0; id<1002; id++) interceptor.processRequest(HttpRequestContext.builder().method("POST").url(url).body(id==0 ? "Aa" : id==1 ? "BB" : "value-"+id).messageId(id).toolSource("PROXY").build());
        assertEquals("Aa", interceptor.processResponse(HttpResponseContext.builder().method("POST").url(url).body("response").messageId(0).toolSource("PROXY").build()).getBody());
        assertEquals("BB", interceptor.processResponse(HttpResponseContext.builder().method("POST").url(url).body("response").messageId(1).toolSource("PROXY").build()).getBody());
    }

    @Test public void requestOriginalHeadersAreAvailableAndRetainValuesBeforeHeaderActions() throws Exception {
        ProcessingRule rule = new ProcessingRule("request-original", "Request original", true, 1);
        rule.setCondition(new com.universal.crypto.model.RuleCondition());
        var change = script("return 'changed';", "header", "display,send,editor-send");
        change.setTargetName("X-Test-Probe"); rule.addRequestAction(change);
        rule.addRequestAction(script("return 'orig='+request.getOriginalHeader('x-test-probe')+'|get='+request.getHeader('X-Test-Probe')+'|keys='+Object.keys(request.getOriginalHeaders()).join(',');", "body", "display,send,editor-send"));
        ruleManager.addRule(rule);
        var context = HttpRequestContext.builder().method("POST").url(new java.net.URL("https://example.com/"))
                .headers(Map.of("X-Test-Probe", "hello")).body("cipher").toolSource("PROXY").build();
        var service = new com.universal.crypto.engine.RuleProcessingService(ruleManager, matchEngine, processorManager);
        for (String phase : List.of("display", "editor-send")) {
            var result = service.processRequestForPhase(context, context.getBody(), phase);
            assertEquals("orig=hello|get=changed|keys=X-Test-Probe", result.getContent());
            assertEquals("changed", result.getModifiedHeaders().get("X-Test-Probe"));
        }
        assertEquals("orig=hello|get=changed|keys=X-Test-Probe", interceptor.processRequest(context).getBody());
        assertEquals("hello", context.getHeaderIgnoreCase("X-Test-Probe"));
    }

    @Test public void originalRequestHeadersReachBothResponsePhasesWithoutAffectingMatching() throws Exception {
        ProcessingRule rule = new ProcessingRule("original", "Original headers", true, 1);
        var condition = new com.universal.crypto.model.RuleCondition();
        condition.setHeaders(Map.of("Content-Type", "application/json")); rule.setCondition(condition);
        rule.addResponseAction(script("return request.getOriginalHeader('x-test-probe') + '|' + request.getHeader('Content-Type') + '|' + request.getOriginalHeaders()['X-Test-Probe'];", "body", "response-display,response-send"));
        ruleManager.addRule(rule);
        var context = HttpResponseContext.builder().method("POST").url(new java.net.URL("https://example.com/"))
                .headers(Map.of("Content-Type", "application/json"))
                .requestHeaders(Map.of("X-Test-Probe", "hello", "Content-Type", "request/type"))
                .body("cipher").toolSource("PROXY").build();
        var service = new com.universal.crypto.engine.RuleProcessingService(ruleManager, matchEngine, processorManager);
        assertEquals("hello|application/json|hello", service.processResponseForPhase(context, context.getBody(), "response-display").getContent());
        assertEquals("hello|application/json|hello", interceptor.processResponse(context).getBody());
        condition.setHeaders(Map.of("X-Test-Probe", "hello")); ruleManager.updateRule(rule);
        org.junit.jupiter.api.Assertions.assertFalse(service.processResponseForPhase(context, context.getBody(), "response-display").isMatched());
        assertEquals("cipher", interceptor.processResponse(context).getBody());
    }

    @Test public void requestHeaderAadDecryptsOnlyForDisplayAndRejectsWrongNonce() throws Exception {
        byte[] key = new byte[32], iv = new byte[12];
        var cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, "AES"), new javax.crypto.spec.GCMParameterSpec(128, iv));
        cipher.updateAAD("POST|/api/demo|nonce-one".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String ciphertext = Base64.getEncoder().encodeToString(cipher.doFinal("hello".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        String code = "var aad=Bytes.utf8(request.getMethod()+'|'+request.getPath()+'|'+request.getOriginalHeader('X-Nonce'));"
                + "return Bytes.text(Crypto.aesGcmDecrypt(Bytes.fromBase64('" + Base64.getEncoder().encodeToString(key)
                + "'),Bytes.fromBase64('" + Base64.getEncoder().encodeToString(iv) + "'),Bytes.fromBase64(content),aad));";
        ProcessingRule rule = new ProcessingRule("aad", "Request AAD", true, 1);
        rule.setCondition(new com.universal.crypto.model.RuleCondition());
        rule.addResponseAction(script(code, "body", "response-display")); ruleManager.addRule(rule);
        var context = HttpResponseContext.builder().method("POST").url(new java.net.URL("https://example.com/api/demo"))
                .requestHeaders(Map.of("X-Nonce", "nonce-one"))
                .headers(Map.of("Content-Type", "text/plain", "Content-Length", Integer.toString(ciphertext.length())))
                .body(ciphertext).toolSource("PROXY").build();
        var service = new com.universal.crypto.engine.RuleProcessingService(ruleManager, matchEngine, processorManager);
        assertEquals("hello", service.processResponseForPhase(context, ciphertext, "response-display").getContent());
        var wire = interceptor.processResponse(context);
        org.junit.jupiter.api.Assertions.assertArrayEquals(context.getBodyBytes(), wire.getBodyBytes());
        assertEquals(context.getHeaders(), wire.getHeaders());
        for (var headers : List.of(Map.of("X-Nonce", "wrong"), Map.<String,String>of())) {
            var invalid = HttpResponseContext.builder().method("POST").url(context.getUrl()).requestHeaders(headers)
                    .headers(context.getHeaders()).body(ciphertext).toolSource("PROXY").build();
            org.junit.jupiter.api.Assertions.assertFalse(service.processResponseForPhase(invalid, ciphertext, "response-display").isSuccess());
            assertEquals(ciphertext, interceptor.processResponse(invalid).getBody());
        }
    }

    @Test public void originalHeadersAreImmutableAndSurviveResponseCopies() {
        var original = new HashMap<String,String>(); original.put("X-Nonce", "one");
        var context = HttpResponseContext.builder().headers(Map.of()).requestHeaders(original).body("cipher").build();
        original.put("X-Nonce", "two");
        for (var copy : List.of(context, context.withBody("new"), context.withBodyBytes(new byte[]{1}), context.withHeader("X-Other", "v"), context.withError("failure"))) {
            assertEquals("one", copy.getOriginalHeader("x-nonce"));
            org.junit.jupiter.api.Assertions.assertThrows(UnsupportedOperationException.class, () -> copy.getRequestHeaders().put("X-Nonce", "bad"));
        }
        var processor = com.universal.crypto.processor.ProcessorContext.builder().requestHeaders(context.getRequestHeaders()).build();
        processor.setHeader("X-Nonce", "current");
        assertEquals("one", processor.getOriginalHeader("X-NONCE"));
        org.junit.jupiter.api.Assertions.assertThrows(UnsupportedOperationException.class, () -> processor.getOriginalHeaders().clear());
        org.junit.jupiter.api.Assertions.assertNull(HttpResponseContext.builder().build().getRequestHeaders());
        org.junit.jupiter.api.Assertions.assertTrue(com.universal.crypto.processor.ProcessorContext.builder().build().getOriginalHeaders().isEmpty());
    }

    @Test public void responseDisplayLeavesWireBodyUnchanged() throws Exception {
        ProcessingRule rule = new ProcessingRule("display", "Display", true, 1);
        rule.setCondition(new com.universal.crypto.model.RuleCondition());
        rule.addResponseAction(script("return 'plaintext';", "body", "response-display"));
        ruleManager.addRule(rule);
        HttpResponseContext context = HttpResponseContext.builder().method("GET").url(new java.net.URL("http://example.com/")).body("ciphertext").toolSource("PROXY").build();
        assertEquals("ciphertext", interceptor.processResponse(context).getBody());
        com.universal.crypto.engine.RuleProcessingService service = new com.universal.crypto.engine.RuleProcessingService(ruleManager, matchEngine, processorManager);
        assertEquals("plaintext", service.processResponseForPhase(context, context.getBody(), "response-display").getContent());
    }

    @Test public void scriptCanWriteRawBytes() throws Exception {
        ProcessingRule rule = new ProcessingRule("binary", "Binary", true, 1);
        rule.setCondition(new com.universal.crypto.model.RuleCondition());
        rule.addRequestAction(script("return [0,255,128,1];", "body", "send"));
        ruleManager.addRule(rule);
        HttpRequestContext result = interceptor.processRequest(HttpRequestContext.builder().method("POST").url(new java.net.URL("http://example.com/")).body("input").toolSource("PROXY").build());
        org.junit.jupiter.api.Assertions.assertArrayEquals(new byte[]{0,(byte)255,(byte)128,1}, result.getBodyBytes());
    }

}
