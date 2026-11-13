package com.universal.crypto.ui;

import com.universal.crypto.engine.*;
import com.universal.crypto.handler.*;
import com.universal.crypto.model.*;
import com.universal.crypto.processor.ProcessorFactory;
import com.universal.crypto.processor.ProcessorContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.net.URL;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class TemplateLifecycleTest {
    @TempDir Path temp;

    @Test void requestTemplateEncryptsEditedPlaintextExactlyOnceAndKeepsUneditedCiphertext() throws Exception {
        var actions=PipelineTemplateFactory.base64WrappedCipherFieldRequestRoundTrip(new PipelineTemplateFactory.Base64WrappedCipherFieldConfig(
                "data","AES-GCM",Base64.getEncoder().encodeToString(new byte[32]),"base64","iv",Base64.getEncoder().encodeToString(new byte[12]),"base64"));
        var processors=ProcessorFactory.createDefaultProcessorManager(null);
        var nonce=Base64.getEncoder().encodeToString(new byte[12]);
        var plain="{\"data\":\"original\",\"iv\":\""+nonce+"\"}";
        var initial=processors.process(actions.get(1),plain,ProcessorContext.forRequest("POST",new URL("https://api.example.test/demo"),Map.of(),"REPEATER").build());
        assertTrue(initial.isSuccess(),initial.getErrorMessage());
        ProcessingRule rule=new ProcessingRule("wizard-roundtrip");rule.setName("test");rule.setEnabled(true);rule.setShowInEditor(true);
        RuleCondition condition=new RuleCondition();condition.setHosts(List.of("api.example.test"));rule.setCondition(condition);rule.setRequestActions(actions);
        var manager=new RuleManager(new RuleConfigStorage(temp.toString()));manager.addRule(rule);
        var match=new RuleMatchEngine();var service=new RuleProcessingService(manager,match,processors);var wire=new HttpInterceptor(manager,match,processors);
        var original=HttpRequestContext.builder().method("POST").url(new URL("https://api.example.test/demo"))
                .headers(Map.of("Content-Type","application/json")).body(initial.getProcessedContent()).toolSource("REPEATER").build();
        assertTrue(service.shouldProvidePlaintextRequestEditor(original));
        var shown=service.processRequestForPhase(original,original.getBody(),"display");assertTrue(shown.isSuccess(),shown.getError());
        assertTrue(shown.getContent().contains("original"));
        String edited=shown.getContent().replace("original","edited");
        var prepared=service.processRequestForPhase(original.withBody(edited),edited,"editor-send");
        assertTrue(prepared.isSuccess(),prepared.getError());assertTrue(prepared.hasBodyEncryption());
        var forwarded=wire.processRequest(original.withBody(prepared.getContent()));
        assertArrayEquals(original.withBody(prepared.getContent()).getBodyBytes(),forwarded.getBodyBytes());
        var decrypted=service.processRequestForPhase(forwarded,forwarded.getBody(),"display");
        assertTrue(decrypted.isSuccess(),decrypted.getError());assertTrue(decrypted.getContent().contains("edited"));
        assertArrayEquals(original.getBodyBytes(),wire.processRequest(original).getBodyBytes());
        var preview=new StepFlowPreviewService(processors).preview(actions,prepared.getContent(),"POST",original.getUrl(),original.getHeaders(),"REPEATER",true,"send");
        assertEquals(prepared.getContent(),preview.getFinalBody());assertTrue(preview.getSteps().stream().noneMatch(s->"executed".equals(s.getStatus())));
    }

    @Test void oldEditorSendRulesRetainWireExecutionWhileOptInFlagSkipsIt() throws Exception {
        var action=new ProcessingAction("encrypt","body","script");action.setConfig("scriptCode","return content+'-encrypted';");action.setConfig("executionPhase","editor-send");
        var rule=new ProcessingRule("legacy");rule.setName("legacy");rule.addRequestAction(action);rule.setEnabled(true);rule.setCondition(new RuleCondition());
        var manager=new RuleManager(new RuleConfigStorage(temp.toString()));manager.addRule(rule);
        var processors=ProcessorFactory.createDefaultProcessorManager(null);var interceptor=new HttpInterceptor(manager,new RuleMatchEngine(),processors);
        var context=HttpRequestContext.builder().method("POST").url(new URL("https://example.test/")).body("original").headers(Map.of()).toolSource("REPEATER").build();
        assertEquals("original-encrypted",interceptor.processRequest(context).getBody());
        action.setConfig("editorOnly",true);action.setConfig("executionPhase","send,editor-send");manager.updateRule(rule);
        assertEquals("original",interceptor.processRequest(context).getBody());
        var service=new RuleProcessingService(manager,new RuleMatchEngine(),processors);
        assertTrue(service.processRequestForPhase(context,context.getBody(),"send").getExecutedActions().isEmpty());
        assertEquals("original-encrypted",service.processRequestForPhase(context,context.getBody(),"editor-send").getContent());
    }
}
