package com.universal.crypto.engine;

import com.universal.crypto.handler.*;
import com.universal.crypto.model.*;
import com.universal.crypto.processor.*;
import com.universal.crypto.processor.impl.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class PipelineConsistencyTest {
    @TempDir Path temp;
    private ProcessingAction script(String target, String name, String code, String phase) {
        var action = new ProcessingAction("execute",target,"script"); action.setTargetName(name);
        action.setConfig("scriptCode",code); if (phase != null) action.setConfig("executionPhase",phase);
        return action;
    }
    private ProcessorManager processors() {
        var manager = new ProcessorManager(); manager.registerProcessor(new ScriptProcessor());
        manager.registerProcessor(new SignatureProcessor(null)); return manager;
    }
    private RuleManager rules(List<ProcessingAction> actions, boolean response) {
        var manager = new RuleManager(new RuleConfigStorage(temp.toString()));
        var rule = new ProcessingRule("consistency"); rule.setEnabled(true); rule.setCondition(new RuleCondition());
        actions.forEach(a -> { if (response) rule.addResponseAction(a); else rule.addRequestAction(a); });
        manager.addRule(rule); return manager;
    }

    @Test void generatedSignatureHeadersAndCurrentBodyAgreeAcrossThreePipelines() throws Exception {
        String phases = "display,editor-send,send,response-display,response-editor-send,response-send";
        var change = script("body",null,"return 'changed';",phases);
        var sign = new ProcessingAction("sign","header","signature"); sign.setTargetName("X-Sign");
        sign.setConfig(Map.of("algorithm","HmacSHA256","cryptoProvider","internal","keySource","static","keyValue","key",
                "signatureFormat","hex","signContent","body","inputSource","request-body","executionPhase",phases,
                "headerTemplates",Map.of("X-Generated","fixed")));
        var inspect = script("header","X-Probe","return request.getOriginalHeader('x-origin')+'|'+request.getHeader('X-Generated')+'|'+Bytes.text(bodyBytes);",phases);
        var actions = List.of(change,sign,inspect); var url = new URL("https://example.test/demo");
        var mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec("key".getBytes(StandardCharsets.UTF_8),"HmacSHA256"));
        String expectedSign = HexFormat.of().formatHex(mac.doFinal("changed".getBytes(StandardCharsets.UTF_8)));
        for (boolean response : new boolean[]{false,true}) {
            var headers = response ? Map.of("Content-Type","text/plain") : Map.of("X-Origin","hello");
            var originalHeaders = Map.of("X-Origin","hello"); var manager = rules(actions,response);
            var processors = processors(); var match = new RuleMatchEngine();
            var service = new RuleProcessingService(manager,match,processors);
            var request = HttpRequestContext.builder().method("POST").url(url).headers(headers).body("initial").toolSource("PROXY").build();
            var reply = HttpResponseContext.builder().method("POST").url(url).headers(headers).requestHeaders(originalHeaders).body("initial").toolSource("PROXY").build();
            var outcome = response ? service.processResponseForPhase(reply,"initial","response-editor-send") : service.processRequestForPhase(request,"initial","editor-send");
            var preview = new StepFlowPreviewService(processors).preview(actions,"initial","POST",url,headers,"PROXY",!response,
                    response ? "response-editor-send" : "editor-send",originalHeaders);
            HttpContextBase wire = response ? new HttpInterceptor(manager,match,processors).processResponse(reply)
                    : new HttpInterceptor(manager,match,processors).processRequest(request);
            assertTrue(outcome.isSuccess()); assertTrue(preview.isSuccess());
            assertEquals("changed",outcome.getContent()); assertEquals(outcome.getContent(),preview.getFinalBody()); assertEquals("changed",wire.getBody());
            for (var values : List.of(outcome.getModifiedHeaders(),preview.getModifiedHeaders())) {
                assertEquals("fixed",values.get("X-Generated")); assertEquals(expectedSign,values.get("X-Sign"));
                assertEquals("hello|fixed|changed",values.get("X-Probe"));
            }
            assertEquals(expectedSign,wire.getHeaderIgnoreCase("X-Sign")); assertEquals("fixed",wire.getHeaderIgnoreCase("X-Generated"));
            assertEquals("hello|fixed|changed",wire.getHeaderIgnoreCase("X-Probe"));
        }
    }

    @Test void byteResultsReachLaterStepsWithoutUtf8RoundTrip() throws Exception {
        var first = script("body",null,"return [0,255,128,65];","display");
        var second = script("header","X-Bytes","return Bytes.toBase64(bodyBytes);","display");
        var actions = List.of(first,second); var processors = processors();
        var ctx = HttpRequestContext.builder().method("POST").url(new URL("https://example.test/"))
                .headers(Map.of("Content-Type","text/plain; charset=ISO-8859-1")).body("initial").build();
        var outcome = new RuleProcessingService(rules(actions,false),new RuleMatchEngine(),processors).processRequestForPhase(ctx,ctx.getBody(),"display");
        var preview = new StepFlowPreviewService(processors).preview(actions,ctx.getBody(),"POST",ctx.getUrl(),ctx.getHeaders(),"PROXY",true,"display");
        assertEquals("AP+AQQ==",outcome.getModifiedHeaders().get("X-Bytes")); assertEquals("AP+AQQ==",preview.getModifiedHeaders().get("X-Bytes"));
        assertArrayEquals(new byte[]{0,(byte)255,(byte)128,65},outcome.getContent().getBytes(StandardCharsets.ISO_8859_1));
    }

    @Test void previewUsesOriginalResponseHeadersAndDefaultResponseDisplayPhase() throws Exception {
        var action = script("body",null,"return request.getOriginalHeader('X-Nonce')+'|'+request.getHeader('Content-Type');",null);
        var result = new StepFlowPreviewService(processors()).preview(List.of(action),"body","GET",new URL("https://example.test/"),
                Map.of("Content-Type","response/type"),"PROXY",false,null,Map.of("X-Nonce","n","Content-Type","request/type"));
        assertTrue(result.isSuccess()); assertEquals("n|response/type",result.getFinalBody());
    }

    @Test void noChangeDoesNotCopyAHeaderInputIntoTheBody() throws Exception {
        var action = script("body",null,"return null;","display"); action.setConfig("inputSource","header"); action.setConfig("inputName","X-Input");
        var result = new StepFlowPreviewService(processors()).preview(List.of(action),"original","GET",new URL("https://example.test/"),
                Map.of("X-Input","header-only"),"PROXY",true,"display");
        assertEquals("original",result.getFinalBody());
    }

    @Test void previewFailurePolicyMatchesEditorAndWireExecution() throws Exception {
        var fail = script("body",null,"throw new Error('failure');","display,send");
        var later = script("body",null,"return 'later';","display,send");
        var preview = new StepFlowPreviewService(processors()); var url = new URL("https://example.test/");
        var editor = preview.preview(List.of(fail,later),"original","GET",url,Map.of(),"PROXY",true,"display");
        assertFalse(editor.isSuccess()); assertEquals("original",editor.getFinalBody()); assertEquals(1,editor.getSteps().size());
        var wire = preview.preview(List.of(fail,later),"original","GET",url,Map.of(),"PROXY",true,"send");
        assertFalse(wire.isSuccess()); assertEquals("later",wire.getFinalBody());
    }

    @Test void previewNeverCallsExternalProviderOrReturnsMockSuccess() throws Exception {
        var calls = new AtomicInteger();
        var client = new ProcessorFactory.MockApiClient() {
            public CryptoProcessor.ApiResponse processRequest(CryptoProcessor.ApiRequest request) throws Exception {
                calls.incrementAndGet(); return super.processRequest(request);
            }
        };
        var action = new ProcessingAction("encrypt","body","crypto");
        action.setConfig(Map.of("algorithm","AES-CBC","cryptoProvider","external","keySource","static","keyValue","test","executionPhase","display"));
        var result = new StepFlowPreviewService(ProcessorFactory.createDefaultProcessorManager(client)).preview(List.of(action),"plain","POST",
                new URL("https://example.test/"),Map.of(),"PROXY",true,"display");
        assertFalse(result.isSuccess()); assertEquals(0,calls.get()); assertEquals("plain",result.getFinalBody());
    }

    @Test void changingCharsetReinterpretsTheSameBytesAcrossAllPipelines() throws Exception {
        String phases = "display,send";
        var change = script("header","Content-Type","return 'text/plain; charset=ISO-8859-1';",phases);
        var inspect = script("header","X-Probe","return content+'|'+Bytes.toBase64(bodyBytes);",phases);
        inspect.setConfig("inputSource","request-body");
        var actions=List.of(change,inspect);var processors=processors();var manager=rules(actions,false);var match=new RuleMatchEngine();
        var context=HttpRequestContext.builder().method("POST").url(new URL("https://example.test/"))
                .headers(Map.of("Content-Type","text/plain; charset=GBK")).body("中文").toolSource("PROXY").build();
        String expected=new String(context.getBodyBytes(),StandardCharsets.ISO_8859_1)+"|1tDOxA==";
        var outcome=new RuleProcessingService(manager,match,processors).processRequestForPhase(context,context.getBody(),"display");
        var preview=new StepFlowPreviewService(processors).preview(actions,context.getBody(),"POST",context.getUrl(),context.getHeaders(),"PROXY",true,"display");
        var wire=new HttpInterceptor(manager,match,processors).processRequest(context);
        assertEquals(expected,outcome.getModifiedHeaders().get("X-Probe"));assertEquals(expected,preview.getModifiedHeaders().get("X-Probe"));
        assertEquals(expected,wire.getHeaderIgnoreCase("X-Probe"));assertArrayEquals(context.getBodyBytes(),wire.getBodyBytes());
    }

    @Test void failedSignatureAndScriptDoNotLeakTentativeHeadersOrSharedBindings() throws Exception {
        var sign=new ProcessingAction("sign","header","signature");sign.setTargetName("X-Sign");
        sign.setConfig(Map.of("algorithm","Unsupported","keySource","static","keyValue","key","cryptoProvider","internal",
                "headerTemplates",Map.of("X-Attempt","tentative"),"executionPhase","send"));
        var fail=script("body",null,"ctx.setSharedData('temporary','leaked'); throw new Error('failure');","send");
        var inspect=script("header","X-Probe","return (ctx.getSharedData('temporary') == null ? 'none' : 'leaked')+'|'+request.getHeader('X-Attempt');","send");
        var actions=List.of(sign,fail,inspect);var processors=processors();var manager=rules(actions,false);var match=new RuleMatchEngine();
        var context=HttpRequestContext.builder().method("POST").url(new URL("https://example.test/"))
                .headers(Map.of("X-Attempt","original")).body("body").toolSource("PROXY").build();
        var wire=new HttpInterceptor(manager,match,processors).processRequest(context);
        var preview=new StepFlowPreviewService(processors).preview(actions,"body","POST",context.getUrl(),context.getHeaders(),"PROXY",true,"send");
        assertEquals("none|original",wire.getHeaderIgnoreCase("X-Probe"));assertEquals("original",wire.getHeaderIgnoreCase("X-Attempt"));
        assertEquals("none|original",preview.getModifiedHeaders().get("X-Probe"));assertFalse(preview.isSuccess());
    }

    @Test void booleanNoChangeAndEmptyPhaseCannotPretendEncryptionWasApplied() throws Exception {
        var context=ProcessorContext.forRequest("POST",new URL("https://example.test/"),Map.of("X-Input","header"),"PROXY").build();
        var pipeline=new ActionPipeline(context,"plaintext",null);
        var action=script("body",null,"return null;","display");action.setActionType("encrypt");
        pipeline.apply(action,ProcessorResult.success("header").addMetadata("noChange",true).addMetadata("setHeaders",Map.of("X-Fake","bad")).build());
        assertEquals("plaintext",pipeline.body());assertTrue(pipeline.modifiedHeaders().isEmpty());assertFalse(pipeline.bodyEncryptionApplied());
        var request=HttpRequestContext.builder().method("POST").url(context.getUrl()).body("plaintext").build();
        var result=new RuleProcessingService(rules(List.of(action),false),new RuleMatchEngine(),processors()).processRequestForPhase(request,"plaintext","editor-send");
        assertFalse(result.isMatched());assertFalse(result.hasBodyEncryption());assertNull(result.getContent());
    }

    @Test void repeaterSendPreviewIncludesEditorSendAndAlwaysExcludesResponseEditor() throws Exception {
        var action = script("body",null,"return 'encrypted';","editor-send"); var url = new URL("https://example.test/");
        var preview = new StepFlowPreviewService(processors());
        assertEquals("encrypted",preview.preview(List.of(action),"plain","POST",url,Map.of(),"REPEATER",true,"send").getFinalBody());
        assertEquals("plain",preview.preview(List.of(action),"plain","POST",url,Map.of(),"PROXY",true,"send").getFinalBody());
        action.setConfig("executionPhase","always");
        assertEquals("plain",preview.preview(List.of(action),"plain","POST",url,Map.of(),"PROXY",false,"response-editor-send").getFinalBody());
    }
}
