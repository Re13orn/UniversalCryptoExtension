package com.universal.crypto.ui.editor;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import com.universal.crypto.engine.*;
import com.universal.crypto.model.*;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.processor.impl.ScriptProcessor;
import com.universal.crypto.util.HttpBodyEncoding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import javax.swing.SwingUtilities;
import java.lang.reflect.Proxy;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MontoyaByteArrayExtension.class)
class EditorBodyBytesTest {
    private static <T> T stub(Class<T> type, Map<String,Object> values) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(),new Class[]{type},(p,m,a)->values.get(m.getName())));
    }

    private <T> T message(Class<T> type, byte[] body, Map<String,String> headers) {
        String first = type == HttpRequest.class ? "POST /demo HTTP/1.1" : "HTTP/1.1 200 OK";
        StringBuilder prefix = new StringBuilder(first+"\r\n");
        headers.forEach((n,v)->prefix.append(n).append(": ").append(v).append("\r\n"));
        prefix.append("\r\n");
        byte[] raw = prefix.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] serialized = Arrays.copyOf(raw,raw.length+body.length);
        System.arraycopy(body,0,serialized,raw.length,body.length);
        var values = Map.<String,Object>of("method","POST","url","https://example.test/demo","path","/demo",
                "statusCode",(short)200,"headers",headers.entrySet().stream().map(e->stub(HttpHeader.class,Map.of("name",e.getKey(),"value",e.getValue()))).toList(),
                "body",MontoyaByteArrayExtension.bytes(body),"bodyToString",new String(body,HttpBodyEncoding.charset(headers)),
                "toByteArray",MontoyaByteArrayExtension.bytes(serialized),"bodyOffset",raw.length);
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(),new Class[]{type},(p,m,a)->{
            if (m.getName().equals("withBody")) {
                assertInstanceOf(ByteArray.class,a[0],"Ciphertext must reach Montoya without a text round trip");
                return message(type,((ByteArray)a[0]).getBytes(),headers);
            }
            if (m.getName().equals("hasHeader")) return headers.keySet().stream().anyMatch(((String)a[0])::equalsIgnoreCase);
            if (m.getName().equals("withHeader") || m.getName().equals("withAddedHeader") || m.getName().equals("withUpdatedHeader")) {
                var next = new TreeMap<String,String>(String.CASE_INSENSITIVE_ORDER); next.putAll(headers); next.put((String)a[0],(String)a[1]);
                return message(type,body,next);
            }
            return values.get(m.getName());
        }));
    }

    private RuleProcessingService service(String encryption) {
        var manager = new RuleManager(null);
        var rule = new ProcessingRule("bytes","bytes",true,1); rule.setCondition(new RuleCondition()); rule.setShowInEditor(true);
        var decrypt = new ProcessingAction("decrypt","body","script");
        decrypt.setConfig(Map.of("executionPhase","display,response-display","scriptCode","return 'plain';"));
        var encrypt = new ProcessingAction("encrypt","body","script");
        encrypt.setConfig(Map.of("executionPhase","editor-send,response-editor-send","editorOnly","true","scriptCode",encryption));
        rule.addRequestAction(decrypt); rule.addRequestAction(encrypt); rule.addResponseAction(decrypt); rule.addResponseAction(encrypt); manager.addRule(rule);
        var processors = new ProcessorManager(); processors.registerProcessor(new ScriptProcessor());
        return new RuleProcessingService(manager,new RuleMatchEngine(),processors);
    }

    private void assertWriteBack(String script, String plaintext, Map<String,String> headers, byte[] expected) throws Exception {
        var service = service(script);
        SwingUtilities.invokeAndWait(()->{
            for (boolean response : new boolean[]{false,true}) {
                var request = message(HttpRequest.class,"cipher".getBytes(StandardCharsets.US_ASCII),headers);
                var original = message(HttpResponse.class,"cipher".getBytes(StandardCharsets.US_ASCII),headers);
                var pair = stub(HttpRequestResponse.class,Map.of("request",request,"response",original));
                var creation = stub(EditorCreationContext.class,Map.of("editorMode",EditorMode.DEFAULT));
                PlaintextMessageView view;
                if (response) {
                    var editor = new PlaintextHttpResponseEditor(null,service,creation); editor.setRequestResponse(pair);
                    assertSame(original,editor.getResponse());
                    view = (PlaintextMessageView)editor.uiComponent();
                    view.textArea().replaceRange(plaintext,view.prefixText().length(),view.textArea().getDocument().getLength());
                    var changed = editor.getResponse();
                    assertArrayEquals(expected,changed.body().getBytes());
                    assertEquals(Integer.toString(expected.length),changed.headers().stream().filter(h->h.name().equalsIgnoreCase("Content-Length")).findFirst().orElseThrow().value());
                    assertSame(changed,editor.getResponse()); assertTrue(editor.isModified());
                } else {
                    var editor = new PlaintextHttpRequestEditor(null,service,creation); editor.setRequestResponse(pair);
                    assertSame(request,editor.getRequest());
                    view = (PlaintextMessageView)editor.uiComponent();
                    view.textArea().replaceRange(plaintext,view.prefixText().length(),view.textArea().getDocument().getLength());
                    var changed = editor.getRequest();
                    assertArrayEquals(expected,changed.body().getBytes());
                    assertEquals(Integer.toString(expected.length),changed.headers().stream().filter(h->h.name().equalsIgnoreCase("Content-Length")).findFirst().orElseThrow().value());
                    assertSame(changed,editor.getRequest()); assertTrue(editor.isModified());
                }
                assertTrue(view.textArea().isEditable());
            }
        });
    }

    @Test void rawScriptCiphertextSurvivesRequestAndResponseEditorWriteBack() throws Exception {
        assertWriteBack("return [0,128,255,65];","edited",Map.of(),new byte[]{0,(byte)128,(byte)255,65});
    }

    @Test void declaredCharsetDeterminesTextCiphertextBytesInBothEditors() throws Exception {
        assertWriteBack("return '密文:'+content;","编辑",Map.of("Content-Type","text/plain; charset=GBK"),"密文:编辑".getBytes(Charset.forName("GBK")));
    }

    @Test void differentBytesWithTheSameDecodedTextAreStillAnEncryptionChange() throws Exception {
        assertWriteBack("return [128];","\uFFFD",Map.of(),new byte[]{(byte)128});
    }

    @Test void outcomeBytesCannotBeMutatedByCallers() {
        byte[] input = {0,(byte)128,(byte)255};
        var outcome = RuleProcessingService.ProcessingOutcome.success("text",input,List.of(),Map.of(),true);
        input[0] = 1; byte[] received = outcome.getBodyBytes(); received[1] = 0;
        assertArrayEquals(new byte[]{0,(byte)128,(byte)255},outcome.getBodyBytes());
    }
}
