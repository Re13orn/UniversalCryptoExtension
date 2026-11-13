package com.universal.crypto.ui.editor;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.extension.*;
import com.universal.crypto.engine.*;
import com.universal.crypto.handler.*;
import com.universal.crypto.model.*;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.processor.impl.ScriptProcessor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@org.junit.jupiter.api.extension.ExtendWith(MontoyaByteArrayExtension.class)
class ResponseEditLifecycleTest {
    private static final byte[] KEY = new byte[32], IV = new byte[12];
    private static final String AAD = "POST|/demo|nonce";
    private static <T> T stub(Class<T> type, Map<String,Object> values) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class[]{type}, (p,m,a) -> values.get(m.getName())));
    }
    private static HttpHeader header(String name, String value) {
        return stub(HttpHeader.class, Map.of("name", name, "value", value));
    }
    private static HttpResponse response(String body, int status, Map<String,String> headers) {
        var all = new LinkedHashMap<>(headers);
        all.put("Content-Length", Integer.toString(body.getBytes(StandardCharsets.UTF_8).length));
        var prefix = new StringBuilder("HTTP/1.1 " + status + " OK\r\n");
        all.forEach((n,v) -> prefix.append(n).append(": ").append(v).append("\r\n")); prefix.append("\r\n");
        var bytes = stub(ByteArray.class, Map.of("getBytes", body.getBytes(StandardCharsets.UTF_8)));
        var raw = stub(ByteArray.class, Map.of("getBytes", (prefix + body).getBytes(StandardCharsets.UTF_8)));
        var values = Map.<String,Object>of("headers", all.entrySet().stream().map(e -> header(e.getKey(),e.getValue())).toList(),
                "statusCode", (short)status, "body", bytes, "bodyToString", body, "toByteArray", raw,
                "bodyOffset", prefix.length(), "httpVersion", "HTTP/1.1", "reasonPhrase", "OK");
        return (HttpResponse)Proxy.newProxyInstance(HttpResponse.class.getClassLoader(), new Class[]{HttpResponse.class}, (p,m,a) -> {
            if (m.getName().equals("withBody")) return response(MontoyaByteArrayExtension.text(a[0]), status, all);
            if (m.getName().equals("hasHeader")) return all.keySet().stream().anyMatch(n -> n.equalsIgnoreCase((String)a[0]));
            if (m.getName().equals("withAddedHeader") || m.getName().equals("withUpdatedHeader")) {
                var next = new LinkedHashMap<>(all); next.put((String)a[0], (String)a[1]); return response(body,status,next);
            }
            return values.get(m.getName());
        });
    }
    private static String cipher(String content, int mode) throws Exception {
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(KEY,"AES"), new GCMParameterSpec(128,IV));
        cipher.updateAAD(AAD.getBytes(StandardCharsets.UTF_8));
        return mode == Cipher.ENCRYPT_MODE ? Base64.getEncoder().encodeToString(cipher.doFinal(content.getBytes(StandardCharsets.UTF_8)))
                : new String(cipher.doFinal(Base64.getDecoder().decode(content)),StandardCharsets.UTF_8);
    }
    private static class Fixture {
        final RuleManager manager;
        final RuleMatchEngine match = new RuleMatchEngine();
        final ProcessorManager processors = new ProcessorManager();
        final AtomicInteger encryptions = new AtomicInteger(), parses = new AtomicInteger();
        final RuleProcessingService service;
        final ProcessingAction encrypt;
        final ProcessingRule rule;
        final HttpResponse original;
        final HttpRequestResponse pair;
        Fixture() throws Exception {
            manager = new RuleManager(new RuleConfigStorage() {
                public List<ProcessingRule> loadRules() { return List.of(); }
                public void saveRules(List<ProcessingRule> rules) { }
            });
            processors.registerProcessor(new ScriptProcessor());
            rule = new ProcessingRule("response-edit","Response edit",true,1); rule.setShowInEditor(true); rule.setCondition(new RuleCondition());
            String args = "Bytes.fromBase64('"+Base64.getEncoder().encodeToString(KEY)+"'),Bytes.fromBase64('"+Base64.getEncoder().encodeToString(IV)+"'),";
            String aad = "Bytes.utf8(request.getMethod()+'|'+request.getPath()+'|'+request.getOriginalHeader('X-Nonce'))";
            var decrypt = new ProcessingAction("decrypt","body","script");
            decrypt.setConfig("executionPhase","response-display");
            decrypt.setConfig("scriptCode","return Bytes.text(Crypto.aesGcmDecrypt("+args+"Bytes.fromBase64(content),"+aad+"));");
            encrypt = new ProcessingAction("encrypt","body","script");
            encrypt.setConfig("executionPhase","response-editor-send");
            encrypt.setConfig("scriptCode","return Bytes.toBase64(Crypto.aesGcmEncrypt("+args+"Bytes.utf8(content),"+aad+"));");
            rule.addResponseAction(decrypt); rule.addResponseAction(encrypt); manager.addRule(rule);
            service = new RuleProcessingService(manager,match,processors) {
                public ProcessingOutcome processResponseForPhase(HttpResponseContext c,String content,String phase) {
                    if (phase.equals("response-editor-send")) encryptions.incrementAndGet();
                    return super.processResponseForPhase(c,content,phase);
                }
            };
            original = response(cipher("{\"value\":1}",Cipher.ENCRYPT_MODE),200,Map.of("Content-Type","application/json"));
            var request = stub(HttpRequest.class,Map.of("method","POST","url","https://example.test/demo","headers",List.of(header("X-Nonce","nonce"))));
            pair = stub(HttpRequestResponse.class,Map.of("request",request,"response",original));
        }
        PlaintextHttpResponseEditor editor(EditorMode mode) {
            return new PlaintextHttpResponseEditor(null,service,stub(EditorCreationContext.class,Map.of("editorMode",mode)),prefix -> {
                parses.incrementAndGet(); assertTrue(prefix.startsWith("HTTP/1.1 201"));
                assertFalse(prefix.contains("value"));
                return response("",201,Map.of("Content-Type","application/json","X-Edited","yes"));
            });
        }
    }

    @ParameterizedTest @EnumSource(EditorMode.class)
    void onlyHostEditableResponsesAreEncryptedAfterEdits(EditorMode mode) throws Exception {
        var f = new Fixture();
        SwingUtilities.invokeAndWait(() -> {
            try {
                var editor = f.editor(mode); editor.setRequestResponse(f.pair);
                var view = (PlaintextMessageView)editor.uiComponent();
                assertSame(f.original,editor.getResponse()); assertFalse(editor.isModified()); assertEquals(0,f.encryptions.get());
                if (mode == EditorMode.READ_ONLY) { assertFalse(view.textArea().isEditable()); return; }
                assertTrue(view.textArea().isEditable());
                var menu = view.textArea().getComponentPopupMenu(); ((JRadioButtonMenuItem)menu.getComponent(2)).doClick();
                int value = view.textArea().getText().lastIndexOf('1'); view.textArea().replaceRange("2",value,value+1);
                var changed = editor.getResponse(); assertTrue(editor.isModified());
                assertEquals("{\"value\":2}",cipher(changed.bodyToString(),Cipher.DECRYPT_MODE));
                ((JCheckBoxMenuItem)menu.getComponent(0)).doClick(); ((JRadioButtonMenuItem)menu.getComponent(1)).doClick();
                assertSame(changed,editor.getResponse()); assertEquals(1,f.encryptions.get());
                ((JCheckBoxMenuItem)menu.getComponent(0)).doClick();
                String prefix = view.prefixText().replace("200 OK","201 Created").replace("\r\n\r\n","\r\nX-Edited: yes\r\n\r\n");
                view.textArea().replaceRange(prefix,0,view.prefixText().length());
                var next = editor.getResponse(); assertEquals(201,next.statusCode()); assertEquals(1,f.parses.get());
                assertEquals("{\"value\":2}",cipher(next.bodyToString(),Cipher.DECRYPT_MODE)); assertEquals(2,f.encryptions.get());
                assertSame(next,editor.getResponse()); assertTrue(editor.isModified());
                // The normal wire callback must not run response-editor-send again.
                var ctx = HttpResponseContext.builder().method("POST").url(new java.net.URL("https://example.test/demo"))
                        .requestHeaders(Map.of("X-Nonce","nonce")).headers(Map.of("Content-Length",Integer.toString(next.bodyToString().length())))
                        .body(next.bodyToString()).toolSource("PROXY").build();
                assertArrayEquals(ctx.getBodyBytes(),new HttpInterceptor(f.manager,f.match,f.processors).processResponse(ctx).getBodyBytes());
                var newPair = stub(HttpRequestResponse.class,Map.of("request",f.pair.request(),"response",next));
                editor.setRequestResponse(newPair); assertFalse(editor.isModified()); assertSame(next,editor.getResponse());
                assertTrue(view.bodyText().contains("2"));
            } catch (Exception e) { throw new AssertionError(e); }
        });
    }

    @Test void missingEncryptionAndLegacyAlwaysRulesDoNotOpenEditing() throws Exception {
        var f = new Fixture();
        SwingUtilities.invokeAndWait(() -> {
            for (String phase : List.of("response-send","always")) {
                f.encrypt.setConfig("executionPhase",phase); f.manager.updateRule(f.rule);
                var editor = f.editor(EditorMode.DEFAULT); editor.setRequestResponse(f.pair);
                assertFalse(((PlaintextMessageView)editor.uiComponent()).textArea().isEditable());
                assertSame(f.original,editor.getResponse()); assertFalse(editor.isModified());
            }
            assertEquals(0,f.encryptions.get());
        });
    }

    @Test void failuresAndNoOpEncryptionReturnOriginalCiphertext() throws Exception {
        var f = new Fixture();
        SwingUtilities.invokeAndWait(() -> {
            for (String script : List.of("throw new Error('invalid key');","return null;","return content;","return '';")) {
                var editor = f.editor(EditorMode.DEFAULT); editor.setRequestResponse(f.pair);
                var view = (PlaintextMessageView)editor.uiComponent();
                f.encrypt.setConfig("scriptCode",script); f.manager.updateRule(f.rule);
                view.textArea().append(" ");
                assertSame(f.original,editor.getResponse()); assertTrue(editor.isModified());
                assertTrue(view.textArea().getToolTipText().contains("original ciphertext retained"));
            }
        });
    }

    @Test void removingEncryptionAfterLoadKeepsCiphertext() throws Exception {
        var f = new Fixture();
        SwingUtilities.invokeAndWait(() -> {
            var editor = f.editor(EditorMode.DEFAULT); editor.setRequestResponse(f.pair);
            var view = (PlaintextMessageView)editor.uiComponent();
            assertTrue(view.textArea().isEditable());
            f.encrypt.setEnabled(false); f.manager.updateRule(f.rule); view.textArea().append(" ");
            assertSame(f.original,editor.getResponse()); assertEquals(0,f.encryptions.get());
            assertTrue(view.textArea().getToolTipText().contains("No response-editor-send"));
        });
    }

    @Test void ruleUpdatesInvalidatePreparedResponseWithoutConsumingDirtyState() throws Exception {
        var f=new Fixture();
        SwingUtilities.invokeAndWait(()->{
            try {
                var editor=f.editor(EditorMode.DEFAULT);editor.setRequestResponse(f.pair);var view=(PlaintextMessageView)editor.uiComponent();
                int at=view.textArea().getText().lastIndexOf('1');view.textArea().replaceRange("2",at,at+1);
                var first=editor.getResponse();assertNotSame(f.original,first);assertSame(first,editor.getResponse());assertEquals(1,f.encryptions.get());
                f.encrypt.setConfig("scriptCode",f.encrypt.getConfigString("scriptCode").replace("Bytes.utf8(content)","Bytes.utf8(content+' ')"));f.manager.updateRule(f.rule);
                var next=editor.getResponse();assertNotSame(first,next);assertEquals(view.bodyText()+" ",cipher(next.bodyToString(),Cipher.DECRYPT_MODE));
                assertSame(next,editor.getResponse());assertEquals(2,f.encryptions.get());assertTrue(editor.isModified());
                f.manager.removeRule(f.rule.getId());assertSame(f.original,editor.getResponse());assertTrue(editor.isModified());
            } catch(Exception error) { throw new AssertionError(error); }
        });
    }

    @Test void invalidResponsePrefixDoesNotEncryptOrParse() throws Exception {
        var f = new Fixture();
        SwingUtilities.invokeAndWait(() -> {
            var editor = f.editor(EditorMode.DEFAULT); editor.setRequestResponse(f.pair);
            var view = (PlaintextMessageView)editor.uiComponent();
            view.textArea().replaceRange("BAD\r\n",0,view.textArea().getText().indexOf("\r\n")+2);
            assertSame(f.original,editor.getResponse()); assertEquals(0,f.encryptions.get()); assertEquals(0,f.parses.get());
        });
    }
}
