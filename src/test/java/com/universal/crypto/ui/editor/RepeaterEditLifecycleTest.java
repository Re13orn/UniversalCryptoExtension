package com.universal.crypto.ui.editor;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import com.universal.crypto.engine.*;
import com.universal.crypto.handler.HttpRequestContext;
import com.universal.crypto.model.*;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.processor.impl.ScriptProcessor;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.SwingUtilities;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@org.junit.jupiter.api.extension.ExtendWith(MontoyaByteArrayExtension.class)
class RepeaterEditLifecycleTest {
    private static final byte[] KEY = new byte[32], IV = new byte[12];
    private static final String PREFIX = "POST / HTTP/1.1\r\nHost: example.test\r\n\r\n";

    private static <T> T stub(Class<T> type, Map<String,Object> values) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class[]{type},
                (p,m,a) -> values.get(m.getName())));
    }

    private static HttpRequest request(String body) {
        var bytes = stub(ByteArray.class, Map.of("getBytes", (PREFIX + body).getBytes(StandardCharsets.ISO_8859_1)));
        var service = stub(HttpService.class, Map.of("secure", true, "host", "example.test", "port", 443));
        var values = Map.<String,Object>of("method", "POST", "path", "/", "httpService", service,
                "headers", List.of(), "bodyToString", body, "toByteArray", bytes, "bodyOffset", PREFIX.length());
        return (HttpRequest)Proxy.newProxyInstance(HttpRequest.class.getClassLoader(), new Class[]{HttpRequest.class},
                (p,m,a) -> m.getName().equals("withBody") ? request(MontoyaByteArrayExtension.text(a[0])) : values.get(m.getName()));
    }

    private static String cipher(String content, int mode) throws Exception {
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(KEY, "AES"), new GCMParameterSpec(128, IV));
        return mode == Cipher.ENCRYPT_MODE
                ? Base64.getEncoder().encodeToString(cipher.doFinal(content.getBytes(StandardCharsets.UTF_8)))
                : new String(cipher.doFinal(Base64.getDecoder().decode(content)), StandardCharsets.UTF_8);
    }

    @Test void previewAndRepeatedHostReadsDoNotAcknowledgeOrLoseEditedCiphertext() throws Exception {
        var manager = new RuleManager(new RuleConfigStorage() {
            public List<ProcessingRule> loadRules() { return List.of(); }
            public void saveRules(List<ProcessingRule> rules) { }
        });
        var processors = new ProcessorManager(); processors.registerProcessor(new ScriptProcessor());
        var rule = new ProcessingRule("lifecycle", "Lifecycle", true, 1);
        rule.setCondition(new RuleCondition());
        String key = Base64.getEncoder().encodeToString(KEY), iv = Base64.getEncoder().encodeToString(IV);
        for (boolean encrypt : new boolean[]{false, true}) {
            var action = new ProcessingAction(encrypt ? "encrypt" : "decrypt", "body", "script");
            action.setConfig(Constants.ConfigKey.EXECUTION_PHASE, encrypt ? "editor-send" : "display");
            action.setConfig(Constants.ConfigKey.SCRIPT_CODE, encrypt
                    ? "return Bytes.toBase64(Crypto.aesGcmEncrypt(Bytes.fromBase64('"+key+"'),Bytes.fromBase64('"+iv+"'),Bytes.utf8(content),[]));"
                    : "return Bytes.text(Crypto.aesGcmDecrypt(Bytes.fromBase64('"+key+"'),Bytes.fromBase64('"+iv+"'),Bytes.fromBase64(content),[]));");
            rule.addRequestAction(action);
        }
        manager.addRule(rule);
        var encryptions = new AtomicInteger();
        var processing = new RuleProcessingService(manager, new RuleMatchEngine(), processors) {
            public ProcessingOutcome processRequestForPhase(HttpRequestContext context, String content, String phase) {
                if (phase.equals("editor-send")) encryptions.incrementAndGet();
                return super.processRequestForPhase(context, content, phase);
            }
        };
        var original = request(cipher("{\"value\":1}", Cipher.ENCRYPT_MODE));
        SwingUtilities.invokeAndWait(() -> {
            try {
                var editor = new PlaintextHttpRequestEditor(null, processing, stub(EditorCreationContext.class, Map.of()));
                editor.setRequestResponse(stub(HttpRequestResponse.class, Map.of("request", original)));
                var view = (PlaintextMessageView)editor.uiComponent();
                var menu = view.textArea().getComponentPopupMenu();
                ((javax.swing.JRadioButtonMenuItem)menu.getComponent(2)).doClick();
                view.textArea().replaceRange("2", view.textArea().getText().lastIndexOf('1'), view.textArea().getText().lastIndexOf('1')+1);
                var preview = editor.getRequest();
                assertTrue(editor.isModified(), "Host preview must not consume the dirty state");
                ((javax.swing.JCheckBoxMenuItem)menu.getComponent(0)).doClick();
                ((javax.swing.JRadioButtonMenuItem)menu.getComponent(1)).doClick();
                assertSame(preview, editor.getRequest()); assertEquals(1, encryptions.get());
                var outgoing = editor.isModified() ? editor.getRequest() : original;
                assertEquals("{\"value\":2}", cipher(outgoing.bodyToString(), Cipher.DECRYPT_MODE));
                assertTrue(editor.isModified());
                // A further edit invalidates prepared ciphertext and uses the new body.
                int number = view.textArea().getText().lastIndexOf('2');
                view.textArea().replaceRange("3", number, number+1);
                var second = editor.getRequest();
                assertNotSame(preview, second); assertEquals(2, encryptions.get());
                assertTrue(cipher(second.bodyToString(), Cipher.DECRYPT_MODE).contains("3"));
                assertSame(second, editor.getRequest()); assertEquals(2, encryptions.get());
                // Only the host setting the committed message establishes a new baseline.
                editor.setRequestResponse(stub(HttpRequestResponse.class, Map.of("request", second)));
                assertFalse(editor.isModified()); assertSame(second, editor.getRequest());
                assertTrue(view.bodyText().contains("3"));
            } catch (Exception e) { throw new AssertionError(e); }
        });
    }
}
