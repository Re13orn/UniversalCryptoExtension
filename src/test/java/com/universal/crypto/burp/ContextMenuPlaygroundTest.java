package com.universal.crypto.burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorFactory;
import com.universal.crypto.ui.PlaygroundPanel;
import org.junit.jupiter.api.Test;
import javax.swing.*;
import java.lang.reflect.Proxy;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class ContextMenuPlaygroundTest {
    @Test void sendingARequestToThePlaygroundRetainsScriptHeaderAndUrlContext() throws Exception {
        String raw = "POST /api/item?x=1 HTTP/2\r\nHost: example.test\r\nX-Nonce: nonce-one\r\nContent-Type: application/json\r\n\r\n{\"x\":1}";
        HttpRequest request = (HttpRequest) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> switch (method.getName()) { case "toString" -> raw; case "bodyToString" -> "{\"x\":1}"; default -> null; });
        PlaygroundPanel[] panel = new PlaygroundPanel[1]; CountDownLatch complete = new CountDownLatch(1);
        SwingUtilities.invokeAndWait(() -> {
            panel[0] = new PlaygroundPanel(null, ProcessorFactory.createDefaultProcessorManager(null));
            var action = new ProcessingAction("execute", "body", "script");
            action.setConfig("scriptCode", "return request.getMethod()+'|'+request.getPath()+'|'+request.getOriginalHeader('X-Nonce')+'|'+content;");
            panel[0].importActionConfiguration(action); panel[0].setInputText(UniversalContextMenuProvider.playgroundInput(request));
            var output = field(panel[0], "outputArea", JTextArea.class);
            output.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                private void check() { if (output.getText().equals("POST|/api/item|nonce-one|{\"x\":1}")) complete.countDown(); }
                public void insertUpdate(javax.swing.event.DocumentEvent e) { check(); }
                public void removeUpdate(javax.swing.event.DocumentEvent e) { check(); }
                public void changedUpdate(javax.swing.event.DocumentEvent e) { check(); }
            });
            try { var run = PlaygroundPanel.class.getDeclaredMethod("executeTest", java.awt.event.ActionEvent.class); run.setAccessible(true); run.invoke(panel[0], (Object) null); }
            catch (Exception error) { throw new RuntimeException(error); }
        });
        assertTrue(complete.await(5, TimeUnit.SECONDS), "The request body alone cannot provide method/path/original headers");
    }
    @Test void fullHttpInputAlsoKeepsCryptoTestingFocusedOnTheBody() throws Exception {
        PlaygroundPanel[] panel = new PlaygroundPanel[1]; CountDownLatch complete = new CountDownLatch(1);
        SwingUtilities.invokeAndWait(() -> {
            panel[0] = new PlaygroundPanel(null, ProcessorFactory.createDefaultProcessorManager(null));
            var action = new ProcessingAction("encrypt", "body", "crypto");
            action.setConfig(java.util.Map.of("algorithm", "Base64", "cryptoProvider", "internal", "keySource", "none"));
            panel[0].importActionConfiguration(action);
            panel[0].setInputText("POST /api HTTP/1.1\r\nHost: example.test\r\nContent-Type: text/plain\r\n\r\nhello");
            var output = field(panel[0], "outputArea", JTextArea.class);
            output.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                private void check() { if (output.getText().equals("aGVsbG8=")) complete.countDown(); }
                public void insertUpdate(javax.swing.event.DocumentEvent e) { check(); }
                public void removeUpdate(javax.swing.event.DocumentEvent e) { check(); }
                public void changedUpdate(javax.swing.event.DocumentEvent e) { check(); }
            });
            try { var run = PlaygroundPanel.class.getDeclaredMethod("executeTest", java.awt.event.ActionEvent.class); run.setAccessible(true); run.invoke(panel[0], (Object) null); }
            catch (Exception error) { throw new RuntimeException(error); }
        });
        assertTrue(complete.await(5, TimeUnit.SECONDS), "Crypto mode must transform the HTTP body rather than its entire serialized request");
    }

    private static <T> T field(Object object, String name, Class<T> type) {
        try { var field = object.getClass().getDeclaredField(name); field.setAccessible(true); return type.cast(field.get(object)); }
        catch (Exception error) { throw new RuntimeException(error); }
    }
}
