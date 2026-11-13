package com.universal.crypto.ui.editor;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import com.universal.crypto.engine.RuleProcessingService;
import com.universal.crypto.handler.HttpRequestContext;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@org.junit.jupiter.api.extension.ExtendWith(MontoyaByteArrayExtension.class)
class PlaintextHttpRequestEditorTest {
    @SuppressWarnings("unchecked") private <T> T stub(Class<T> type, Map<String, Object> values) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class[]{type}, (p, m, a) -> values.get(m.getName()));
    }

    @Test void cancellingAllBodyEditsDiscardsPreparedCiphertext() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            String prefix = "POST / HTTP/1.1\r\nHost: example.test\r\n\r\n";
            var raw = stub(ByteArray.class,Map.of("getBytes",(prefix+"cipher").getBytes(StandardCharsets.ISO_8859_1)));
            var request = stub(HttpRequest.class,Map.of("method","POST","path","/","headers",List.of(),"bodyToString","cipher","toByteArray",raw,"bodyOffset",prefix.length(),"withBody",stub(HttpRequest.class,Map.of())));
            var calls = new AtomicInteger();
            var processing = new RuleProcessingService(null,null,null) {
                public boolean canPrepareEditedRequest(HttpRequestContext context) { return true; }
                public ProcessingOutcome processRequestForPhase(HttpRequestContext ctx,String body,String phase) {
                    if (phase.equals("display")) return ProcessingOutcome.success(" {\"value\":1} ",List.of("decrypt"),Map.of());
                    calls.incrementAndGet(); return ProcessingOutcome.success("new-cipher",List.of("encrypt"),Map.of(), true);
                }
            };
            var editor = new PlaintextHttpRequestEditor(null,processing,stub(EditorCreationContext.class,Map.of()));
            editor.setRequestResponse(stub(HttpRequestResponse.class,Map.of("request",request)));
            var area = (org.fife.ui.rsyntaxtextarea.RSyntaxTextArea)((PlaintextMessageView)editor.uiComponent()).textArea();
            int value = area.getText().lastIndexOf('1'); area.replaceRange("2",value,value+1);
            assertTrue(editor.isModified()); assertNotSame(request,editor.getRequest());
            while (area.canUndo()) area.undoLastAction();
            assertFalse(editor.isModified()); assertSame(request,editor.getRequest()); assertEquals(1,calls.get());
        });
    }

    @Test
    void fullViewPreservesRawHeadersAndEncryptsOnlyEditedBody() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            String prefix = "POST /app?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nX-Duplicate: first\r\nX-Duplicate: second\r\n\r\n";
            ByteArray raw = stub(ByteArray.class, Map.of("getBytes", (prefix + "cipher").getBytes(StandardCharsets.ISO_8859_1)));
            HttpService httpService = stub(HttpService.class, Map.of("secure", true, "host", "example.com", "port", 443));
            HttpRequest encrypted = stub(HttpRequest.class, Map.of());
            AtomicReference<String> sentBody = new AtomicReference<>();
            Map<String, Object> values = Map.of("method", "POST", "path", "/app?x=1", "httpService", httpService,
                    "headers", List.of(), "bodyToString", "cipher", "toByteArray", raw, "bodyOffset", prefix.length());
            HttpRequest request = (HttpRequest) Proxy.newProxyInstance(HttpRequest.class.getClassLoader(), new Class[]{HttpRequest.class}, (p, m, a) -> {
                if (m.getName().equals("withBody")) { sentBody.set(MontoyaByteArrayExtension.text(a[0])); return encrypted; }
                return values.get(m.getName());
            });
            AtomicInteger displays = new AtomicInteger();
            AtomicInteger sends = new AtomicInteger();
            RuleProcessingService service = new RuleProcessingService(null, null, null) {
                public boolean canPrepareEditedRequest(HttpRequestContext context) { return true; }
                public ProcessingOutcome processRequestForPhase(HttpRequestContext context, String content, String phase) {
                    if (phase.equals("display")) { displays.incrementAndGet(); return ProcessingOutcome.success("明文", List.of("decrypt"), Map.of()); }
                    sends.incrementAndGet(); assertEquals("明文 edited", content);
                    return ProcessingOutcome.success("ENC(明文 edited)", List.of("encrypt"), Map.of(), true);
                }
            };
            var editor = new PlaintextHttpRequestEditor(null, service, stub(EditorCreationContext.class, Map.of()));
            var message = stub(HttpRequestResponse.class, Map.of("request", request));
            editor.setRequestResponse(message);
            PlaintextMessageView view = (PlaintextMessageView) editor.uiComponent();
            var toggle = (JCheckBoxMenuItem) view.textArea().getComponentPopupMenu().getComponent(0);
            assertEquals("Show original HTTP headers", toggle.getText());
            assertTrue(toggle.isSelected());
            assertEquals(prefix + "明文", view.textArea().getText()); assertFalse(editor.isModified());
            toggle.doClick(); assertEquals("明文", view.textArea().getText()); assertFalse(editor.isModified());
            toggle.doClick();
            assertEquals(prefix + "明文", view.textArea().getText());
            assertFalse(editor.isModified()); assertSame(request, editor.getRequest());
            view.textArea().append(" edited"); assertTrue(editor.isModified());
            toggle.doClick(); assertEquals("明文 edited", view.textArea().getText());
            toggle.doClick(); assertEquals(prefix + "明文 edited", view.textArea().getText());
            assertTrue(editor.isModified()); assertEquals(1, displays.get());
            assertSame(encrypted, editor.getRequest()); assertEquals("ENC(明文 edited)", sentBody.get());
            assertTrue(editor.isModified()); assertEquals(1, sends.get());
            // New messages reset edits but retain the display choice without a false modification.
            editor.setRequestResponse(message);
            assertEquals(prefix + "明文", view.textArea().getText()); assertFalse(editor.isModified());
            editor.setRequestResponse(null); assertEquals("无可用请求", view.textArea().getText());
        });
    }
    @Test
    void prettyAndRawAreDisplayOnlyUntilJsonIsEdited() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            String prefix = "POST / HTTP/1.1\r\nHost: example.test\r\n\r\n";
            String plaintext = " {\"n\":1e+02,\"n\":-0} ";
            var bytes = stub(ByteArray.class, Map.of("getBytes", (prefix + "cipher").getBytes(StandardCharsets.ISO_8859_1)));
            var httpService = stub(HttpService.class, Map.of("secure", true, "host", "example.test", "port", 443));
            var encrypted = stub(HttpRequest.class, Map.of());
            Map<String, Object> values = Map.of("method", "POST", "path", "/", "httpService", httpService,
                    "headers", List.of(), "bodyToString", "cipher", "toByteArray", bytes, "bodyOffset", prefix.length());
            var request = (HttpRequest) Proxy.newProxyInstance(HttpRequest.class.getClassLoader(), new Class[]{HttpRequest.class},
                    (p, m, a) -> m.getName().equals("withBody") ? encrypted : values.get(m.getName()));
            AtomicInteger sends = new AtomicInteger();
            AtomicReference<String> encryptionInput = new AtomicReference<>();
            var service = new RuleProcessingService(null, null, null) {
                public boolean canPrepareEditedRequest(HttpRequestContext context) { return true; }
                public ProcessingOutcome processRequestForPhase(HttpRequestContext context, String content, String phase) {
                    if (phase.equals("display")) return ProcessingOutcome.success(plaintext, List.of("decrypt"), Map.of());
                    sends.incrementAndGet(); encryptionInput.set(content);
                    return ProcessingOutcome.success("encrypted", List.of("encrypt"), Map.of(), true);
                }
            };
            var editor = new PlaintextHttpRequestEditor(null, service, stub(EditorCreationContext.class, Map.of()));
            editor.setRequestResponse(stub(HttpRequestResponse.class, Map.of("request", request)));
            var view = (PlaintextMessageView) editor.uiComponent();
            var menu = view.textArea().getComponentPopupMenu();
            assertEquals(prefix + JsonPresentation.pretty(plaintext), view.textArea().getText());
            assertEquals(plaintext, view.bodyText()); assertFalse(editor.isModified());
            ((JRadioButtonMenuItem) menu.getComponent(2)).doClick();
            ((JRadioButtonMenuItem) menu.getComponent(1)).doClick();
            assertFalse(editor.isModified()); assertSame(request, editor.getRequest()); assertEquals(0, sends.get());
            int offset = view.textArea().getText().indexOf("1e+02");
            view.textArea().select(offset, offset + 5); view.textArea().replaceSelection("2e+02");
            String edited = view.bodyText(); assertFalse(edited.contains("HTTP/1.1"));
            ((JRadioButtonMenuItem) menu.getComponent(2)).doClick();
            assertTrue(editor.isModified()); assertSame(encrypted, editor.getRequest());
            assertEquals(edited, encryptionInput.get()); assertEquals(1, sends.get());
        });
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(burp.api.montoya.ui.editor.extension.EditorMode.class)
    void repeaterKeyboardEditingStartsInBodyAndRespectsReadOnly(burp.api.montoya.ui.editor.extension.EditorMode mode) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            String prefix = "POST / HTTP/1.1\r\nHost: example.test\r\n\r\n";
            String plaintext = "{\"value\":1}";
            var bytes = stub(ByteArray.class, Map.of("getBytes", (prefix + "cipher").getBytes(StandardCharsets.ISO_8859_1)));
            var httpService = stub(HttpService.class, Map.of("secure", true, "host", "example.test", "port", 443));
            var encrypted = stub(HttpRequest.class, Map.of());
            var request = stub(HttpRequest.class, Map.of("method", "POST", "path", "/", "httpService", httpService,
                    "headers", List.of(), "bodyToString", "cipher", "toByteArray", bytes, "bodyOffset", prefix.length(), "withBody", encrypted));
            AtomicInteger sends = new AtomicInteger();
            var service = new RuleProcessingService(null, null, null) {
                public boolean canPrepareEditedRequest(HttpRequestContext context) { return true; }
                public ProcessingOutcome processRequestForPhase(HttpRequestContext context, String content, String phase) {
                    assertEquals("REPEATER", context.getToolSource());
                    if (phase.equals("display")) return ProcessingOutcome.success(plaintext, List.of("decrypt"), Map.of());
                    sends.incrementAndGet(); assertEquals("{\"value\":2}", content);
                    return ProcessingOutcome.success("encrypted", List.of("encrypt"), Map.of(), true);
                }
            };
            var tool = stub(burp.api.montoya.core.ToolSource.class, Map.of("toolType", burp.api.montoya.core.ToolType.REPEATER));
            var creation = stub(EditorCreationContext.class, Map.of("toolSource", tool, "editorMode", mode));
            var editor = new PlaintextHttpRequestEditor(null, service, creation);
            editor.setRequestResponse(stub(HttpRequestResponse.class, Map.of("request", request)));
            var view = (PlaintextMessageView) editor.uiComponent();
            var area = view.textArea();
            var typed = area.getActionMap().get(javax.swing.text.DefaultEditorKit.defaultKeyTypedAction);
            if (mode == burp.api.montoya.ui.editor.extension.EditorMode.READ_ONLY) {
                assertFalse(area.isEditable());
                typed.actionPerformed(new java.awt.event.ActionEvent(area, 0, "x"));
                assertEquals(prefix + JsonPresentation.pretty(plaintext), area.getText());
                assertFalse(editor.isModified()); assertSame(request, editor.getRequest());
                assertEquals(0, sends.get()); return;
            }
            assertTrue(area.isEditable()); assertEquals(prefix.length(), area.getCaretPosition());
            typed.actionPerformed(new java.awt.event.ActionEvent(area, 0, " "));
            assertTrue(editor.isModified()); assertTrue(area.getText().startsWith(prefix + " "));
            area.getActionMap().get(javax.swing.text.DefaultEditorKit.selectAllAction)
                    .actionPerformed(new java.awt.event.ActionEvent(area, 0, ""));
            assertEquals(0, area.getSelectionStart());
            area.replaceSelection(prefix + "{\"value\":2}");
            assertEquals(prefix + "{\"value\":2}", area.getText());
            ((JRadioButtonMenuItem) area.getComponentPopupMenu().getComponent(2)).doClick();
            assertEquals(prefix.length(), area.getCaretPosition());
            assertTrue(editor.isModified()); assertSame(encrypted, editor.getRequest()); assertEquals(1, sends.get());
        });
    }

    @Test void editedRequestLineAndHeadersReachEncryptionAndSurviveViewSwitches() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            String prefix = "POST /old HTTP/1.1\r\nHost: example.test\r\nX-Remove: old\r\n\r\n";
            String changedPrefix = "PATCH /new?x=1 HTTP/1.1\r\nHost: virtual.example\r\nX-Added: value\r\nX-Duplicate: first\r\nX-Duplicate: second\r\n\r\n";
            String plaintext = " {\"value\":1e+02} ";
            var bytes = stub(ByteArray.class, Map.of("getBytes", (prefix + "cipher").getBytes(StandardCharsets.ISO_8859_1)));
            var transport = stub(HttpService.class, Map.of("secure", true, "host", "example.test", "port", 443));
            var encrypted = stub(HttpRequest.class, Map.of("withHeader", stub(HttpRequest.class, Map.of())));
            AtomicReference<String> sentBody = new AtomicReference<>();
            var request = stub(HttpRequest.class, Map.of("method", "POST", "path", "/old", "httpService", transport,
                    "headers", List.of(), "bodyToString", "cipher", "toByteArray", bytes, "bodyOffset", prefix.length()));
            var header1 = stub(burp.api.montoya.http.message.HttpHeader.class, Map.of("name", "Host", "value", "virtual.example"));
            var header2 = stub(burp.api.montoya.http.message.HttpHeader.class, Map.of("name", "X-Added", "value", "value"));
            var edited = (HttpRequest) Proxy.newProxyInstance(HttpRequest.class.getClassLoader(), new Class[]{HttpRequest.class}, (p, m, a) -> {
                if (m.getName().equals("withBody")) { sentBody.set(MontoyaByteArrayExtension.text(a[0])); return encrypted; }
                return Map.of("method", "PATCH", "path", "/new?x=1", "httpService", transport, "headers", List.of(header1, header2)).get(m.getName());
            });
            AtomicInteger sends = new AtomicInteger(), parses = new AtomicInteger();
            var service = new RuleProcessingService(null, null, null) {
                public boolean canPrepareEditedRequest(HttpRequestContext context) { return true; }
                public ProcessingOutcome processRequestForPhase(HttpRequestContext context, String content, String phase) {
                    if (phase.equals("display")) return ProcessingOutcome.success(plaintext, List.of("decrypt"), Map.of());
                    sends.incrementAndGet(); assertEquals("PATCH", context.getMethod());
                    assertEquals("/new", context.getUrl().getPath()); assertEquals("x=1", context.getUrl().getQuery());
                    assertEquals("virtual.example", context.getHeaders().get("Host"));
                    assertEquals("value", context.getHeaders().get("X-Added")); assertFalse(context.getHeaders().containsKey("X-Remove"));
                    assertEquals(plaintext, content); // Header-only edit must preserve exact raw plaintext.
                    return ProcessingOutcome.success("new-cipher", List.of("encrypt"), Map.of(), true);
                }
            };
            var editor = new PlaintextHttpRequestEditor(null, service, stub(EditorCreationContext.class, Map.of()), (svc, message) -> {
                parses.incrementAndGet(); assertSame(transport, svc); assertEquals(changedPrefix, message); return edited;
            });
            editor.setRequestResponse(stub(HttpRequestResponse.class, Map.of("request", request)));
            var view = (PlaintextMessageView) editor.uiComponent();
            view.textArea().replaceRange(changedPrefix, 0, prefix.length());
            assertTrue(editor.isModified()); assertEquals(changedPrefix, view.prefixText()); assertEquals(plaintext, view.bodyText());
            var menu = view.textArea().getComponentPopupMenu();
            ((JCheckBoxMenuItem)menu.getComponent(0)).doClick();
            ((JRadioButtonMenuItem)menu.getComponent(2)).doClick();
            assertEquals(plaintext, view.textArea().getText()); assertEquals(changedPrefix, view.prefixText());
            ((JCheckBoxMenuItem)menu.getComponent(0)).doClick();
            ((JRadioButtonMenuItem)menu.getComponent(1)).doClick();
            assertEquals(changedPrefix + JsonPresentation.pretty(plaintext), view.textArea().getText());
            assertSame(encrypted, editor.getRequest()); assertEquals("new-cipher", sentBody.get());
            assertEquals(1, sends.get()); assertEquals(1, parses.get());
            assertSame(encrypted, editor.getRequest()); assertEquals(1, sends.get());
        });
    }

    @Test void malformedFullRequestRetainsOriginalWithoutEncrypting() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            String prefix = "POST / HTTP/1.1\r\nHost: example.test\r\n\r\n";
            var bytes = stub(ByteArray.class, Map.of("getBytes", (prefix + "cipher").getBytes(StandardCharsets.ISO_8859_1)));
            var transport = stub(HttpService.class, Map.of("secure", true, "host", "example.test", "port", 443));
            var request = stub(HttpRequest.class, Map.of("method", "POST", "path", "/", "httpService", transport,
                    "headers", List.of(), "bodyToString", "cipher", "toByteArray", bytes, "bodyOffset", prefix.length()));
            AtomicInteger sends = new AtomicInteger();
            var service = new RuleProcessingService(null, null, null) {
                public boolean canPrepareEditedRequest(HttpRequestContext context) { return true; }
                public ProcessingOutcome processRequestForPhase(HttpRequestContext context, String content, String phase) {
                    if (phase.equals("display")) return ProcessingOutcome.success("{}", List.of("decrypt"), Map.of());
                    sends.incrementAndGet(); throw new AssertionError("Do not encrypt malformed HTTP");
                }
            };
            var editor = new PlaintextHttpRequestEditor(null, service, stub(EditorCreationContext.class, Map.of()), (svc, message) -> {
                throw new AssertionError("Do not parse invalid headers");
            });
            editor.setRequestResponse(stub(HttpRequestResponse.class, Map.of("request", request)));
            var view = (PlaintextMessageView)editor.uiComponent();
            view.textArea().replaceRange("bad request line\r\n", 0, prefix.indexOf("\r\n") + 2);
            assertSame(request, editor.getRequest()); assertTrue(editor.isModified());
            assertTrue(view.textArea().getToolTipText().contains("Invalid HTTP request line")); assertEquals(0, sends.get());
            view.textArea().replaceRange("POST / HTTP/1.1\r\nHost: example.test\r\n", 0, view.prefixText().length());
            assertSame(request, editor.getRequest()); assertTrue(view.textArea().getToolTipText().contains("blank line"));
        });
    }

}
