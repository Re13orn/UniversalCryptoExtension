package com.universal.crypto.ui.editor;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.extension.*;
import com.universal.crypto.engine.RuleProcessingService;
import com.universal.crypto.handler.HttpResponseContext;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;
class PlaintextHttpResponseEditorTest {
    @SuppressWarnings("unchecked") private <T> T stub(Class<T> type, Map<String,Object> values) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class[]{type}, (p,m,a) -> values.get(m.getName()));
    }
    @Test void enablingDoesNotExecuteAndDisplayPreservesOriginal() {
        AtomicInteger executions = new AtomicInteger();
        RuleProcessingService service = new RuleProcessingService(null,null,null) {
            public boolean shouldProvidePlaintextResponseEditor(HttpResponseContext context) { return context != null; }
            public ProcessingOutcome processResponseForPhase(HttpResponseContext context, String content, String phase) {
                executions.incrementAndGet(); assertEquals("response-display", phase);
                assertEquals("hello", context.getOriginalHeader("x-test-probe"));
                assertEquals(null, context.getHeaderIgnoreCase("X-Test-Probe"));
                return ProcessingOutcome.success("plaintext", List.of("test:decrypt"), Map.of());
            }
        };
        var requestHeader = stub(burp.api.montoya.http.message.HttpHeader.class, Map.of("name", "X-Test-Probe", "value", "hello"));
        HttpRequest request = stub(HttpRequest.class, Map.of("url", "https://example.com/path", "method", "GET", "headers", List.of(requestHeader)));
        ByteArray bytes = stub(ByteArray.class, Map.of("getBytes", new byte[]{1,2,3}));
        String prefix = "HTTP/2 200 OK\r\nX-Test: original\r\n\r\n";
        ByteArray raw = stub(ByteArray.class, Map.of("getBytes", (prefix + "cipher").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
        HttpResponse response = stub(HttpResponse.class, Map.of("headers",List.of(),"body", bytes,"statusCode",(short)200,"toByteArray",raw,"bodyOffset",prefix.length()));
        HttpRequestResponse message = stub(HttpRequestResponse.class, Map.of("request",request,"response",response));
        ExtensionProvidedHttpResponseEditor editor = new PlaintextHttpResponseEditorProvider(service).provideHttpResponseEditor(stub(EditorCreationContext.class,Map.of()));
        assertTrue(editor.isEnabledFor(message)); assertEquals(0,executions.get());
        editor.setRequestResponse(message);
        assertEquals(1,executions.get()); assertSame(response,editor.getResponse()); assertFalse(editor.isModified());
        PlaintextMessageView view = (PlaintextMessageView) editor.uiComponent();
        assertEquals(prefix + "plaintext", view.textArea().getText());
        var toggle = (javax.swing.JCheckBoxMenuItem) view.textArea().getComponentPopupMenu().getComponent(0);
        assertTrue(toggle.isSelected()); toggle.doClick();
        assertEquals("plaintext", view.textArea().getText());
        assertSame(response,editor.getResponse()); assertFalse(editor.isModified());
        assertFalse(view.textArea().isEditable()); assertEquals(1, executions.get());
    }
}
