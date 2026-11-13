package com.universal.crypto.ui.editor;

import org.junit.jupiter.api.Test;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.TokenTypes;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class PlaintextMessageViewTest {
    @Test void undoBackToPrettyBaselineRestoresExactRawTextAndClearsContentChanges() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var view = new PlaintextMessageView();
            String raw = " {\"value\":1e+02} "; view.setBodyText(raw); view.setBodyEditable(true);
            var text = (org.fife.ui.rsyntaxtextarea.RSyntaxTextArea)view.textArea();
            int n = text.getText().indexOf("1e+02"); text.replaceRange("2e+02",n,n+5);
            assertTrue(view.isContentModified()); assertTrue(view.bodyText().contains("2e+02"));
            while (text.canUndo()) text.undoLastAction();
            assertFalse(view.isContentModified()); assertEquals(raw,view.bodyText());
        });
    }

    @Test void checkedHeadersRemainVisibleWhenHostBodyOffsetIsZero() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            String prefix = "POST /register HTTP/1.1\r\nHost: example.test\r\nX-Repeat: a\r\nX-Repeat: b\r\n\r\n";
            var bytes = proxy(burp.api.montoya.core.ByteArray.class, java.util.Map.of("getBytes", (prefix + "cipher").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
            var request = proxy(burp.api.montoya.http.message.requests.HttpRequest.class,
                    java.util.Map.of("toByteArray", bytes, "bodyOffset", 0));
            var view = new PlaintextMessageView(); view.setOriginalMessage(request); view.setBodyText("{}");
            assertTrue(view.textArea().getText().startsWith(prefix)); assertEquals("{}", view.bodyText());
            var toggle = (JCheckBoxMenuItem)view.textArea().getComponentPopupMenu().getComponent(0);
            assertTrue(toggle.isSelected()); toggle.doClick(); assertEquals("{}", view.textArea().getText());
            toggle.doClick(); assertTrue(view.textArea().getText().startsWith(prefix));
        });
    }

    @Test void structuredHeadersAreUsedWhenSerializationOnlyContainsBody() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var bytes = proxy(burp.api.montoya.core.ByteArray.class, java.util.Map.of("getBytes", "cipher".getBytes()));
            var host = proxy(burp.api.montoya.http.message.HttpHeader.class, java.util.Map.of("name", "Host", "value", "example.test"));
            var request = proxy(burp.api.montoya.http.message.requests.HttpRequest.class,
                    java.util.Map.of("toByteArray", bytes, "bodyOffset", 0, "method", "POST", "path", "/register", "httpVersion", "HTTP/2", "headers", java.util.List.of(host)));
            var view = new PlaintextMessageView(); view.setOriginalMessage(request); view.setBodyText("{}");
            assertEquals("POST /register HTTP/2\r\nHost: example.test\r\n\r\n{}", view.textArea().getText());
            assertEquals("{}", view.bodyText()); assertFalse(view.headersChanged());
        });
    }

    @Test void displayPrefixDoesNotChangeOriginalHeaderBaseline() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            String original = "GET / HTTP/1.1\r\nHost: api.example.test\r\n"
                    + "Referer: https://staging.example.test/path\r\n\r\n";
            String display = original.replace("staging.example.test", "example.test");
            var bytes = proxy(burp.api.montoya.core.ByteArray.class,
                    java.util.Map.of("getBytes", (original + "abc").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
            var request = proxy(burp.api.montoya.http.message.requests.HttpRequest.class,
                    java.util.Map.of("toByteArray", bytes, "bodyOffset", original.length()));

            var view = new PlaintextMessageView();
            view.setOriginalMessage(request);
            view.setDisplayPrefix(display);
            view.setBodyText("abc");

            assertEquals(original, view.originalPrefix());
            assertEquals(display + "abc", view.textArea().getText());
            assertFalse(view.headersChanged());
            assertEquals("abc", view.bodyText());
        });
    }

    private static <T> T proxy(Class<T> type, java.util.Map<String,Object> values) {
        return type.cast(java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(), new Class[]{type}, (p,m,a) -> {
            if (values.containsKey(m.getName())) return values.get(m.getName());
            if (m.getReturnType() == int.class) return 0;
            if (m.getReturnType() == boolean.class) return false;
            return null;
        }));
    }

    @Test void presentationRetainsExactRawAndOnlyEditsChangeTheBody() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var view = new PlaintextMessageView();
            String body = " {\"a\":1e+02,\"a\":-0,\"s\":\"a\\\\b\\\"c\",\"empty\":[],\"nested\":{\"ok\":true}} \r\n";
            AtomicInteger edits = new AtomicInteger();
            view.textArea().getDocument().addDocumentListener(new DocumentListener() {
                public void insertUpdate(DocumentEvent e) { changed(); }
                public void removeUpdate(DocumentEvent e) { changed(); }
                public void changedUpdate(DocumentEvent e) { changed(); }
                private void changed() { if (!view.isRendering()) edits.incrementAndGet(); }
            });
            view.setBodyText(body);
            assertTrue(view.textArea().getText().contains("\n  \"a\": 1e+02,"));
            assertTrue(view.textArea().getText().contains("\"a\": -0"));
            assertEquals(body, view.bodyText());
            JPopupMenu menu = view.textArea().getComponentPopupMenu();
            ((JRadioButtonMenuItem) menu.getComponent(2)).doClick();
            assertEquals(body, view.textArea().getText());
            ((JRadioButtonMenuItem) menu.getComponent(1)).doClick();
            assertEquals(body, view.bodyText()); assertEquals(0, edits.get());
            view.textArea().setEditable(true);
            int offset = view.textArea().getText().indexOf("1e+02");
            view.textArea().select(offset, offset + 5); view.textArea().replaceSelection("2e+02");
            String edited = view.bodyText(); assertTrue(edited.contains("2e+02"));
            ((JRadioButtonMenuItem) menu.getComponent(2)).doClick();
            assertEquals(edited, view.textArea().getText());
            ((JRadioButtonMenuItem) menu.getComponent(1)).doClick();
            assertEquals(edited, view.bodyText());
            assertTrue(edits.get() > 0);
            assertFalse(((RSyntaxTextArea) view.textArea()).canUndo());
        });
    }

    @Test void invalidAndNonJsonBodiesStayLiteralAndJsonTokensAreColored() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var view = new PlaintextMessageView();
            for (String body : new String[]{"plain", "{bad}", "{\"a\":1} trailing", "\"scalar\"", ""}) {
                view.setBodyText(body); assertEquals(body, view.textArea().getText()); assertEquals(body, view.bodyText());
            }
            view.setBodyText("{\"text\":\"value\",\"number\":42,\"bool\":true}");
            var area = (RSyntaxTextArea) view.textArea();
            boolean string = false, number = false;
            for (int line = 0; line < area.getLineCount(); line++) {
                for (var token = area.getTokenListForLine(line); token != null && token.isPaintable(); token = token.getNextToken()) {
                    string |= token.getType() == TokenTypes.LITERAL_STRING_DOUBLE_QUOTE;
                    number |= token.getType() == TokenTypes.LITERAL_NUMBER_DECIMAL_INT || token.getType() == TokenTypes.LITERAL_NUMBER_FLOAT;
                }
            }
            assertTrue(string); assertTrue(number);
        });
    }

    @Test void formatterPreservesEscapesEmptyContainersAndDuplicates() {
        assertEquals("{\n  \"x\": {},\n  \"x\": [],\n  \"n\": 1.2300e-5,\n  \"s\": \"\\u0041 a\\n\"\n}",
                JsonPresentation.pretty("{\"x\":{},\"x\":[],\"n\":1.2300e-5,\"s\":\"\\u0041 a\\n\"}"));
        assertNull(JsonPresentation.pretty("{\"a\":1,}"));
    }
    @Test void bothEditorsUseBurpFontAndRefreshWithoutChangingPlaintext() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var font = new java.util.concurrent.atomic.AtomicReference<>(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 15).deriveFont(15.5f));
            var ui = (burp.api.montoya.ui.UserInterface) java.lang.reflect.Proxy.newProxyInstance(
                    getClass().getClassLoader(), new Class[]{burp.api.montoya.ui.UserInterface.class},
                    (p, m, a) -> m.getName().equals("currentEditorFont") ? font.get() : null);
            var api = (burp.api.montoya.MontoyaApi) java.lang.reflect.Proxy.newProxyInstance(
                    getClass().getClassLoader(), new Class[]{burp.api.montoya.MontoyaApi.class},
                    (p, m, a) -> m.getName().equals("userInterface") ? ui : null);
            var request = new PlaintextHttpRequestEditor(api, null, null);
            var response = new PlaintextHttpResponseEditorProvider(api, null).provideHttpResponseEditor(null);
            for (var component : new java.awt.Component[]{request.uiComponent(), response.uiComponent()}) {
                var view = (PlaintextMessageView) component;
                var area = (RSyntaxTextArea) view.textArea();
                assertEquals(font.get(), area.getFont());
                view.setBodyText(" {\"number\":1e+02} ");
                String body = view.bodyText(), display = area.getText();
                // Token fonts must not introduce bold text or a different point size.
                for (var style : area.getSyntaxScheme().getStyles()) if (style != null) assertEquals(font.get(), style.font);
                java.awt.Font changed = new java.awt.Font("DialogInput", java.awt.Font.PLAIN, 18);
                font.set(changed); view.setOriginalMessage(null);
                assertEquals(changed, area.getFont());
                var scroll = (org.fife.ui.rtextarea.RTextScrollPane) view.getComponent(0);
                assertEquals(changed, scroll.getGutter().getLineNumberFont());
                for (var style : area.getSyntaxScheme().getStyles()) if (style != null) assertEquals(changed, style.font);
                assertEquals(body, view.bodyText()); assertEquals(display, area.getText());
                font.set(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 15).deriveFont(15.5f));
            }
            assertFalse(request.isModified()); assertFalse(response.isModified());
        });
    }

}
