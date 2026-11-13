package com.universal.crypto.ui;

import com.universal.crypto.engine.RuleMatchEngine;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.engine.RuleConfigStorage;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleCondition;
import org.junit.jupiter.api.io.TempDir;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import com.universal.crypto.handler.HttpResponseContext;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorFactory;
import com.universal.crypto.processor.impl.CryptoProcessor;
import com.universal.crypto.util.LanguageManager;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ComponentEvent;
import java.lang.reflect.Field;
import java.net.URL;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class LiveTracePanelTest {
    @TempDir Path tempDir;
    private static final String CIPHER = "PCCgeqmQpzm3cOo62ZEfYjYBp8jqJlsWBx9w";

    private HttpResponseContext response(String nonce) throws Exception {
        return HttpResponseContext.builder().method("POST").url(new URL("https://api.example.test/api/demo"))
                .headers(Map.of("Content-Type", "application/json", "Content-Length", "36"))
                .requestHeaders(Map.of("X-Nonce", nonce)).body(CIPHER).statusCode(200).toolSource("PROXY").messageId(42).build();
    }

    private ProcessingAction decrypt() {
        var action = new ProcessingAction("decrypt", "body", "script");
        action.setConfig(Constants.ConfigKey.EXECUTION_PHASE, "response-display");
        action.setConfig(Constants.ConfigKey.SCRIPT_CODE,
                "return Bytes.text(Crypto.aesGcmDecrypt(Bytes.fromBase64('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='),"
                        + "Bytes.fromBase64('AAECAwQFBgcICQoL'),Bytes.fromBase64(content),"
                        + "Bytes.utf8(request.getMethod()+'|'+request.getPath()+'|'+request.getOriginalHeader('X-Nonce'))));");
        return action;
    }

    @Test void previewDecryptsRealGcmWithOriginalRequestAadAndLeavesWireIntact() throws Exception {
        var context = response("nonce-one");
        byte[] original = context.getBodyBytes();
        var text = LiveTracePanel.plaintextPreview(context, List.of(decrypt()), ProcessorFactory.createDefaultProcessorManager(null), LanguageManager.getInstance());
        assertTrue(text.contains("\"value\" : 1"), text);
        assertTrue(text.contains("response-display"));
        assertFalse(text.contains("Content-Length"), "Preview must not present ciphertext length as a plaintext HTTP header");
        assertArrayEquals(original, context.getBodyBytes());
        assertEquals("36", context.getHeaderIgnoreCase("Content-Length"));
    }

    @Test void wrongAadAndMissingDisplayActionsDoNotClaimPlaintextSuccess() throws Exception {
        var lang = LanguageManager.getInstance();
        var processors = ProcessorFactory.createDefaultProcessorManager(null);
        var failed = LiveTracePanel.plaintextPreview(response("wrong"), List.of(decrypt()), processors, lang);
        assertTrue(failed.startsWith(lang.getString("trace.preview.failed")), failed);
        assertFalse(failed.contains("\"value\""));
        var editorOnly = decrypt(); editorOnly.setConfig(Constants.ConfigKey.EXECUTION_PHASE, "response-editor-send");
        assertTrue(LiveTracePanel.plaintextPreview(response("nonce-one"), List.of(editorOnly), processors, lang)
                .startsWith(lang.getString("trace.preview.no_actions")));
    }

    @Test void externalCryptoIsExplicitlyUnverifiedAndNeverCalled() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        var processors = ProcessorFactory.createDefaultProcessorManager(new CryptoProcessor.ApiClient() {
            @Override public boolean isAvailable() { return true; }
            @Override public CryptoProcessor.ApiResponse processRequest(CryptoProcessor.ApiRequest request) {
                calls.incrementAndGet(); throw new AssertionError("No network call permitted in preview");
            }
        });
        var action = new ProcessingAction("decrypt", "body", "crypto");
        action.setConfig(Constants.ConfigKey.EXECUTION_PHASE, "response-display");
        action.setConfig(Constants.ConfigKey.CRYPTO_PROVIDER, "external");
        String text = LiveTracePanel.plaintextPreview(response("nonce-one"), List.of(action), processors, LanguageManager.getInstance());
        assertTrue(text.startsWith(LanguageManager.getInstance().getString("trace.preview.failed")), text);
        assertEquals(0, calls.get());
    }

    @Test void observedResponseAndResponseActionHaveTruthfulDirectionAndResult() throws Exception {
        var original = response("nonce-one");
        var observed = new LiveTracePanel.TraceEntry(1, "12:00:00", "POST", "https://example.test", "Response Observed", "decrypt [response-display]", original, original);
        assertEquals("trace.result.unchanged", observed.resultKey());
        assertEquals(LanguageManager.getInstance().getString("trace.flow.response"), observed.flowLabel());
        var action = new LiveTracePanel.TraceEntry(2, "12:00:00", "POST", "https://example.test", "Action Changed", "sign", original, original.withHeader("X-Sign", "signed"));
        assertEquals(LanguageManager.getInstance().getString("trace.flow.response"), action.flowLabel());
        assertEquals("trace.result.action_changed", action.resultKey());
        var failed = new LiveTracePanel.TraceEntry(3, "12:00:00", "POST", "https://example.test", "Action Failed", "decrypt", original, original);
        assertEquals("trace.result.failed", failed.resultKey());
    }

    @Test void incomingRowsKeepSelectedSnapshotsAndNumericSequenceSort() throws Exception {
        LiveTracePanel[] holder = new LiveTracePanel[1];
        SwingUtilities.invokeAndWait(() -> holder[0] = new LiveTracePanel(null, new RuleMatchEngine(), ProcessorFactory.createDefaultProcessorManager(null)));
        var panel = holder[0];
        var original = response("nonce-one");
        panel.addLogEntry("POST", "https://first.example.test", "Response Observed", "decrypt [response-display]", original, original);
        SwingUtilities.invokeAndWait(() -> {});
        SwingUtilities.invokeAndWait(() -> get(panel, "logTable", JTable.class).setRowSelectionInterval(0, 0));
        for (int i=0; i<11; i++) panel.addLogEntry("POST", "https://next.example.test/"+i, "Response Observed", "match", original, original);
        SwingUtilities.invokeAndWait(() -> {
            var table = get(panel, "logTable", JTable.class);
            assertEquals(1L, table.getValueAt(table.getSelectedRow(), 0));
            assertTrue(get(panel,"summaryArea",JTextArea.class).getText().contains("https://first.example.test"));
            assertEquals(get(panel,"originalArea",JTextArea.class).getText(), get(panel,"modifiedArea",JTextArea.class).getText());
            assertFalse(get(panel,"originalArea",JTextArea.class).getText().contains("HTTP/2"), "Protocol version was not captured");
            table.getRowSorter().toggleSortOrder(0);
            assertEquals(1L, table.getValueAt(0, 0));
            assertEquals(12L, table.getValueAt(11, 0));
            panel.refresh();
            assertEquals(12, table.getRowCount());
            assertTrue(get(panel,"summaryArea",JTextArea.class).getText().contains("https://first.example.test"));
        });
    }

    @Test void plaintextTabRunsAsynchronouslyOnlyWhenOpenedAndKeepsCiphertextSnapshot() throws Exception {
        var manager = new RuleManager(new RuleConfigStorage(tempDir.toString()));
        var rule = new ProcessingRule("preview", "Preview", true, 1);
        rule.setCondition(new RuleCondition()); rule.addResponseAction(decrypt()); manager.addRule(rule);
        LiveTracePanel[] holder = new LiveTracePanel[1];
        SwingUtilities.invokeAndWait(() -> holder[0] = new LiveTracePanel(manager, new RuleMatchEngine(), ProcessorFactory.createDefaultProcessorManager(null)));
        var panel = holder[0]; var context = response("nonce-one");
        panel.addLogEntry("POST", context.getUrl().toString(), "Response Observed", "decrypt [response-display]", context, context);
        CountDownLatch ready = new CountDownLatch(1);
        SwingUtilities.invokeAndWait(() -> {
            get(panel,"logTable",JTable.class).setRowSelectionInterval(0,0);
            assertNull(get(panel,"previewWorker",SwingWorker.class), "Selecting a wire record must not run scripts");
            var area = get(panel,"plaintextArea",JTextArea.class);
            area.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                private void check() { if (area.getText().contains("\"value\" : 1")) ready.countDown(); }
                public void insertUpdate(javax.swing.event.DocumentEvent event) { check(); }
                public void removeUpdate(javax.swing.event.DocumentEvent event) { check(); }
                public void changedUpdate(javax.swing.event.DocumentEvent event) { check(); }
            });
            get(panel,"outputTabs",JTabbedPane.class).setSelectedIndex(1);
        });
        assertTrue(ready.await(5, TimeUnit.SECONDS), "Real display phase should publish plaintext on the EDT");
        SwingUtilities.invokeAndWait(() -> {
            assertTrue(get(panel,"modifiedArea",JTextArea.class).getText().contains(CIPHER));
            var tabs = get(panel,"outputTabs",JTabbedPane.class); tabs.setSelectedIndex(0); tabs.setSelectedIndex(1);
            assertNull(get(panel,"previewWorker",SwingWorker.class), "Reopening the preview uses the record cache");
            assertTrue(get(panel,"plaintextArea",JTextArea.class).getText().contains("\"value\" : 1"));
        });
        assertEquals(CIPHER, context.getBody());
    }

    @Test void languageRefreshUpdatesExistingRowsAndKeepsSelection() throws Exception {
        var lang=LanguageManager.getInstance();String previous=lang.getCurrentLocale().getLanguage();
        LiveTracePanel[] holder=new LiveTracePanel[1];
        SwingUtilities.invokeAndWait(()->holder[0]=new LiveTracePanel(null,new RuleMatchEngine(),ProcessorFactory.createDefaultProcessorManager(null)));
        var context=response("nonce-one");holder[0].addLogEntry("POST","https://example.test/lang","Response Observed","display",context,context);
        SwingUtilities.invokeAndWait(()->{
            var panel=holder[0];var table=get(panel,"logTable",JTable.class);table.setRowSelectionInterval(0,0);
            try {
                lang.setLanguage("zh");panel.refresh();
                assertEquals("响应",table.getValueAt(0,2));assertEquals("转发数据未改变",table.getValueAt(0,5));
                assertEquals(1L,table.getValueAt(table.getSelectedRow(),0));
            } finally { lang.setLanguage(previous); }
        });
    }

    @Test void initialLayoutReservesHalfHeightForReadableDetails() throws Exception {
        var context = response("nonce-one");
        LiveTracePanel[] holder = new LiveTracePanel[1];
        SwingUtilities.invokeAndWait(() -> {
            holder[0] = new LiveTracePanel(null, new RuleMatchEngine(), ProcessorFactory.createDefaultProcessorManager(null));
            holder[0].setSize(1280, 820);
        });
        var panel = holder[0];
        for (int i=0; i<22; i++) panel.addLogEntry("POST", "https://api.example.test/api/demo", "Response Observed", "Response rule: decrypt body [response-display]; encrypt body [response-editor-send]", context, context);
        SwingUtilities.invokeAndWait(() -> {
            layout(panel);
            var split = get(panel, "mainSplit", JSplitPane.class);
            split.dispatchEvent(new ComponentEvent(split, ComponentEvent.COMPONENT_RESIZED));
            layout(panel);
            assertTrue(split.getDividerLocation() > split.getHeight()*0.40);
            assertTrue(split.getDividerLocation() < split.getHeight()*0.60);
            assertTrue(split.getBottomComponent().getHeight() > 280);
            var detailPanel = (Container) split.getBottomComponent();
            var horizontal = java.util.Arrays.stream(detailPanel.getComponents()).filter(c -> c instanceof JSplitPane).map(c -> (JSplitPane)c).findFirst().orElseThrow();
            horizontal.dispatchEvent(new ComponentEvent(horizontal, ComponentEvent.COMPONENT_RESIZED));
            layout(panel);
            assertTrue(horizontal.getDividerLocation() > horizontal.getWidth()*0.40);
            assertTrue(horizontal.getDividerLocation() < horizontal.getWidth()*0.60);
            var table = get(panel,"logTable",JTable.class);
            table.setRowSelectionInterval(0,0);
            get(panel,"plaintextArea",JTextArea.class).setText(LiveTracePanel.plaintextPreview(context,List.of(decrypt()),ProcessorFactory.createDefaultProcessorManager(null),LanguageManager.getInstance()));
            layout(panel);
            var image = new java.awt.image.BufferedImage(1280,820,java.awt.image.BufferedImage.TYPE_INT_RGB);
            var graphics=image.createGraphics();panel.printAll(graphics);graphics.dispose();
            try { javax.imageio.ImageIO.write(image,"png",Path.of("target/live-trace-layout.png").toFile()); }
            catch (Exception ex) { throw new RuntimeException(ex); }
        });
    }

    @Test void clearingSelectionClearsDetailsAndDisablesPreview() throws Exception {
        var context=response("nonce-one");LiveTracePanel[] holder=new LiveTracePanel[1];
        SwingUtilities.invokeAndWait(()->holder[0]=new LiveTracePanel(null,new RuleMatchEngine(),ProcessorFactory.createDefaultProcessorManager(null)));
        holder[0].addLogEntry("POST","https://example.test","Response Observed","display",context,context);
        SwingUtilities.invokeAndWait(()->{
            var panel=holder[0];var table=get(panel,"logTable",JTable.class);table.setRowSelectionInterval(0,0);
            assertTrue(get(panel,"previewButton",JButton.class).isEnabled());
            assertFalse(get(panel,"originalArea",JTextArea.class).getText().isBlank());
            table.clearSelection();
            assertEquals("",get(panel,"originalArea",JTextArea.class).getText());
            assertEquals("",get(panel,"modifiedArea",JTextArea.class).getText());
            assertEquals("",get(panel,"summaryArea",JTextArea.class).getText());
            assertFalse(get(panel,"previewButton",JButton.class).isEnabled());
            assertFalse(get(panel,"rerunButton",JButton.class).isEnabled());
        });
    }

    @Test void intermediateSnapshotDoesNotReplayCompleteDecryptionPipeline() throws Exception {
        var context=response("nonce-one");LiveTracePanel[] holder=new LiveTracePanel[1];
        SwingUtilities.invokeAndWait(()->holder[0]=new LiveTracePanel(null,new RuleMatchEngine(),ProcessorFactory.createDefaultProcessorManager(null)));
        holder[0].addLogEntry("POST","https://example.test","Action Changed","decrypt",context,context.withBody("{\"value\":1}"));
        SwingUtilities.invokeAndWait(()->{
            var panel=holder[0];get(panel,"logTable",JTable.class).setRowSelectionInterval(0,0);
            get(panel,"outputTabs",JTabbedPane.class).setSelectedIndex(1);
            assertNull(get(panel,"previewWorker",SwingWorker.class));
            assertFalse(get(panel,"previewButton",JButton.class).isEnabled());
            assertEquals(LanguageManager.getInstance().getString("trace.preview.action_snapshot"),get(panel,"plaintextArea",JTextArea.class).getText());
        });
    }

    private static void layout(Container container) {
        container.doLayout();
        for (Component child : container.getComponents()) if (child instanceof Container nested) layout(nested);
    }
    private static <T> T get(Object object, String name, Class<T> type) {
        try { Field field=object.getClass().getDeclaredField(name); field.setAccessible(true); return type.cast(field.get(object)); }
        catch (Exception ex) { throw new RuntimeException(ex); }
    }
}
