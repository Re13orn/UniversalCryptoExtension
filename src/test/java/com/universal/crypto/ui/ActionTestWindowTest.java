package com.universal.crypto.ui;

import com.universal.crypto.model.ProcessingAction;
import org.junit.jupiter.api.Test;
import javax.swing.*;
import java.awt.GraphicsEnvironment;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

class ActionTestWindowTest {
    @Test void testRunsTheCompleteDraftInAnOwnedWindowAndKeepsBothEditorsOpen() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        var owner = new JDialog();
        var original = new ProcessingAction("execute", "variable", "token", "script");
        original.setConfig(Map.of("scriptCode", "return content + '-tested';", "inputSource", "header", "inputName", "X-Token",
                "variableName", "token", "executionPhase", "always", "editorOnly", true, "customFlag", 128));
        var preview = new AtomicReference<StepFlowPreviewDialog>();
        var editor = new ActionEditDialog(owner, original, false, (ActionTestNavigator) (currentOwner, draft, response) -> {
            preview.set(UniversalCryptoTab.createActionTestDialog(currentOwner, draft, response));
        });
        CountDownLatch complete = new CountDownLatch(1);
        try {
            SwingUtilities.invokeAndWait(() -> {
                owner.addNotify(); editor.addNotify();
                field(editor, "targetNameField", JTextField.class).setText("editedToken");
                invoke(editor, "showTestDialog");
                var dialog = preview.get(); assertNotNull(dialog); assertSame(editor, dialog.getOwner());
                assertTrue(dialog.isModal()); assertEquals("editor-send", field(dialog, "phaseBox", JComboBox.class).getSelectedItem());
                field(dialog, "headersArea", JTextArea.class).setText("X-Token: actual");
                var trace = field(dialog, "traceArea", JTextArea.class);
                trace.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                    private void check() { if (trace.getText().contains("actual-tested")) complete.countDown(); }
                    public void insertUpdate(javax.swing.event.DocumentEvent e) { check(); }
                    public void removeUpdate(javax.swing.event.DocumentEvent e) { check(); }
                    public void changedUpdate(javax.swing.event.DocumentEvent e) { check(); }
                });
                invoke(dialog, "runPreview");
            });
            assertTrue(complete.await(5, TimeUnit.SECONDS), "Actual ActionPipeline must select the configured header input");
            SwingUtilities.invokeAndWait(() -> {
                assertTrue(owner.isDisplayable()); assertTrue(editor.isDisplayable()); assertFalse(editor.isConfirmed());
                assertEquals("token", original.getConfigString("variableName")); assertEquals(128, original.getConfig("customFlag"));
            });
        } finally { SwingUtilities.invokeAndWait(() -> { if (preview.get() != null) preview.get().dispose(); editor.dispose(); owner.dispose(); }); }
    }

    @Test void responseTestsKeepResponseDirectionAndTheirConfiguredPhase() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        SwingUtilities.invokeAndWait(() -> {
            var action = new ProcessingAction("encrypt", "body", "script");
            action.setConfig(Map.of("executionPhase", "response-editor-send", "scriptCode", "return content;"));
            var dialog = UniversalCryptoTab.createActionTestDialog(null, action, true);
            try {
                assertEquals("response-editor-send", field(dialog, "phaseBox", JComboBox.class).getSelectedItem());
                assertEquals(Boolean.FALSE, field(dialog, "requestFlow", Boolean.class));
                assertNotNull(field(dialog, "requestHeadersArea", JTextArea.class));
            } finally { dialog.dispose(); }
        });
    }

    private static void invoke(Object object, String name) {
        try { var method = object.getClass().getDeclaredMethod(name); method.setAccessible(true); method.invoke(object); }
        catch (Exception error) { throw new RuntimeException(error); }
    }
    private static <T> T field(Object object, String name, Class<T> type) {
        try { Field value = object.getClass().getDeclaredField(name); value.setAccessible(true); return type.cast(value.get(object)); }
        catch (Exception error) { throw new RuntimeException(error); }
    }
}
