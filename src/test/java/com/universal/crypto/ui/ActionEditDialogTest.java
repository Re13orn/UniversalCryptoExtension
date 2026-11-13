package com.universal.crypto.ui;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.ui.processor.FieldConfigPanel;
import com.universal.crypto.ui.processor.ProcessorConfigUI;
import com.universal.crypto.ui.processor.SignatureConfigPanel;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

class ActionEditDialogTest {

    @Test
    void changingActionTypeToSignSwitchesProcessorAndConfigPanel() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        ActionEditDialog dialog = new ActionEditDialog(null, null, false, null);
        try {
            JComboBox<String> actionTypeCombo = combo(dialog, "actionTypeCombo");
            actionTypeCombo.setSelectedItem(Constants.ActionType.SIGN);

            assertEquals(Constants.ProcessorType.SIGNATURE, combo(dialog, "processorCombo").getSelectedItem());
            assertEquals(Constants.TargetType.HEADER, combo(dialog, "targetTypeCombo").getSelectedItem());
            assertEquals("X-Signature", text(dialog, "targetNameField").getText());
            assertTrue(field(dialog, "currentProcessorUI", ProcessorConfigUI.class) instanceof SignatureConfigPanel);
            assertTrue(check(dialog, "phaseSendCheck").isSelected());
        } finally {
            dialog.dispose();
        }
    }

    @Test
    void changingActionTypeToReplaceSwitchesProcessorAndConfigPanel() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        ActionEditDialog dialog = new ActionEditDialog(null, null, false, null);
        try {
            JComboBox<String> actionTypeCombo = combo(dialog, "actionTypeCombo");
            actionTypeCombo.setSelectedItem(Constants.ActionType.REPLACE);

            assertEquals(Constants.ProcessorType.FIELD, combo(dialog, "processorCombo").getSelectedItem());
            assertEquals(Constants.TargetType.FIELD, combo(dialog, "targetTypeCombo").getSelectedItem());
            assertTrue(field(dialog, "currentProcessorUI", ProcessorConfigUI.class) instanceof FieldConfigPanel);
            assertTrue(check(dialog, "phaseSendCheck").isSelected());
        } finally {
            dialog.dispose();
        }
    }

    @Test
    void editingExistingActionKeepsStoredProcessorChoice() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        ProcessingAction existing = new ProcessingAction(Constants.ActionType.SIGN, Constants.TargetType.HEADER,
                "X-Test", Constants.ProcessorType.SCRIPT);
        ActionEditDialog dialog = new ActionEditDialog(null, existing, false, null);
        try {
            assertEquals(Constants.ActionType.SIGN, combo(dialog, "actionTypeCombo").getSelectedItem());
            assertEquals(Constants.ProcessorType.SCRIPT, combo(dialog, "processorCombo").getSelectedItem());
        } finally {
            dialog.dispose();
        }
    }

    @Test void editorOnlyAndTypedExtraOptionsSurviveActionEditing() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        ProcessingAction existing=new ProcessingAction("encrypt","body","script");
        existing.setConfig("scriptCode","return content + '-encrypted';");
        existing.setConfig("executionPhase","editor-send");existing.setConfig("editorOnly",true);
        existing.setConfig("customFlag",true);existing.setConfig("customNumber",128);
        ActionEditDialog dialog=new ActionEditDialog(null,existing,false,null);
        try {
            assertTrue(check(dialog,"editorOnlyCheck").isSelected());
            var save=ActionEditDialog.class.getDeclaredMethod("saveAction");save.setAccessible(true);save.invoke(dialog);
            assertTrue(dialog.isConfirmed());
            assertEquals(Boolean.TRUE,dialog.getAction().getConfig("editorOnly"));
            assertEquals(Boolean.TRUE,dialog.getAction().getConfig("customFlag"));
            assertEquals(128,dialog.getAction().getConfig("customNumber"));
        }finally{dialog.dispose();}
    }

    @Test void testConfigurationUsesTheCompleteDraftAndKeepsUnsavedNestedEditorsOpen() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        SwingUtilities.invokeAndWait(() -> {
            var owner = new JDialog();
            var original = new ProcessingAction("execute", "variable", "token", "script");
            original.setEnabled(false); original.setDescription("existing metadata");
            original.setConfig(java.util.Map.of("scriptCode", "return content;", "variableName", "token",
                    "inputSource", "header", "inputName", "X-Token", "executionPhase", "send",
                    "editorOnly", true, "customFlag", 128));
            var captured = new java.util.concurrent.atomic.AtomicReference<ProcessingAction>();
            var dialog = new ActionEditDialog(owner, original, false, captured::set);
            owner.addNotify(); dialog.addNotify();
            try {
                text(dialog, "targetNameField").setText("editedToken");
                JTable table = field(dialog, "extraConfigTable", JTable.class);
                assertTrue(table.editCellAt(0, 1));
                ((JTextField) table.getEditorComponent()).setText("edited extra value");
                var test = ActionEditDialog.class.getDeclaredMethod("showTestDialog"); test.setAccessible(true); test.invoke(dialog);
                assertFalse(table.isEditing());
                assertEquals(dialog.buildAction(), captured.get());
                assertEquals("editedToken", captured.get().getConfigString("variableName"));
                assertEquals("X-Token", captured.get().getConfigString("inputName"));
                assertEquals("edited extra value", captured.get().getConfig("customFlag"));
                assertEquals(Boolean.TRUE, captured.get().getConfig("editorOnly"));
                assertEquals("send", captured.get().getConfigString("executionPhase"));
                assertFalse(captured.get().isEnabled());
                assertTrue(dialog.isDisplayable()); assertTrue(owner.isDisplayable()); assertFalse(dialog.isConfirmed());
                assertEquals("token", original.getConfigString("variableName")); assertEquals(128, original.getConfig("customFlag"));
            } catch (Exception ex) { throw new RuntimeException(ex); }
            finally { dialog.dispose(); owner.dispose(); }
        });
    }

    @SuppressWarnings("unchecked")
    private JComboBox<String> combo(ActionEditDialog dialog, String name) throws Exception {
        return (JComboBox<String>) field(dialog, name, JComboBox.class);
    }

    private JTextField text(ActionEditDialog dialog, String name) throws Exception {
        return field(dialog, name, JTextField.class);
    }

    private JCheckBox check(ActionEditDialog dialog, String name) throws Exception {
        return field(dialog, name, JCheckBox.class);
    }

    private <T> T field(Object target, String name, Class<T> type) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return type.cast(field.get(target));
    }
}
