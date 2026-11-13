package com.universal.crypto.ui.processor;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.lang.reflect.Field;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScriptConfigPanelTest {
    private String previousLanguage;
    @org.junit.jupiter.api.BeforeEach void useChineseHelp() {
        previousLanguage = com.universal.crypto.util.LanguageManager.getInstance().getCurrentLocale().getLanguage();
        com.universal.crypto.util.LanguageManager.getInstance().setLanguage("zh");
    }
    @org.junit.jupiter.api.AfterEach void restoreLanguage() {
        com.universal.crypto.util.LanguageManager.getInstance().setLanguage(previousLanguage);
    }


    @Test
    void scriptPanelExplainsRuntimeObjectsAndAppliesTemplates() throws Exception {
        ScriptConfigPanel panel = new ScriptConfigPanel();

        JTextArea referenceArea = getField(panel, "referenceArea", JTextArea.class);
        assertTrue(referenceArea.getText().contains("content"));
        assertTrue(referenceArea.getText().contains("request.getPath"));
        assertTrue(referenceArea.getText().contains("request.getQueryParam"));
        assertTrue(referenceArea.getText().contains("request.getHeader"));
        assertTrue(referenceArea.getText().contains("ctx.setSharedData"));
        assertTrue(referenceArea.getText().contains("Hash.sha256"));
        assertTrue(referenceArea.getText().contains("Hash.hmacSha256"));

        JComboBox<?> guideCombo = getField(panel, "guideCombo", JComboBox.class);
        JTextArea guideArea = getField(panel, "guideArea", JTextArea.class);
        guideCombo.setSelectedItem("语言、内置库与自定义库");
        assertTrue(guideArea.getText().contains("Rhino JavaScript"));
        assertTrue(guideArea.getText().contains("没有 require"));
        assertTrue(guideArea.getText().contains("目前 UI 不支持上传 npm 包"));
        guideCombo.setSelectedItem("获取 HTTP 信息");
        assertTrue(guideArea.getText().contains("request.getQueryParam('a')"));
        guideCombo.setSelectedItem("写回 Header / Body / Field");
        assertTrue(guideArea.getText().contains("结果写回到 = header"));

        JComboBox<?> templateCombo = getField(panel, "templateCombo", JComboBox.class);
        templateCombo.setSelectedItem("计算签名并写回 Header");

        JButton applyButton = findButton(panel.getPanel(), "套用模板");
        assertNotNull(applyButton);
        applyButton.doClick();

        ProcessingAction action = new ProcessingAction();
        panel.saveConfig(action);

        Map<String, Object> config = action.getConfig();
        String script = String.valueOf(config.get(Constants.ConfigKey.SCRIPT_CODE));
        assertTrue(script.contains("request.getHeader('Timestamp')"));
        assertTrue(script.contains("Hash.sha256"));
        assertTrue(script.contains("return"));
    }

    private <T> T getField(Object target, String fieldName, Class<T> type) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return type.cast(field.get(target));
    }

    private JButton findButton(JComponent component, String text) {
        for (java.awt.Component child : component.getComponents()) {
            if (child instanceof JButton button && text.equals(button.getText())) {
                return button;
            }
            if (child instanceof JComponent nested) {
                JButton found = findButton(nested, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
