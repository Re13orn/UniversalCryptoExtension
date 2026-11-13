package com.universal.crypto.ui.processor;

import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureConfigPanelTest {
    private String previousLanguage;
    @org.junit.jupiter.api.BeforeEach void useChinese() {
        previousLanguage = com.universal.crypto.util.LanguageManager.getInstance().getCurrentLocale().getLanguage();
        com.universal.crypto.util.LanguageManager.getInstance().setLanguage("zh");
    }
    @org.junit.jupiter.api.AfterEach void restoreLanguage() {
        com.universal.crypto.util.LanguageManager.getInstance().setLanguage(previousLanguage);
    }


    @Test
    void conceptGuideExplainsSpecialTermsAndExamplesInTheUi() throws Exception {
        SignatureConfigPanel panel = new SignatureConfigPanel();
        JTextArea guideArea = getField(panel, "conceptGuideArea", JTextArea.class);

        assertTrue(guideArea.getText().contains("算法=SHA-256"));
        assertTrue(guideArea.getText().contains("密钥来源=不需要密钥"));
        assertTrue(guideArea.getText().contains("目标类型=header"));

        JComboBox<?> guideCombo = getField(panel, "conceptGuideCombo", JComboBox.class);
        guideCombo.setSelectedItem("参数整理与稳定 JSON");

        assertTrue(guideArea.getText().contains("参数之间用"));
        assertTrue(guideArea.getText().contains("${stablejson:payload}"));
        assertTrue(guideArea.getText().contains("GET 用 query"));
    }

    private <T> T getField(Object target, String fieldName, Class<T> type) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return type.cast(field.get(target));
    }
}
