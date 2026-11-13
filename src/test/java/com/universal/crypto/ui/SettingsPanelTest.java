package com.universal.crypto.ui;

import com.universal.crypto.burp.UniversalCryptoExtension;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

class SettingsPanelTest {

    @Test
    void validatesApiBaseUrlBeforeSaving() throws Exception {
        SettingsPanel panel = new SettingsPanel(null, new UniversalCryptoExtension());
        Method validator = SettingsPanel.class.getDeclaredMethod("validateApiBaseUrl", String.class);
        validator.setAccessible(true);

        assertNull(validator.invoke(panel, "http://localhost:8080/api"));
        assertNull(validator.invoke(panel, "https://api.example.com/crypto"));
        assertNotNull(validator.invoke(panel, ""));
        assertNotNull(validator.invoke(panel, "localhost:8080/api"));
        assertNotNull(validator.invoke(panel, "ftp://example.com/api"));
    }

    @Test
    void disablesLogDirectoryControlsWhenFileLoggingIsOff() throws Exception {
        SettingsPanel panel = new SettingsPanel(null, new UniversalCryptoExtension());
        JCheckBox fileLogging = getField(panel, "fileLoggingCheckBox", JCheckBox.class);
        JTextField logDirectory = getField(panel, "logDirectoryField", JTextField.class);
        JButton browseButton = getField(panel, "browseLogDirectoryButton", JButton.class);

        fileLogging.setSelected(false);
        Method updateState = SettingsPanel.class.getDeclaredMethod("updateLogControlState");
        updateState.setAccessible(true);
        updateState.invoke(panel);

        assertFalse(logDirectory.isEnabled());
        assertFalse(browseButton.isEnabled());

        fileLogging.setSelected(true);
        updateState.invoke(panel);

        assertTrue(logDirectory.isEnabled());
        assertTrue(browseButton.isEnabled());
    }

    private <T> T getField(Object target, String fieldName, Class<T> type) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return type.cast(field.get(target));
    }
}
