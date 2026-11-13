package com.universal.crypto.util;

import java.util.Locale;
import java.util.ResourceBundle;

/**
 * Manages internationalization (i18n) resources
 */
public class LanguageManager {

    private static LanguageManager instance;
    private ResourceBundle messages;
    private Locale currentLocale;

    private LanguageManager() {
        // Default to English
        setLanguage("en");
    }

    public static synchronized LanguageManager getInstance() {
        if (instance == null) {
            instance = new LanguageManager();
        }
        return instance;
    }

    public void setLanguage(String langCode) {
        if ("zh".equalsIgnoreCase(langCode)) {
            currentLocale = Locale.CHINESE;
        } else {
            currentLocale = Locale.ENGLISH;
        }
        // Force reload
        ResourceBundle.clearCache();
        loadBundle();
    }

    private void loadBundle() {
        try {
            // Searches for messages_en.properties, messages_zh.properties in classpath
            messages = ResourceBundle.getBundle("com.universal.crypto.resources.messages", currentLocale);
            Logger.getInstance().debug("Loaded resource bundle for locale: " + currentLocale + ", bundle locale: " + messages.getLocale());
        } catch (Exception e) {
            Logger.getInstance().error("Could not load resource bundle for " + currentLocale + ": " + e.getMessage());
            // Fallback to English manually if completely failed?
        }
    }

    public String getString(String key) {
        if (messages == null) return key;
        try {
            return messages.getString(key);
        } catch (Exception e) {
            return "!" + key + "!";
        }
    }
    
    public Locale getCurrentLocale() {
        return currentLocale;
    }

    /**
     * Helper to format a message with arguments
     */
    public String format(String key, Object... args) {
        String pattern = getString(key);
        return java.text.MessageFormat.format(pattern, args);
    }
}
