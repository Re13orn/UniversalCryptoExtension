package com.universal.crypto.ui;

import com.universal.crypto.util.Logger;
import javax.swing.*;

/**
 * Manages the UI theme using FlatLaF.
 */
public class ThemeManager {
    
    private static final Logger logger = Logger.getInstance();

    public static void initialize() {
        // Do not force FlatLaf as it conflicts with Burp's internal theming
        // causing global UI corruption (red screens).
        // We will respect Burp's native Look and Feel.
        logger.info("ThemeManager: Using Burp Suite native theme");
    }

    public static void setDarkTheme() {
        // No-op to avoid breaking Burp
    }

    public static void setLightTheme() {
        // No-op to avoid breaking Burp
    }
    
    // updateUI removed as it's dangerous

}
