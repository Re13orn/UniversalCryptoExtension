package com.universal.crypto.util;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.universal.crypto.util.Logger.LogLevel;

import java.io.File;
import java.io.IOException;

/**
 * Persistent settings for the extension.
 * stored in ~/.burp/universal-crypto-extension/config.json
 */
public class ExtensionSettings {

    private static final String CONFIG_DIR = System.getProperty("user.home") + "/.burp/universal-crypto-extension";
    private static final String CONFIG_FILE = "config.json";
    private static final ExtensionSettings INSTANCE = new ExtensionSettings();

    // API Settings
    private volatile String apiBaseUrl = "http://localhost:8080/api";
    private volatile int apiTimeoutMs = 30000;

    // Logging Settings
    private volatile String logLevel = LogLevel.INFO;
    private volatile boolean debugMode = false;
    private volatile boolean fileLoggingEnabled = true;
    private volatile String logDirectory = CONFIG_DIR + "/logs";
    private volatile String language = "en";

    private ExtensionSettings() {
        // Private constructor
    }

    public static ExtensionSettings getInstance() {
        return INSTANCE;
    }

    /**
     * Load settings from disk
     */
    public synchronized void load() {
        File configFile = new File(CONFIG_DIR, CONFIG_FILE);
        if (configFile.exists()) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                ExtensionSettings loaded = mapper.readValue(configFile, ExtensionSettings.class);
                
                // Copy values
                this.apiBaseUrl = loaded.apiBaseUrl;
                this.apiTimeoutMs = loaded.apiTimeoutMs;
                this.logLevel = loaded.logLevel;
                this.debugMode = loaded.debugMode;
                this.fileLoggingEnabled = loaded.fileLoggingEnabled;
                this.logDirectory = loaded.logDirectory;
                this.language = loaded.language;
                
                Logger.getInstance().info("Settings loaded from " + configFile.getAbsolutePath());
            } catch (IOException e) {
                Logger.getInstance().error("Failed to load settings: " + e.getMessage());
            }
        }
    }

    /**
     * Save settings to disk
     */
    public synchronized void save() {
        try { saveOrThrow(); }
        catch (IOException e) { Logger.getInstance().error("Failed to save settings: " + e.getMessage()); }
    }

    /** UI callers must not report success if persistence fails. */
    public synchronized void saveOrThrow() throws IOException {
        java.nio.file.Path directory = java.nio.file.Path.of(CONFIG_DIR);
        java.nio.file.Files.createDirectories(directory);
        java.nio.file.Path staged = java.nio.file.Files.createTempFile(directory, "config-", ".json");
        try {
            new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(staged.toFile(), this);
            java.nio.file.Path destination = directory.resolve(CONFIG_FILE);
            try {
                java.nio.file.Files.move(staged, destination, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException ex) {
                java.nio.file.Files.move(staged, destination, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        } finally { java.nio.file.Files.deleteIfExists(staged); }
    }

    // Getters and Setters

    public String getApiBaseUrl() {
        return apiBaseUrl;
    }

    public void setApiBaseUrl(String apiBaseUrl) {
        this.apiBaseUrl = apiBaseUrl;
    }

    public int getApiTimeoutMs() {
        return apiTimeoutMs;
    }

    public void setApiTimeoutMs(int apiTimeoutMs) {
        this.apiTimeoutMs = apiTimeoutMs;
    }

    public String getLogLevel() {
        return logLevel;
    }

    public void setLogLevel(String logLevel) {
        this.logLevel = logLevel;
    }

    public boolean isDebugMode() {
        return debugMode;
    }

    public void setDebugMode(boolean debugMode) {
        this.debugMode = debugMode;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public boolean isFileLoggingEnabled() {
        return fileLoggingEnabled;
    }

    public void setFileLoggingEnabled(boolean fileLoggingEnabled) {
        this.fileLoggingEnabled = fileLoggingEnabled;
    }

    public String getLogDirectory() {
        return logDirectory;
    }

    public void setLogDirectory(String logDirectory) {
        this.logDirectory = logDirectory;
    }
}

