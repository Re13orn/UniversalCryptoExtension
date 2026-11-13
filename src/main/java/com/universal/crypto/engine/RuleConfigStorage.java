package com.universal.crypto.engine;

import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleSerializer;
import com.universal.crypto.util.LanguageManager;
import com.universal.crypto.util.Logger;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Rule configuration storage implementation for saving and loading rules to/from JSON files
 */
public class RuleConfigStorage {

    private static final String CONFIG_FILE = "universal-crypto-rules.json";
    private static final String BACKUP_SUFFIX = ".backup";

    private final String configDirectory;

    /**
     * Constructor with default configuration directory
     */
    public RuleConfigStorage() {
        this(getDefaultConfigDirectory());
    }

    /**
     * Constructor with custom configuration directory
     *
     * @param configDirectory directory to store configuration files
     */
    public RuleConfigStorage(String configDirectory) {
        this.configDirectory = configDirectory;
        ensureConfigDirectoryExists();
    }

    /**
     * Save processing rules to configuration file
     *
     * @param rules list of rules to save
     * @throws IOException if save operation fails
     */
    public void saveRules(List<ProcessingRule> rules) throws IOException {
        if (rules == null) {
            rules = new ArrayList<>();
        }

        String json = RuleSerializer.toJson(rules);
        Path configPath = getConfigFilePathObject();

        // Create backup of existing file
        createBackup(configPath);

        try {
            Files.write(configPath, json.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            // Restore from backup if save fails
            restoreFromBackup(configPath);
            throw new IOException("Failed to save rules configuration", e);
        }
    }

    /**
     * Load processing rules from configuration file
     *
     * @return list of loaded rules
     * @throws IOException if load operation fails
     */
    public List<ProcessingRule> loadRules() throws IOException {
        Path configPath = getConfigFilePathObject();

        if (!Files.exists(configPath)) {
            return new ArrayList<>();
        }

        try {
            String json = Files.readString(configPath, StandardCharsets.UTF_8);

            if (json == null || json.trim().isEmpty()) {
                return new ArrayList<>();
            }

            List<ProcessingRule> rules = RuleSerializer.fromJsonList(json);
            return rules != null ? rules : new ArrayList<>();

        } catch (Exception e) {
            throw new IOException("Failed to load rules configuration from: " + configPath, e);
        }
    }

    /**
     * Check if configuration file exists
     *
     * @return true if configuration file exists
     */
    public boolean configFileExists() {
        return Files.exists(getConfigFilePathObject());
    }

    /**
     * Get the configuration file path
     *
     * @return full path to configuration file
     */
    public String getConfigFilePath() {
        return Paths.get(configDirectory, CONFIG_FILE).toString();
    }

    /**
     * Get the configuration file Path object
     *
     * @return Path object for configuration file
     */
    private Path getConfigFilePathObject() {
        return Paths.get(configDirectory, CONFIG_FILE);
    }

    /**
     * Get backup file path
     *
     * @return Path object for backup file
     */
    private Path getBackupFilePath() {
        return Paths.get(configDirectory, CONFIG_FILE + BACKUP_SUFFIX);
    }

    /**
     * Delete configuration file
     *
     * @return true if file was deleted or didn't exist
     */
    public boolean deleteConfigFile() {
        try {
            Path configPath = getConfigFilePathObject();
            if (Files.exists(configPath)) {
                Files.delete(configPath);
            }
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Create backup of existing configuration file
     *
     * @param configPath path to configuration file
     */
    private void createBackup(Path configPath) {
        if (Files.exists(configPath)) {
            try {
                Path backupPath = getBackupFilePath();
                Files.copy(configPath, backupPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                // Backup creation failure is not critical
                Logger.getInstance().warn("Failed to create backup: " + e.getMessage());
            }
        }
    }

    /**
     * Restore configuration from backup
     *
     * @param configPath path to configuration file
     */
    private void restoreFromBackup(Path configPath) {
        Path backupPath = getBackupFilePath();
        if (Files.exists(backupPath)) {
            try {
                Files.copy(backupPath, configPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                Logger.getInstance().warn("Failed to restore from backup: " + e.getMessage());
            }
        }
    }

    /**
     * Ensure configuration directory exists
     */
    private void ensureConfigDirectoryExists() {
        try {
            Path dirPath = Paths.get(configDirectory);
            if (!Files.exists(dirPath)) {
                Files.createDirectories(dirPath);
            }
        } catch (IOException e) {
            // Do not hard-fail extension initialization if the config directory cannot be created.
            // Downstream save/load operations will surface errors as needed.
            Logger.getInstance().warn("Failed to create configuration directory: " + configDirectory + " - " + e.getMessage());
        }
    }

    /**
     * Get default configuration directory
     *
     * @return default configuration directory path
     */
    private static String getDefaultConfigDirectory() {
        String userHome = System.getProperty("user.home");
        String osName = System.getProperty("os.name").toLowerCase();

        if (osName.contains("windows")) {
            String appData = System.getenv("APPDATA");
            if (appData != null) {
                return Paths.get(appData, "UniversalCryptoExtension").toString();
            }
            return Paths.get(userHome, "AppData", "Roaming", "UniversalCryptoExtension").toString();

        } else if (osName.contains("mac")) {
            return Paths.get(userHome, "Library", "Application Support", "UniversalCryptoExtension").toString();

        } else {
            // Linux and other Unix-like systems
            String xdgConfigHome = System.getenv("XDG_CONFIG_HOME");
            if (xdgConfigHome != null) {
                return Paths.get(xdgConfigHome, "UniversalCryptoExtension").toString();
            }
            return Paths.get(userHome, ".config", "UniversalCryptoExtension").toString();
        }
    }

    /**
     * Get configuration file size in bytes
     *
     * @return file size or -1 if file doesn't exist
     */
    public long getConfigFileSize() {
        try {
            Path configPath = getConfigFilePathObject();
            return Files.exists(configPath) ? Files.size(configPath) : -1;
        } catch (IOException e) {
            return -1;
        }
    }

    /**
     * Validate configuration file
     *
     * @return true if configuration file is valid JSON
     */
    public boolean validateConfigFile() {
        try {
            Path configPath = getConfigFilePathObject();
            if (!Files.exists(configPath)) {
                return true; // Non-existent file is considered valid (will be created)
            }

            String json = Files.readString(configPath, StandardCharsets.UTF_8);
            return RuleSerializer.isValidRuleListJson(json);

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get configuration directory
     *
     * @return configuration directory path
     */
    public String getConfigDirectory() {
        return configDirectory;
    }

    @Override
    public String toString() {
        return "RuleConfigStorage{" +
                "configDirectory='" + configDirectory + '\'' +
                ", configFile='" + CONFIG_FILE + '\'' +
                ", fileExists=" + configFileExists() +
                '}';
    }
}
