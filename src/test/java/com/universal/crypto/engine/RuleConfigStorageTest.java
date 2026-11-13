package com.universal.crypto.engine;

import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleCondition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

class RuleConfigStorageTest {

    private RuleConfigStorage storage;
    private ProcessingRule rule1;
    private ProcessingRule rule2;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        storage = new RuleConfigStorage(tempDir.toString());

        rule1 = createTestRule("rule-1", "Rule 1");
        rule2 = createTestRule("rule-2", "Rule 2");
    }

    private ProcessingRule createTestRule(String id, String name) {
        ProcessingRule rule = new ProcessingRule(id);
        rule.setName(name);
        rule.setDescription("Test rule: " + name);
        rule.setEnabled(true);
        rule.setPriority(10);

        RuleCondition condition = new RuleCondition();
        condition.addHost("example.com");
        condition.addMethod("POST");
        rule.setCondition(condition);

        ProcessingAction action = new ProcessingAction("decrypt", "body", "crypto");
        action.setDescription("Decrypt body content");
        action.setConfig("algorithm", "aes-256");
        rule.addRequestAction(action);

        return rule;
    }

    @Test
    void testDefaultConstructor() {
        RuleConfigStorage defaultStorage = new RuleConfigStorage();
        assertNotNull(defaultStorage.getConfigDirectory());
        assertFalse(defaultStorage.getConfigDirectory().isEmpty());
    }

    @Test
    void testConstructorWithCustomDirectory() {
        String customDir = tempDir.toString();
        RuleConfigStorage customStorage = new RuleConfigStorage(customDir);
        assertEquals(customDir, customStorage.getConfigDirectory());
    }

    @Test
    void testGetConfigFilePath() {
        String expectedPath = Paths.get(tempDir.toString(), "universal-crypto-rules.json").toString();
        assertEquals(expectedPath, storage.getConfigFilePath());
    }

    @Test
    void testConfigFileExists() {
        assertFalse(storage.configFileExists());

        // Create empty file
        Path configFile = Paths.get(storage.getConfigFilePath());
        assertDoesNotThrow(() -> {
            Files.createFile(configFile);
        });

        assertTrue(storage.configFileExists());
    }

    @Test
    void testSaveRules() throws IOException {
        List<ProcessingRule> rules = Arrays.asList(rule1, rule2);
        storage.saveRules(rules);

        assertTrue(storage.configFileExists());
        assertTrue(storage.getConfigFileSize() > 0);
    }

    @Test
    void testSaveRulesWithNull() throws IOException {
        storage.saveRules(null);
        assertTrue(storage.configFileExists());

        List<ProcessingRule> loadedRules = storage.loadRules();
        assertNotNull(loadedRules);
        assertTrue(loadedRules.isEmpty());
    }

    @Test
    void testLoadRules() throws IOException {
        List<ProcessingRule> originalRules = Arrays.asList(rule1, rule2);
        storage.saveRules(originalRules);

        List<ProcessingRule> loadedRules = storage.loadRules();
        assertNotNull(loadedRules);
        assertEquals(2, loadedRules.size());

        ProcessingRule loadedRule1 = loadedRules.stream()
                .filter(r -> "rule-1".equals(r.getId()))
                .findFirst()
                .orElse(null);
        assertNotNull(loadedRule1);
        assertEquals("Rule 1", loadedRule1.getName());

        ProcessingRule loadedRule2 = loadedRules.stream()
                .filter(r -> "rule-2".equals(r.getId()))
                .findFirst()
                .orElse(null);
        assertNotNull(loadedRule2);
        assertEquals("Rule 2", loadedRule2.getName());
    }

    @Test
    void testLoadRulesWhenFileDoesNotExist() throws IOException {
        List<ProcessingRule> loadedRules = storage.loadRules();
        assertNotNull(loadedRules);
        assertTrue(loadedRules.isEmpty());
    }

    @Test
    void testLoadRulesWithEmptyFile() throws IOException {
        // Create empty file
        Path configFile = Paths.get(storage.getConfigFilePath());
        Files.createFile(configFile);

        List<ProcessingRule> loadedRules = storage.loadRules();
        assertNotNull(loadedRules);
        assertTrue(loadedRules.isEmpty());
    }

    @Test
    void testLoadRulesWithInvalidJson() throws IOException {
        // Create file with invalid JSON
        Path configFile = Paths.get(storage.getConfigFilePath());
        Files.write(configFile, "invalid json content".getBytes());

        assertThrows(IOException.class, () -> {
            storage.loadRules();
        });
    }

    @Test
    void testDeleteConfigFile() throws IOException {
        // Save rules to create the file
        storage.saveRules(Arrays.asList(rule1));
        assertTrue(storage.configFileExists());

        assertTrue(storage.deleteConfigFile());
        assertFalse(storage.configFileExists());

        // Test deleting non-existent file
        assertTrue(storage.deleteConfigFile());
    }

    @Test
    void testGetConfigFileSize() throws IOException {
        assertEquals(-1, storage.getConfigFileSize());

        storage.saveRules(Arrays.asList(rule1));
        long size = storage.getConfigFileSize();
        assertTrue(size > 0);

        storage.saveRules(Arrays.asList(rule1, rule2));
        long newSize = storage.getConfigFileSize();
        assertTrue(newSize > size);
    }

    @Test
    void testValidateConfigFile() throws IOException {
        // Non-existent file should be valid
        assertTrue(storage.validateConfigFile());

        // Valid JSON should be valid
        storage.saveRules(Arrays.asList(rule1));
        assertTrue(storage.validateConfigFile());

        // Invalid JSON should be invalid
        Path configFile = Paths.get(storage.getConfigFilePath());
        Files.write(configFile, "invalid json".getBytes());
        assertFalse(storage.validateConfigFile());

        // Empty file should be valid
        Files.write(configFile, "".getBytes());
        assertTrue(storage.validateConfigFile());
    }

    @Test
    void testBackupAndRestore() throws IOException {
        // Save initial rules
        List<ProcessingRule> initialRules = Arrays.asList(rule1);
        storage.saveRules(initialRules);

        // Save new rules (this should create a backup)
        List<ProcessingRule> newRules = Arrays.asList(rule1, rule2);
        storage.saveRules(newRules);

        // Verify backup file exists
        Path backupFile = Paths.get(tempDir.toString(), "universal-crypto-rules.json.backup");
        assertTrue(Files.exists(backupFile));

        // Load rules and verify new rules are loaded
        List<ProcessingRule> loadedRules = storage.loadRules();
        assertEquals(2, loadedRules.size());
    }

    @Test
    void testSaveFailureRestoresBackup() throws IOException {
        // Save initial rules
        storage.saveRules(Arrays.asList(rule1));
        assertTrue(storage.configFileExists());

        // Make the config file read-only to simulate save failure
        Path configFile = Paths.get(storage.getConfigFilePath());
        configFile.toFile().setReadOnly();

        try {
            assumeFalse(Files.isWritable(configFile), "Test process can write to read-only files");
            // This should fail and restore from backup
            assertThrows(IOException.class, () -> {
                storage.saveRules(Arrays.asList(rule1, rule2));
            });

            // Original rules should still be loadable
            configFile.toFile().setWritable(true);
            List<ProcessingRule> loadedRules = storage.loadRules();
            assertEquals(1, loadedRules.size());
            assertEquals("rule-1", loadedRules.get(0).getId());
        } finally {
            // Cleanup: restore write permissions
            configFile.toFile().setWritable(true);
        }
    }

    @Test
    void testGetDefaultConfigDirectory() {
        // Test that default config directory is platform-appropriate
        RuleConfigStorage defaultStorage = new RuleConfigStorage();
        String configDir = defaultStorage.getConfigDirectory();

        assertNotNull(configDir);
        assertFalse(configDir.isEmpty());
        assertTrue(configDir.contains("UniversalCryptoExtension"));

        Path testHome = Path.of(System.getProperty("user.home"));
        String osName = System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT);
        Path expectedBase;
        if (osName.contains("windows")) {
            expectedBase = testHome.resolve("appdata");
        } else if (osName.contains("mac")) {
            expectedBase = testHome.resolve("Library").resolve("Application Support");
        } else {
            expectedBase = testHome.resolve("xdg-config");
        }
        assertEquals(expectedBase.resolve("UniversalCryptoExtension"), Path.of(configDir));
    }

    @Test
    void testToString() {
        String str = storage.toString();
        assertTrue(str.contains("RuleConfigStorage"));
        assertTrue(str.contains("configDirectory"));
        assertTrue(str.contains("universal-crypto-rules.json"));
        assertTrue(str.contains("fileExists=false"));

        // After creating file
        assertDoesNotThrow(() -> {
            storage.saveRules(Arrays.asList(rule1));
        });

        str = storage.toString();
        assertTrue(str.contains("fileExists=true"));
    }

    @Test
    void testConfigDirectoryCreation() {
        // Test with non-existent directory
        Path nonExistentDir = tempDir.resolve("new/nested/directory");
        assertFalse(Files.exists(nonExistentDir));

        RuleConfigStorage newStorage = new RuleConfigStorage(nonExistentDir.toString());
        assertTrue(Files.exists(nonExistentDir));
        assertTrue(Files.isDirectory(nonExistentDir));
    }

    @Test
    void testConfigDirectoryCreationFailure() {
        // Create a file where a directory is expected to force directory creation failure.
        Path notADir = tempDir.resolve("not_a_dir");
        assertDoesNotThrow(() -> Files.writeString(notADir, "x"));
        assertTrue(Files.exists(notADir));
        assertFalse(Files.isDirectory(notADir));

        // Constructor should not hard-fail; save should surface IO errors.
        RuleConfigStorage newStorage = new RuleConfigStorage(notADir.toString());
        assertThrows(IOException.class, () -> newStorage.saveRules(Arrays.asList(rule1)));
    }

    @Test
    void testComplexRulePersistence() throws IOException {
        // Create a complex rule to test serialization edge cases
        ProcessingRule complexRule = new ProcessingRule("complex-rule");
        complexRule.setName("Complex Rule");
        complexRule.setDescription("A rule with complex configuration");
        complexRule.setEnabled(false);
        complexRule.setPriority(1);

        RuleCondition condition = new RuleCondition();
        condition.addHost("*.example.com");
        condition.addPath("/api/*");
        condition.addMethod("POST");
        condition.addMethod("PUT");
        condition.addHeader("Content-Type", "application/json");
        condition.addHeader("Authorization", "Bearer *");
        condition.setContentPattern("encrypted_data");
        condition.setToolSource("PROXY");
        complexRule.setCondition(condition);

        ProcessingAction requestAction = new ProcessingAction("decrypt", "body", "crypto");
        requestAction.setDescription("Decrypt request body");
        requestAction.setConfig("algorithm", "aes-gcm");
        requestAction.setConfig("keySource", "lookup");
        requestAction.setConfig("lookupMethod", "md5-hash");
        requestAction.setConfig("inputSource", "request-body");
        complexRule.addRequestAction(requestAction);

        ProcessingAction responseAction = new ProcessingAction("decrypt", "body", "crypto");
        responseAction.setDescription("Decrypt response body");
        responseAction.setConfig("algorithm", "aes-gcm");
        responseAction.setConfig("keySource", "cached");
        responseAction.setConfig("fallbackLookup", true);
        complexRule.addResponseAction(responseAction);

        // Save and load the complex rule
        storage.saveRules(Arrays.asList(complexRule));
        List<ProcessingRule> loadedRules = storage.loadRules();

        assertEquals(1, loadedRules.size());
        ProcessingRule loadedRule = loadedRules.get(0);

        assertEquals(complexRule.getId(), loadedRule.getId());
        assertEquals(complexRule.getName(), loadedRule.getName());
        assertEquals(complexRule.getDescription(), loadedRule.getDescription());
        assertEquals(complexRule.isEnabled(), loadedRule.isEnabled());
        assertEquals(complexRule.getPriority(), loadedRule.getPriority());

        // Verify condition
        RuleCondition loadedCondition = loadedRule.getCondition();
        assertEquals(condition.getHosts(), loadedCondition.getHosts());
        assertEquals(condition.getPaths(), loadedCondition.getPaths());
        assertEquals(condition.getMethods(), loadedCondition.getMethods());
        assertEquals(condition.getHeaders(), loadedCondition.getHeaders());
        assertEquals(condition.getContentPattern(), loadedCondition.getContentPattern());
        assertEquals(condition.getToolSource(), loadedCondition.getToolSource());

        // Verify actions
        assertEquals(complexRule.getRequestActionCount(), loadedRule.getRequestActionCount());
        assertEquals(complexRule.getResponseActionCount(), loadedRule.getResponseActionCount());

        if (loadedRule.hasRequestActions()) {
            ProcessingAction loadedRequestAction = loadedRule.getRequestActions().get(0);
            assertEquals(requestAction.getActionType(), loadedRequestAction.getActionType());
            assertEquals(requestAction.getTargetType(), loadedRequestAction.getTargetType());
            assertEquals(requestAction.getProcessor(), loadedRequestAction.getProcessor());
            assertEquals(requestAction.getDescription(), loadedRequestAction.getDescription());
            assertEquals(requestAction.getConfig("algorithm"), loadedRequestAction.getConfig("algorithm"));
            assertEquals(requestAction.getConfig("keySource"), loadedRequestAction.getConfig("keySource"));
        }
    }
}
