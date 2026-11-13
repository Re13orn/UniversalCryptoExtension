package com.universal.crypto.engine;

import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleCondition;
import com.universal.crypto.model.RuleSerializer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

class RuleManagerTest {

    private RuleManager ruleManager;
    private RuleConfigStorage storage;
    private ProcessingRule rule1;
    private ProcessingRule rule2;
    private ProcessingRule rule3;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        storage = new RuleConfigStorage(tempDir.toString());
        ruleManager = new RuleManager(storage);

        rule1 = createTestRule("rule-1", "Rule 1", true, 10);
        rule2 = createTestRule("rule-2", "Rule 2", false, 20);
        rule3 = createTestRule("rule-3", "Rule 3", true, 5);
    }

    private ProcessingRule createTestRule(String id, String name, boolean enabled, int priority) {
        ProcessingRule rule = new ProcessingRule(id);
        rule.setName(name);
        rule.setEnabled(enabled);
        rule.setPriority(priority);

        RuleCondition condition = new RuleCondition();
        condition.addHost("example.com");
        rule.setCondition(condition);

        ProcessingAction action = new ProcessingAction("decrypt", "body", "crypto");
        rule.addRequestAction(action);

        return rule;
    }

    @Test void concurrentBatchReadersNeverSeeTheTemporaryEmptyList() throws Exception {
        var batch=java.util.List.of(createTestRule("a","A",true,1),createTestRule("b","B",true,2),createTestRule("c","C",true,3));
        ruleManager.setRules(batch);
        var running=new java.util.concurrent.atomic.AtomicBoolean(true);
        var started=new java.util.concurrent.CountDownLatch(1);
        var executor=java.util.concurrent.Executors.newSingleThreadExecutor();
        var reader=executor.submit(()->{
            while(running.get()) {
                assertEquals(3,ruleManager.getAllRules().size());
                started.countDown();
            }
        });
        try {
            assertTrue(started.await(5,java.util.concurrent.TimeUnit.SECONDS));
            for(int i=0;i<500;i++)ruleManager.setRules(batch);
        } finally { running.set(false);executor.shutdown(); }
        reader.get(5,java.util.concurrent.TimeUnit.SECONDS);
    }

    @Test void failedBatchReplacementKeepsOldRulesAndRevision() {
        var original=new ProcessingRule("retained","Retained",true,1);original.setCondition(new com.universal.crypto.model.RuleCondition());
        ruleManager.addRule(original);long revision=ruleManager.getRevision();
        var duplicate=new ProcessingRule("same");
        assertThrows(IllegalArgumentException.class,()->ruleManager.setRules(java.util.List.of(duplicate,duplicate)));
        assertEquals(1,ruleManager.getRuleCount());assertNotNull(ruleManager.getRuleById("retained"));assertEquals(revision,ruleManager.getRevision());
    }

    @Test void failedPersistentEditKeepsDiskMemoryRevisionAndListenersUnchanged() throws Exception {
        var failing = new RuleConfigStorage(tempDir.toString()) {
            boolean fail;
            @Override public void saveRules(List<ProcessingRule> candidate) throws IOException {
                if (fail) throw new IOException("simulated storage failure");
                super.saveRules(candidate);
            }
        };
        var manager = new RuleManager(failing);
        manager.addRuleAndSave(rule1);
        long revision = manager.getRevision();
        var notifications = new AtomicInteger();
        manager.addRuleChangeListener(notifications::incrementAndGet);
        failing.fail = true;
        assertThrows(RuntimeException.class, () -> manager.updateRulesAndSave(candidate -> {
            candidate.get(0).setEnabled(false);
            candidate.add(rule2);
        }));
        assertEquals(RuleSerializer.toJson(List.of(rule1)), RuleSerializer.toJson(manager.getAllRules()));
        assertEquals(RuleSerializer.toJson(List.of(rule1)), RuleSerializer.toJson(failing.loadRules()));
        assertEquals(revision, manager.getRevision());
        assertEquals(0, notifications.get());
    }

    @Test void persistentBatchIsPublishedOnceAfterStorageCompletesAndOwnsItsSnapshot() throws Exception {
        var managerRef = new java.util.concurrent.atomic.AtomicReference<RuleManager>();
        var committed = new RuleConfigStorage(tempDir.toString()) {
            @Override public void saveRules(List<ProcessingRule> candidate) throws IOException {
                assertEquals(RuleSerializer.toJson(List.of(rule1)), RuleSerializer.toJson(managerRef.get().getAllRules()), "readers retain the old complete batch while saving");
                super.saveRules(candidate);
                assertEquals(RuleSerializer.toJson(List.of(rule1)), RuleSerializer.toJson(managerRef.get().getAllRules()), "even persisted candidates are not visible before publication");
            }
        };
        var manager = new RuleManager(committed); managerRef.set(manager); manager.addRule(rule1);
        long revision = manager.getRevision();
        var notifications = new AtomicInteger();
        manager.addRuleChangeListener(() -> {
            notifications.incrementAndGet();
            try { assertEquals(RuleSerializer.toJson(committed.loadRules()), RuleSerializer.toJson(manager.getAllRules())); }
            catch (IOException ex) { throw new AssertionError(ex); }
        });
        var retained = new java.util.concurrent.atomic.AtomicReference<List<ProcessingRule>>();
        manager.updateRulesAndSave(candidate -> {
            candidate.get(0).setEnabled(false);
            candidate.add(rule2);
            retained.set(candidate);
        });
        assertEquals(revision + 1, manager.getRevision()); assertEquals(1, notifications.get());
        assertEquals(2, manager.getRuleCount()); assertFalse(manager.getRuleById(rule1.getId()).isEnabled());
        retained.get().get(0).setName("escaped edit"); rule2.setName("caller edit");
        assertEquals("Rule 1", manager.getRuleById(rule1.getId()).getName());
        assertEquals("Rule 2", manager.getRuleById(rule2.getId()).getName());
        assertEquals(RuleSerializer.toJson(committed.loadRules()), RuleSerializer.toJson(manager.getAllRules()));
    }

    @Test void callerAndReturnedNestedConfigurationCannotMutateStoredRulesWithoutUpdate() {
        var original=new ProcessingRule("owned","Owned",true,1);original.setCondition(new com.universal.crypto.model.RuleCondition());
        var action=new com.universal.crypto.model.ProcessingAction("sign","header","signature");
        action.setTargetName("X-Sign");action.setConfig("headerTemplates",java.util.Map.of("X-Time","original"));original.addRequestAction(action);
        ruleManager.addRule(original);long revision=ruleManager.getRevision();
        original.setName("caller change");
        var editorCopy=ruleManager.getRuleById("owned");
        ((java.util.Map<String,Object>)editorCopy.getRequestActions().get(0).getConfig("headerTemplates")).put("X-Time","cancelled edit");
        assertEquals("Owned",ruleManager.getRuleById("owned").getName());
        assertEquals("original",((java.util.Map<?,?>)ruleManager.getRuleById("owned").getRequestActions().get(0).getConfig("headerTemplates")).get("X-Time"));
        assertEquals(revision,ruleManager.getRevision());
    }

    @Test
    void testConstructor() {
        assertNotNull(ruleManager);
        assertEquals(0, ruleManager.getRuleCount());
        assertFalse(ruleManager.hasRules());
    }

    @Test
    void testAddRule() {
        ruleManager.addRule(rule1);
        assertEquals(1, ruleManager.getRuleCount());
        assertTrue(ruleManager.hasRules());
        assertEquals(rule1, ruleManager.getRuleById("rule-1"));
    }

    @Test
    void testAddRuleWithNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            ruleManager.addRule(null);
        });
    }

    @Test
    void testAddRuleWithNullId() {
        ProcessingRule ruleWithNullId = new ProcessingRule();
        assertThrows(IllegalArgumentException.class, () -> {
            ruleManager.addRule(ruleWithNullId);
        });
    }

    @Test
    void testAddRuleWithEmptyId() {
        ProcessingRule ruleWithEmptyId = new ProcessingRule("");
        assertThrows(IllegalArgumentException.class, () -> {
            ruleManager.addRule(ruleWithEmptyId);
        });
    }

    @Test
    void testAddDuplicateRule() {
        ruleManager.addRule(rule1);
        ProcessingRule duplicateRule = new ProcessingRule("rule-1");
        duplicateRule.setName("Duplicate Rule");

        assertThrows(IllegalArgumentException.class, () -> {
            ruleManager.addRule(duplicateRule);
        });
    }

    @Test
    void testRuleChangeListenerNotifiedOnAddAndUpdate() {
        AtomicInteger notifications = new AtomicInteger();
        ruleManager.addRuleChangeListener(notifications::incrementAndGet);

        ruleManager.addRule(rule1);
        assertEquals(1, notifications.get());

        ProcessingRule updatedRule = new ProcessingRule("rule-1");
        updatedRule.setName("Updated Rule 1");
        updatedRule.setEnabled(false);
        assertTrue(ruleManager.updateRule(updatedRule));
        assertEquals(2, notifications.get());

        assertFalse(ruleManager.updateRule(new ProcessingRule("nonexistent")));
        assertEquals(2, notifications.get());
    }

    @Test
    void testRemoveRule() {
        ruleManager.addRule(rule1);
        ruleManager.addRule(rule2);

        assertTrue(ruleManager.removeRule("rule-1"));
        assertEquals(1, ruleManager.getRuleCount());
        assertNull(ruleManager.getRuleById("rule-1"));
        assertNotNull(ruleManager.getRuleById("rule-2"));

        assertFalse(ruleManager.removeRule("nonexistent"));
        assertFalse(ruleManager.removeRule(null));
        assertFalse(ruleManager.removeRule(""));
    }

    @Test
    void testUpdateRule() {
        ruleManager.addRule(rule1);

        ProcessingRule updatedRule = new ProcessingRule("rule-1");
        updatedRule.setName("Updated Rule 1");
        updatedRule.setEnabled(false);

        assertTrue(ruleManager.updateRule(updatedRule));
        ProcessingRule retrieved = ruleManager.getRuleById("rule-1");
        assertEquals("Updated Rule 1", retrieved.getName());
        assertFalse(retrieved.isEnabled());

        assertFalse(ruleManager.updateRule(new ProcessingRule("nonexistent")));
    }

    @Test
    void testUpdateRuleWithNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            ruleManager.updateRule(null);
        });
    }

    @Test
    void testUpdateRuleWithNullId() {
        ProcessingRule ruleWithNullId = new ProcessingRule();
        assertThrows(IllegalArgumentException.class, () -> {
            ruleManager.updateRule(ruleWithNullId);
        });
    }

    @Test
    void testGetRuleById() {
        ruleManager.addRule(rule1);
        ruleManager.addRule(rule2);

        assertEquals(rule1, ruleManager.getRuleById("rule-1"));
        assertEquals(rule2, ruleManager.getRuleById("rule-2"));
        assertNull(ruleManager.getRuleById("nonexistent"));
        assertNull(ruleManager.getRuleById(null));
        assertNull(ruleManager.getRuleById(""));
    }

    @Test
    void testGetAllRules() {
        ruleManager.addRule(rule1);
        ruleManager.addRule(rule2);

        List<ProcessingRule> allRules = ruleManager.getAllRules();
        assertEquals(2, allRules.size());
        assertTrue(allRules.contains(rule1));
        assertTrue(allRules.contains(rule2));

        // Verify it's a copy
        allRules.clear();
        assertEquals(2, ruleManager.getRuleCount());
    }

    @Test
    void testGetEnabledRules() {
        ruleManager.addRule(rule1); // enabled
        ruleManager.addRule(rule2); // disabled
        ruleManager.addRule(rule3); // enabled

        List<ProcessingRule> enabledRules = ruleManager.getEnabledRules();
        assertEquals(2, enabledRules.size());
        assertTrue(enabledRules.contains(rule1));
        assertTrue(enabledRules.contains(rule3));
        assertFalse(enabledRules.contains(rule2));
    }

    @Test
    void testGetRulesByPriority() {
        ruleManager.addRule(rule1); // priority 10
        ruleManager.addRule(rule2); // priority 20
        ruleManager.addRule(rule3); // priority 5

        List<ProcessingRule> rulesByPriority = ruleManager.getRulesByPriority();
        assertEquals(3, rulesByPriority.size());
        assertEquals(rule3, rulesByPriority.get(0)); // priority 5
        assertEquals(rule1, rulesByPriority.get(1)); // priority 10
        assertEquals(rule2, rulesByPriority.get(2)); // priority 20
    }

    @Test
    void testGetEnabledRulesByPriority() {
        ruleManager.addRule(rule1); // enabled, priority 10
        ruleManager.addRule(rule2); // disabled, priority 20
        ruleManager.addRule(rule3); // enabled, priority 5

        List<ProcessingRule> enabledRulesByPriority = ruleManager.getEnabledRulesByPriority();
        assertEquals(2, enabledRulesByPriority.size());
        assertEquals(rule3, enabledRulesByPriority.get(0)); // priority 5
        assertEquals(rule1, enabledRulesByPriority.get(1)); // priority 10
    }

    @Test
    void testSetRuleEnabled() {
        ruleManager.addRule(rule1);
        assertTrue(ruleManager.getRuleById("rule-1").isEnabled());

        long revision=ruleManager.getRevision();
        var notifications=new java.util.concurrent.atomic.AtomicInteger();ruleManager.addRuleChangeListener(notifications::incrementAndGet);
        assertTrue(ruleManager.setRuleEnabled("rule-1", false));
        assertFalse(ruleManager.getRuleById("rule-1").isEnabled());

        assertTrue(ruleManager.setRuleEnabled("rule-1", true));
        assertTrue(ruleManager.getRuleById("rule-1").isEnabled());

        assertEquals(2,notifications.get());assertEquals(revision+2,ruleManager.getRevision());
        assertFalse(ruleManager.setRuleEnabled("nonexistent", false));
    }

    @Test
    void testGetRuleCount() {
        assertEquals(0, ruleManager.getRuleCount());

        ruleManager.addRule(rule1);
        assertEquals(1, ruleManager.getRuleCount());

        ruleManager.addRule(rule2);
        assertEquals(2, ruleManager.getRuleCount());

        ruleManager.removeRule("rule-1");
        assertEquals(1, ruleManager.getRuleCount());
    }

    @Test
    void testGetEnabledRuleCount() {
        assertEquals(0, ruleManager.getEnabledRuleCount());

        ruleManager.addRule(rule1); // enabled
        assertEquals(1, ruleManager.getEnabledRuleCount());

        ruleManager.addRule(rule2); // disabled
        assertEquals(1, ruleManager.getEnabledRuleCount());

        ruleManager.addRule(rule3); // enabled
        assertEquals(2, ruleManager.getEnabledRuleCount());

        ruleManager.setRuleEnabled("rule-1", false);
        assertEquals(1, ruleManager.getEnabledRuleCount());
    }

    @Test
    void testHasRules() {
        assertFalse(ruleManager.hasRules());

        ruleManager.addRule(rule1);
        assertTrue(ruleManager.hasRules());

        ruleManager.removeRule("rule-1");
        assertFalse(ruleManager.hasRules());
    }

    @Test
    void testHasEnabledRules() {
        assertFalse(ruleManager.hasEnabledRules());

        ruleManager.addRule(rule2); // disabled
        assertFalse(ruleManager.hasEnabledRules());

        ruleManager.addRule(rule1); // enabled
        assertTrue(ruleManager.hasEnabledRules());

        ruleManager.setRuleEnabled("rule-1", false);
        assertFalse(ruleManager.hasEnabledRules());
    }

    @Test
    void testClearRules() {
        ruleManager.addRule(rule1);
        ruleManager.addRule(rule2);
        assertEquals(2, ruleManager.getRuleCount());

        ruleManager.clearRules();
        assertEquals(0, ruleManager.getRuleCount());
        assertFalse(ruleManager.hasRules());
    }

    @Test
    void testSetRules() {
        List<ProcessingRule> newRules = Arrays.asList(rule1, rule2, rule3);
        ruleManager.setRules(newRules);

        assertEquals(3, ruleManager.getRuleCount());
        assertEquals(rule1, ruleManager.getRuleById("rule-1"));
        assertEquals(rule2, ruleManager.getRuleById("rule-2"));
        assertEquals(rule3, ruleManager.getRuleById("rule-3"));
    }

    @Test
    void testSetRulesWithNull() {
        ruleManager.addRule(rule1);
        ruleManager.setRules(null);
        assertEquals(0, ruleManager.getRuleCount());
    }

    @Test
    void testSetRulesWithInvalidRule() {
        ProcessingRule invalidRule = new ProcessingRule();
        List<ProcessingRule> rulesWithInvalid = Arrays.asList(rule1, invalidRule);

        assertThrows(IllegalArgumentException.class, () -> {
            ruleManager.setRules(rulesWithInvalid);
        });
    }

    @Test
    void testSetRulesWithDuplicateIds() {
        ProcessingRule duplicateRule = new ProcessingRule("rule-1");
        List<ProcessingRule> rulesWithDuplicate = Arrays.asList(rule1, duplicateRule);

        assertThrows(IllegalArgumentException.class, () -> {
            ruleManager.setRules(rulesWithDuplicate);
        });
    }

    @Test
    void testSaveRules() throws IOException {
        ruleManager.addRule(rule1);
        ruleManager.addRule(rule2);

        assertDoesNotThrow(() -> {
            ruleManager.saveRules();
        });

        // Verify rules were saved
        List<ProcessingRule> loadedRules = storage.loadRules();
        assertEquals(2, loadedRules.size());
    }

    @Test
    void testLoadRules() throws IOException {
        // Save rules first
        storage.saveRules(Arrays.asList(rule1, rule2));

        // Load rules into manager
        assertDoesNotThrow(() -> {
            ruleManager.loadRules();
        });

        assertEquals(2, ruleManager.getRuleCount());
        assertNotNull(ruleManager.getRuleById("rule-1"));
        assertNotNull(ruleManager.getRuleById("rule-2"));
    }

    @Test
    void testInitializeWithDefaults() {
        List<ProcessingRule> defaultRules = Arrays.asList(rule1, rule2);

        // Initialize with defaults when no existing rules
        ruleManager.initializeWithDefaults(defaultRules);
        assertEquals(2, ruleManager.getRuleCount());

        // Save current rules
        assertDoesNotThrow(() -> {
            ruleManager.saveRules();
        });

        // Create new manager and initialize again - should load existing rules
        RuleManager newManager = new RuleManager(storage);
        newManager.initializeWithDefaults(Arrays.asList(rule3));
        assertEquals(2, newManager.getRuleCount()); // Should load existing, not defaults
        assertNotNull(newManager.getRuleById("rule-1"));
        assertNotNull(newManager.getRuleById("rule-2"));
    }

    @Test
    void testInitializeWithDefaultsWhenLoadFails() throws IOException {
        Files.writeString(Path.of(storage.getConfigFilePath()), "invalid JSON");
        RuleManager managerWithInvalidStorage = new RuleManager(storage);

        List<ProcessingRule> defaultRules = Arrays.asList(rule1, rule2);
        managerWithInvalidStorage.initializeWithDefaults(defaultRules);

        // Should use defaults when load fails
        assertEquals(2, managerWithInvalidStorage.getRuleCount());
        assertNotNull(managerWithInvalidStorage.getRuleById("rule-1"));
        assertNotNull(managerWithInvalidStorage.getRuleById("rule-2"));
    }

    @Test
    void testToString() {
        ruleManager.addRule(rule1);
        ruleManager.addRule(rule2);

        String str = ruleManager.toString();
        assertTrue(str.contains("RuleManager"));
        assertTrue(str.contains("ruleCount=2"));
        assertTrue(str.contains("enabledCount=1"));
    }

    @Test
    void testThreadSafety() throws InterruptedException {
        final int numThreads = 10;
        final int numOperationsPerThread = 100;
        Thread[] threads = new Thread[numThreads];

        for (int i = 0; i < numThreads; i++) {
            final int threadId = i;
            threads[i] = new Thread(() -> {
                for (int j = 0; j < numOperationsPerThread; j++) {
                    String ruleId = "rule-" + threadId + "-" + j;
                    ProcessingRule rule = createTestRule(ruleId, "Rule " + ruleId, true, j);

                    try {
                        ruleManager.addRule(rule);
                        ruleManager.getRuleById(ruleId);
                        ruleManager.setRuleEnabled(ruleId, j % 2 == 0);
                        if (j % 10 == 0) {
                            ruleManager.removeRule(ruleId);
                        }
                    } catch (Exception e) {
                        // Expected for duplicate additions
                    }
                }
            });
        }

        for (Thread thread : threads) {
            thread.start();
        }

        for (Thread thread : threads) {
            thread.join();
        }

        // Verify manager is still in a consistent state
        assertTrue(ruleManager.getRuleCount() >= 0);
        assertTrue(ruleManager.getEnabledRuleCount() >= 0);
        assertTrue(ruleManager.getEnabledRuleCount() <= ruleManager.getRuleCount());
    }
}
