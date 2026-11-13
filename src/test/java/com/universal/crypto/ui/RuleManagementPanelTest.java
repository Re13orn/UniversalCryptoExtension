package com.universal.crypto.ui;

import com.universal.crypto.engine.RuleConfigStorage;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleSerializer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import java.awt.*;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class RuleManagementPanelTest {

    @TempDir
    Path tempDir;

    @Test
    void usesScrollableTopControlsWithoutMoveButtons() {
        RuleManager ruleManager = new RuleManager(new RuleConfigStorage(tempDir.toString()));
        ProcessingRule rule = new ProcessingRule("test-rule");
        rule.setName("Test Rule");
        rule.setEnabled(true);
        rule.setCategory("signature");
        ruleManager.addRule(rule);

        RuleManagementPanel panel = new RuleManagementPanel(null, ruleManager, action -> {});
        List<JButton> buttons = findComponents(panel, JButton.class);

        assertTrue(buttons.stream().noneMatch(button -> button.getText() != null
                && (button.getText().contains("上移") || button.getText().contains("Move Up"))));
        assertTrue(buttons.stream().noneMatch(button -> button.getText() != null
                && (button.getText().contains("下移") || button.getText().contains("Move Down"))));

        List<JScrollPane> scrollPanes = findComponents(panel, JScrollPane.class);
        long horizontalControlBars = scrollPanes.stream()
                .filter(scrollPane -> scrollPane.getVerticalScrollBarPolicy() == ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER)
                .filter(scrollPane -> scrollPane.getHorizontalScrollBarPolicy() == ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)
                .count();

        assertTrue(horizontalControlBars >= 2, "filter row and action row should scroll horizontally on small screens");
    }

    @Test void failedBatchEnableKeepsSelectedRowsDiskAndRuntimeStateConsistent() throws Exception {
        var storage = new RuleConfigStorage(tempDir.toString()) {
            boolean fail;
            @Override public void saveRules(List<ProcessingRule> candidate) throws java.io.IOException {
                if (fail) throw new java.io.IOException("simulated storage failure");
                super.saveRules(candidate);
            }
        };
        var manager = new RuleManager(storage);
        var first = new ProcessingRule("first"); first.setName("Zulu"); first.setEnabled(false);
        var second = new ProcessingRule("second"); second.setName("Alpha"); second.setEnabled(false);
        manager.updateRulesAndSave(candidate -> candidate.addAll(List.of(first, second)));
        long revision = manager.getRevision(); var notifications = new AtomicInteger();
        manager.addRuleChangeListener(notifications::incrementAndGet); storage.fail = true;
        SwingUtilities.invokeAndWait(() -> {
            var panel = new RuleManagementPanel(null, manager, null);
            var table = findComponents(panel, JTable.class).get(0);
            table.getRowSorter().toggleSortOrder(1); table.setRowSelectionInterval(0, 1);
            assertThrows(RuntimeException.class, () -> panel.saveSelectedRuleStatus(true));
            assertEquals(2, table.getSelectedRowCount());
            assertEquals("N", table.getValueAt(0, 0)); assertEquals("N", table.getValueAt(1, 0));
        });
        assertEquals(RuleSerializer.toJson(List.of(first, second)), RuleSerializer.toJson(manager.getAllRules()));
        assertEquals(RuleSerializer.toJson(List.of(first, second)), RuleSerializer.toJson(storage.loadRules()));
        assertEquals(revision, manager.getRevision()); assertEquals(0, notifications.get());
        storage.fail = false;
        SwingUtilities.invokeAndWait(() -> {
            var panel = new RuleManagementPanel(null, manager, null);
            var table = findComponents(panel, JTable.class).get(0); table.setRowSelectionInterval(0, 1);
            panel.saveSelectedRuleStatus(true);
            assertEquals("Y", table.getValueAt(0, 0)); assertEquals("Y", table.getValueAt(1, 0));
            assertEquals(2, table.getSelectedRowCount());
        });
        assertEquals(revision + 1, manager.getRevision()); assertEquals(1, notifications.get());
        assertEquals(RuleSerializer.toJson(storage.loadRules()), RuleSerializer.toJson(manager.getAllRules()));
    }

    @Test void failedPresetInsertionNeverPublishesATemporaryDraft() {
        var manager = new RuleManager(new RuleConfigStorage(tempDir.toString()) {
            @Override public void saveRules(List<ProcessingRule> candidate) throws java.io.IOException {
                throw new java.io.IOException("simulated storage failure");
            }
        });
        long revision = manager.getRevision(); var notifications = new AtomicInteger();
        manager.addRuleChangeListener(notifications::incrementAndGet);
        var panel = new PresetRuleLibraryPanel(null, manager, null);
        assertThrows(RuntimeException.class, () -> panel.addDraft(new ProcessingRule("draft")));
        assertEquals(0, manager.getRuleCount()); assertEquals(revision, manager.getRevision());
        assertEquals(0, notifications.get());
    }

    private <T extends Component> List<T> findComponents(Component root, Class<T> type) {
        List<T> result = new ArrayList<>();
        if (type.isInstance(root)) {
            result.add(type.cast(root));
        }
        if (root instanceof Container) {
            for (Component child : ((Container) root).getComponents()) {
                result.addAll(findComponents(child, type));
            }
        }
        return result;
    }
}
