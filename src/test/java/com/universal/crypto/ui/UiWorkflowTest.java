package com.universal.crypto.ui;

import com.universal.crypto.engine.RuleMatchEngine;
import com.universal.crypto.handler.HttpRequestContext;
import com.universal.crypto.handler.HttpResponseContext;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorFactory;
import com.universal.crypto.ui.processor.CryptoConfigPanel;
import com.universal.crypto.ui.processor.SignatureConfigPanel;
import com.universal.crypto.util.LanguageManager;
import org.junit.jupiter.api.Test;
import javax.swing.*;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class UiWorkflowTest {
    @Test void collapsingNeverRemovesFieldsAndExpansionUsesCurrentPreferredHeight() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            JPanel fields = new JPanel(); JTextField input = new JTextField("keep this", 20); fields.add(input);
            var section = new CollapsibleSection("Advanced", fields);
            int collapsed = section.getPreferredSize().height;
            section.setExpanded(true);
            assertTrue(section.getPreferredSize().height > collapsed);
            assertEquals(section.getPreferredSize().height, section.getMaximumSize().height);
            section.setExpanded(false); assertEquals(fields, input.getParent());
            assertEquals("keep this", input.getText());
            section.setConfigured(true); assertTrue(section.isExpanded());
        });
    }

    @Test void configuredCryptoAdvancedValuesAreVisibleAndSurviveCollapsedSave() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new CryptoConfigPanel(); var action = new ProcessingAction("encrypt", "body", "crypto");
            action.setConfig(Map.of("algorithm", "AES-GCM", "cryptoProvider", "internal", "charset", "UTF-16LE", "gcmTagLength", "96"));
            panel.loadConfig(action);
            var section = field(panel, "advancedSection", CollapsibleSection.class);
            assertTrue(section.isExpanded()); section.setExpanded(false);
            var result = new ProcessingAction(); panel.saveConfig(result);
            assertEquals("UTF-16LE", result.getConfigString("charset"));
            assertEquals("96", result.getConfigString("gcmTagLength"));
            assertEquals("internal", result.getConfigString("cryptoProvider"));
        });
    }

    @Test void defaultCryptoAdvancedOptionsStartCollapsed() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new CryptoConfigPanel(); panel.loadConfig(new ProcessingAction("encrypt", "body", "crypto"));
            assertFalse(field(panel, "advancedSection", CollapsibleSection.class).isExpanded());
        });
    }

    @Test void configuredCanonicalizationSurvivesCollapsedSaveInBothLanguages() throws Exception {
        var lang = LanguageManager.getInstance(); String previous = lang.getCurrentLocale().getLanguage();
        try { for (String locale : List.of("zh", "en")) {
            lang.setLanguage(locale);
            SwingUtilities.invokeAndWait(() -> {
                var panel = new SignatureConfigPanel(); var action = new ProcessingAction("sign", "header", "signature");
                action.setConfig(Map.of("algorithm", "HmacSHA256", "cryptoProvider", "internal", "keySource", "lookup", "sortKeys", true,
                        "urlEncodeValues", true, "pairSeparator", ";", "kvSeparator", ":", "customSignTemplate", "${body}"));
                panel.loadConfig(action); var section = field(panel, "canonicalSection", CollapsibleSection.class);
                assertTrue(section.isExpanded()); section.setExpanded(false);
                var saved = new ProcessingAction(); panel.saveConfig(saved);
                assertEquals("internal", saved.getConfigString("cryptoProvider")); assertEquals("lookup", saved.getConfigString("keySource"));
                assertEquals(true, saved.getConfig().get("sortKeys")); assertEquals(";", saved.getConfigString("pairSeparator"));
                assertEquals(":", saved.getConfigString("kvSeparator")); assertEquals("${body}", saved.getConfigString("customSignTemplate"));
            });
        }} finally { lang.setLanguage(previous); }
    }

    private LiveTracePanel populated() throws Exception {
        LiveTracePanel[] holder = new LiveTracePanel[1];
        SwingUtilities.invokeAndWait(() -> holder[0] = new LiveTracePanel(null, new RuleMatchEngine(), ProcessorFactory.createDefaultProcessorManager(null)));
        var request = HttpRequestContext.builder().method("POST").url(new URL("https://example.test/api")).headers(Map.of()).body("secret-body").toolSource("REPEATER").build();
        var response = HttpResponseContext.builder().method("POST").url(new URL("https://example.test/api")).headers(Map.of()).body("encrypted").toolSource("PROXY").build();
        var panel = holder[0];
        panel.addLogEntry("POST", "https://example.test/API?a=[", "Processed", "HMAC rule", request, request.withBody("changed"));
        panel.addLogEntry("GET", "https://example.test/other", "Response Observed", "AES rule", response, response);
        panel.addLogEntry("POST", "https://example.test/action", "Action Changed", "HMAC rule", request, request.withBody("changed"));
        panel.addLogEntry("POST", "https://example.test/failed", "Action Failed", "AES rule", response, response);
        SwingUtilities.invokeAndWait(() -> {}); return panel;
    }

    @Test void literalSearchIgnoresCaseIncludesToolAndDoesNotSearchBodies() throws Exception {
        var panel = populated();
        SwingUtilities.invokeAndWait(() -> {
            var table = field(panel, "logTable", JTable.class); var query = field(panel, "searchField", JTextField.class);
            query.setText("api?a=["); assertEquals(1, table.getRowCount());
            query.setText("hMaC"); assertEquals(2, table.getRowCount());
            query.setText("REPEATER"); assertEquals(2, table.getRowCount());
            query.setText("secret-body"); assertEquals(0, table.getRowCount());
            query.setText(""); assertEquals(4, table.getRowCount());
        });
    }

    @Test void semanticFiltersCombineWithoutTreatingFailuresAsUnchanged() throws Exception {
        var panel = populated();
        SwingUtilities.invokeAndWait(() -> {
            var table = field(panel, "logTable", JTable.class);
            var direction = field(panel, "directionFilter", JComboBox.class);
            var result = field(panel, "resultFilter", JComboBox.class); var kind = field(panel, "kindFilter", JComboBox.class);
            result.setSelectedIndex(2); assertEquals(1, table.getRowCount());
            result.setSelectedIndex(3); assertEquals(1, table.getRowCount());
            direction.setSelectedIndex(1); assertEquals(0, table.getRowCount());
            direction.setSelectedIndex(0); result.setSelectedIndex(1); assertEquals(2, table.getRowCount());
            kind.setSelectedIndex(1); assertEquals(1, table.getRowCount());
            assertEquals(1L, table.getValueAt(0, 0));
            assertEquals(4, table.getModel().getRowCount());
        });
    }

    @Test void filteringOutSelectionClearsAllDetailsAndDisablesPreview() throws Exception {
        var panel = populated();
        SwingUtilities.invokeAndWait(() -> {
            var table = field(panel, "logTable", JTable.class); table.setRowSelectionInterval(1, 1);
            assertFalse(field(panel, "summaryArea", JTextArea.class).getText().isEmpty());
            field(panel, "searchField", JTextField.class).setText("does-not-exist");
            assertEquals(-1, table.getSelectedRow());
            for (String name : List.of("originalArea", "modifiedArea", "summaryArea")) assertTrue(field(panel, name, JTextArea.class).getText().isEmpty());
            assertFalse(field(panel, "previewButton", JButton.class).isEnabled());
            field(panel, "searchField", JTextField.class).setText("");
            assertEquals(-1, table.getSelectedRow()); assertFalse(field(panel, "previewButton", JButton.class).isEnabled());
        });
    }

    @Test void languageRefreshKeepsFiltersSortAndVisibleSelection() throws Exception {
        var panel = populated(); var lang = LanguageManager.getInstance(); String previous = lang.getCurrentLocale().getLanguage();
        try { SwingUtilities.invokeAndWait(() -> {
            var table = field(panel, "logTable", JTable.class);
            field(panel, "searchField", JTextField.class).setText("HMAC");
            field(panel, "kindFilter", JComboBox.class).setSelectedIndex(1);
            table.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.DESCENDING)));
            table.setRowSelectionInterval(0, 0); lang.setLanguage("zh"); panel.refresh();
            assertEquals("HMAC", field(panel, "searchField", JTextField.class).getText());
            assertEquals(1, field(panel, "kindFilter", JComboBox.class).getSelectedIndex());
            assertEquals(1, table.getRowCount()); assertEquals(1L, table.getValueAt(table.getSelectedRow(), 0));
            assertEquals(SortOrder.DESCENDING, table.getRowSorter().getSortKeys().get(0).getSortOrder());
            assertTrue(field(panel, "filterCount", JLabel.class).getText().contains("1 / 4"));
        }); } finally { lang.setLanguage(previous); }
    }

    @Test void newEntriesRespectActiveFilterAndRemainCaptured() throws Exception {
        var panel = populated();
        SwingUtilities.invokeAndWait(() -> field(panel, "searchField", JTextField.class).setText("later"));
        var context = HttpRequestContext.builder().method("GET").url(new URL("https://example.test")).headers(Map.of()).body("").build();
        panel.addLogEntry("GET", "https://example.test/later", "Processed", "rule", context, context);
        panel.addLogEntry("GET", "https://example.test/hidden", "Processed", "rule", context, context);
        SwingUtilities.invokeAndWait(() -> {
            var table = field(panel, "logTable", JTable.class); assertEquals(1, table.getRowCount()); assertEquals(6, table.getModel().getRowCount());
            assertTrue(field(panel, "filterCount", JLabel.class).getText().contains("1 / 6"));
        });
    }

    @Test void signingVariableHelpAndPresetsWorkUnderEnglishLocale() throws Exception {
        var lang = LanguageManager.getInstance(); String previous = lang.getCurrentLocale().getLanguage();
        try { lang.setLanguage("en"); SwingUtilities.invokeAndWait(() -> {
            var panel = new SignatureConfigPanel(); field(panel, "conceptGuideCombo", JComboBox.class).setSelectedItem(lang.getString("form.sign.topic.template"));
            String text = field(panel, "conceptGuideArea", JTextArea.class).getText();
            assertTrue(text.contains("${header.Timestamp}")); assertTrue(text.contains("${stablejson:payload}"));
            assertTrue(text.contains("Signing template")); assertFalse(text.matches("(?s).*[\\p{IsHan}].*"));
            field(panel, "protocolPresetCombo", JComboBox.class).setSelectedIndex(2);
            try { var method = SignatureConfigPanel.class.getDeclaredMethod("applySelectedProtocolPreset"); method.setAccessible(true); method.invoke(panel); }
            catch (Exception ex) { throw new RuntimeException(ex); }
            var saved = new ProcessingAction(); panel.saveConfig(saved); assertEquals("SHA-256", saved.getConfigString("algorithm")); assertEquals("none", saved.getConfigString("keySource"));
        }); } finally { lang.setLanguage(previous); }
    }

    @Test void sharedHelpHasNoMissingOrMixedLanguageAndDocumentsRealWriteBackSemantics() throws Exception {
        var lang = LanguageManager.getInstance(); String previous = lang.getCurrentLocale().getLanguage();
        try { for (String locale : List.of("zh", "en")) {
            lang.setLanguage(locale);
            SwingUtilities.invokeAndWait(() -> {
                var script = new com.universal.crypto.ui.processor.ScriptConfigPanel();
                var playground = new PlaygroundPanel(null, ProcessorFactory.createDefaultProcessorManager(null));
                for (int i = 0; i < 8; i++) {
                    field(script, "guideCombo", JComboBox.class).setSelectedIndex(i);
                    field(playground, "scriptGuideCombo", JComboBox.class).setSelectedIndex(i);
                    String help = field(script, "guideArea", JTextArea.class).getText();
                    assertEquals(help, field(playground, "scriptGuideArea", JTextArea.class).getText());
                    assertFalse(help.startsWith("!")); assertFalse(help.isBlank());
                    if (locale.equals("en")) assertFalse(help.matches("(?s).*[\\p{IsHan}].*"), help);
                }
                String jsonHelp = com.universal.crypto.ui.processor.ScriptHelp.guide(3);
                assertTrue(jsonHelp.contains("targetType=field"));
                if (locale.equals("en")) assertTrue(jsonHelp.contains("complete body"));
                var sign = new SignatureConfigPanel();
                var topics = field(sign, "conceptGuideCombo", JComboBox.class);
                for (int i = 0; i < topics.getItemCount(); i++) {
                    topics.setSelectedIndex(i);
                    String help = field(sign, "conceptGuideArea", JTextArea.class).getText();
                    assertFalse(help.startsWith("!"));
                    if (locale.equals("en")) assertFalse(help.matches("(?s).*[\\p{IsHan}].*"), help);
                }
            });
        }} finally { lang.setLanguage(previous); }
    }

    @Test void evictedSelectionCannotLeaveAnotherRowHighlightedOrExposeStaleDetails() throws Exception {
        var panel = populated();
        SwingUtilities.invokeAndWait(() -> {
            var table = field(panel, "logTable", JTable.class); table.setRowSelectionInterval(3, 3);
            field(panel, "searchField", JTextField.class).setText("example.test");
        });
        var context = HttpRequestContext.builder().method("GET").url(new URL("https://example.test")).headers(Map.of()).body("").build();
        for (int i = 0; i < 1001; i++) panel.addLogEntry("GET", "https://example.test/" + i, "Processed", "rule", context, context);
        SwingUtilities.invokeAndWait(() -> {
            var table = field(panel, "logTable", JTable.class);
            assertEquals(1000, table.getRowCount()); assertEquals(1000, field(panel, "traceEntries", List.class).size());
            assertEquals(-1, table.getSelectedRow()); assertTrue(field(panel, "summaryArea", JTextArea.class).getText().isEmpty());
            assertFalse(field(panel, "previewButton", JButton.class).isEnabled());
        });
    }

    @Test void resetClearsAllFiltersWithoutDeletingCapturedRows() throws Exception {
        var panel = populated();
        SwingUtilities.invokeAndWait(() -> {
            field(panel, "searchField", JTextField.class).setText("no-match");
            field(panel, "directionFilter", JComboBox.class).setSelectedIndex(1);
            field(panel, "resultFilter", JComboBox.class).setSelectedIndex(3);
            field(panel, "kindFilter", JComboBox.class).setSelectedIndex(2);
            var reset = findButton(panel, LanguageManager.getInstance().getString("trace.filter.reset"));
            assertNotNull(reset); reset.doClick();
            assertEquals("", field(panel, "searchField", JTextField.class).getText());
            assertEquals(4, field(panel, "logTable", JTable.class).getRowCount());
        });
    }

    @Test void processorFormsTrackViewportWidthInsteadOfForcingHorizontalScrolling() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            for (JPanel form : List.of(new CryptoConfigPanel().getPanel(), new SignatureConfigPanel().getPanel())) {
                JScrollPane scroll = new JScrollPane(form);
                for (int width : List.of(480, 840)) {
                    scroll.setSize(width, 700); layout(scroll);
                    assertTrue(form instanceof Scrollable);
                    assertEquals(scroll.getViewport().getWidth(), form.getWidth());
                    assertFalse(scroll.getHorizontalScrollBar().isVisible());
                }
            }
        });
    }

    private static void layout(java.awt.Container root) {
        root.doLayout();
        for (var child : root.getComponents()) if (child instanceof java.awt.Container nested) layout(nested);
    }

    private static JButton findButton(java.awt.Container root, String title) {
        for (var child : root.getComponents()) {
            if (child instanceof JButton button && title.equals(button.getText())) return button;
            if (child instanceof java.awt.Container nested) { var found = findButton(nested, title); if (found != null) return found; }
        }
        return null;
    }

    private static <T> T field(Object object, String name, Class<T> type) {
        try { Field field = object.getClass().getDeclaredField(name); field.setAccessible(true); return type.cast(field.get(object)); }
        catch (Exception ex) { throw new RuntimeException(ex); }
    }
}
