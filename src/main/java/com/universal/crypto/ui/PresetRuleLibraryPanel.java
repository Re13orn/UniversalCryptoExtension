package com.universal.crypto.ui;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import burp.api.montoya.MontoyaApi;
import com.universal.crypto.engine.DefaultRuleFactory;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleSerializer;
import java.util.ArrayList;
import java.util.Locale;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import com.universal.crypto.util.LanguageManager;
import com.universal.crypto.util.Logger;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.List;

/**
 * Panel for managing the preset rule library.
 * <p>
 * Displays a list of built-in preset rules (available in {@link DefaultRuleFactory}) that users can
 * add to their active rule configuration. It prevents duplicate addition by checking existing Rule IDs.
 * Provides a preview functionality to inspect the JSON structure of a preset rule before adding.
 */
public class PresetRuleLibraryPanel extends JPanel {

    private static final Logger logger = Logger.getInstance();
    private final LanguageManager lang = LanguageManager.getInstance();

    private final MontoyaApi api;
    private final RuleManager ruleManager;
    private final java.util.function.Consumer<com.universal.crypto.model.ProcessingAction> playgroundNavigator;

    // UI Components
    private JList<PresetRuleItem> presetRuleList;
    private DefaultListModel<PresetRuleItem> listModel;
    private JTextArea ruleDescriptionArea;
    private JButton addButton;
    private JButton previewButton;
    private JLabel statusLabel;
    private JTextField searchField;
    private JButton customizeButton;
    private JSplitPane mainSplit;
    private boolean loading;
    private List<ProcessingRule> catalog = List.of();

    public PresetRuleLibraryPanel(MontoyaApi api, RuleManager ruleManager, java.util.function.Consumer<com.universal.crypto.model.ProcessingAction> playgroundNavigator) {
        this.api = api;
        this.ruleManager = ruleManager;
        this.playgroundNavigator = playgroundNavigator;
        
        rebuildUI();
        loadPresetRules();
    }
    
    public void rebuildUI() {
        this.removeAll();
        initializeUI();
        this.revalidate();
        this.repaint();
    }

    private void initializeUI() {
        setLayout(new BorderLayout());
        setBorder(UIStyle.emptyBorder());
        setBackground(UIStyle.background());

        // Header
        add(createHeaderPanel(), BorderLayout.NORTH);

        // Main content
        add(createMainPanel(), BorderLayout.CENTER);

        // Footer
        add(createFooterPanel(), BorderLayout.SOUTH);
    }

    private JPanel createHeaderPanel() {
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setOpaque(false);
        headerPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

        JLabel titleLabel = new JLabel(lang.getString("library.title"));
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 17f));

        JLabel descLabel = UIStyle.mutedLabel(lang.getString("library.desc"));

        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setOpaque(false);
        leftPanel.add(titleLabel, BorderLayout.NORTH);
        leftPanel.add(descLabel, BorderLayout.CENTER);

        headerPanel.add(leftPanel, BorderLayout.WEST);

        return headerPanel;
    }

    private JPanel createMainPanel() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setOpaque(false);

        // Left side - rule list
        JPanel leftPanel = createRuleListPanel();

        // Right side - details and actions
        JPanel rightPanel = createDetailsPanel();

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        mainSplit = splitPane;
        SplitPaneLayout.initialize(splitPane, 0.35);
        leftPanel.setMinimumSize(new Dimension(180, 0));
        rightPanel.setMinimumSize(new Dimension(0, 0));
        splitPane.setDividerSize(8);
        splitPane.setBorder(BorderFactory.createEmptyBorder());

        mainPanel.add(splitPane, BorderLayout.CENTER);

        return mainPanel;
    }

    private JPanel createRuleListPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(UIStyle.sectionBorder(lang.getString("library.list.title")));
        panel.setBackground(UIStyle.background());

        JPanel filters = new JPanel(new BorderLayout(6, 6));
        filters.setOpaque(false);
        searchField = new JTextField();
        searchField.setToolTipText(lang.getString("library.search"));
        filters.add(new JLabel(lang.getString("library.search")), BorderLayout.NORTH);
        filters.add(searchField, BorderLayout.CENTER);
        panel.add(filters, BorderLayout.NORTH);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filterCatalog(); }
            public void removeUpdate(DocumentEvent e) { filterCatalog(); }
            public void changedUpdate(DocumentEvent e) { filterCatalog(); }
        });

        // Rule list
        listModel = new DefaultListModel<>();
        presetRuleList = new JList<>(listModel);
        presetRuleList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        presetRuleList.setCellRenderer(new PresetRuleListCellRenderer());
        presetRuleList.setFixedCellHeight(Math.max(30, presetRuleList.getFontMetrics(presetRuleList.getFont()).getHeight() + 10));
        presetRuleList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateRuleDetails();
            }
        });

        JScrollPane scrollPane = UIStyle.scroll(presetRuleList);
        scrollPane.setPreferredSize(new Dimension(380, 300));

        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createDetailsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(UIStyle.sectionBorder(lang.getString("library.details.title")));
        panel.setBackground(UIStyle.background());

        // Description area
        ruleDescriptionArea = new JTextArea();
        ruleDescriptionArea.setEditable(false);
        UIStyle.styleTextArea(ruleDescriptionArea, true);
        ruleDescriptionArea.setText(""); // Initial empty

        JScrollPane descScrollPane = UIStyle.scroll(ruleDescriptionArea);
        descScrollPane.setPreferredSize(new Dimension(300, 200));

        panel.add(descScrollPane, BorderLayout.CENTER);

        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.setOpaque(false);

        previewButton = UIStyle.button(lang.getString("library.btn.preview"));
        previewButton.setEnabled(false);
        previewButton.addActionListener(this::previewRule);

        addButton = UIStyle.primaryButton(lang.getString("library.btn.add"));
        addButton.setIcon(UIStyle.icon(UIStyle.IconType.ADD));
        addButton.setEnabled(false);
        addButton.addActionListener(this::addSelectedRule);

        customizeButton = UIStyle.button(lang.getString("library.btn.customize"));
        customizeButton.setEnabled(false);
        customizeButton.addActionListener(e -> customizeSelectedRule());
        buttonPanel.add(previewButton);
        buttonPanel.add(customizeButton);
        buttonPanel.add(addButton);

        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createFooterPanel() {
        JPanel footerPanel = new JPanel(new BorderLayout());
        footerPanel.setOpaque(false);
        footerPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));

        statusLabel = UIStyle.mutedLabel(lang.getString("library.status.ready"));

        JLabel hintLabel = UIStyle.mutedLabel(lang.getString("library.hint.add"));

        footerPanel.add(statusLabel, BorderLayout.WEST);
        footerPanel.add(hintLabel, BorderLayout.EAST);

        return footerPanel;
    }

    private void loadPresetRules() {
        catalog = DefaultRuleFactory.getAllDefaultRules();
        filterCatalog();
    }

    private void filterCatalog() {
        if (loading || listModel == null) return;
        PresetRuleItem selected = presetRuleList.getSelectedValue();
        String id = selected == null ? null : selected.getRule().getId();
        String query = searchField.getText().trim().toLowerCase(Locale.ROOT);
        List<ProcessingRule> current = ruleManager.getAllRules();
        listModel.clear();
        for (ProcessingRule preset : catalog) {
            String phases = java.util.stream.Stream.concat(preset.getRequestActions().stream(), preset.getResponseActions().stream())
                    .map(action -> action.getConfigString("executionPhase", "")).collect(java.util.stream.Collectors.joining(" "));
            String searchable = preset.getName() + " " + preset.getId() + " " + preset.getDescription()
                    + " " + RuleActionDescriber.describeRule(preset, lang) + " " + phases;
            if (!searchable.toLowerCase(Locale.ROOT).contains(query)) continue;
            listModel.addElement(new PresetRuleItem(preset, current.stream().anyMatch(r -> r.getId().equals(preset.getId()))));
            if (preset.getId().equals(id)) presetRuleList.setSelectedIndex(listModel.size() - 1);
        }
        statusLabel.setText(lang.format("library.status.count", listModel.size(), catalog.size()));
        updateRuleDetails();
    }

    private void updateRuleDetails() {
        PresetRuleItem selected = presetRuleList.getSelectedValue();
        if (selected == null) {
            ruleDescriptionArea.setText("");
            addButton.setEnabled(false);
            previewButton.setEnabled(false);
            customizeButton.setEnabled(false);
            return;
        }

        ProcessingRule rule = selected.getRule();
        StringBuilder details = new StringBuilder();
        details.append("名称: ").append(rule.getName()).append("\nID: ").append(rule.getId()).append("\n");
        details.append(lang.getString("library.details.draft")).append("\n\n");
        details.append(rule.getDescription()).append("\n\n");
        details.append("Host: ").append(RuleActionDescriber.listOrAny(rule.getCondition().getHosts())).append('\n');
        details.append("Path: ").append(RuleActionDescriber.listOrAny(rule.getCondition().getPaths())).append('\n');
        details.append("Method: ").append(RuleActionDescriber.listOrAny(rule.getCondition().getMethods())).append('\n');
        details.append("Tool: ").append(rule.getCondition().getToolSource()).append("\n\n");
        details.append(RuleActionDescriber.describeRule(rule, lang));
        if (selected.isAlreadyExists()) details.append("\n").append(lang.getString("library.details.existing"));
        ruleDescriptionArea.setText(details.toString());
        ruleDescriptionArea.setCaretPosition(0);

        addButton.setEnabled(!selected.isAlreadyExists());
        previewButton.setEnabled(true);
        customizeButton.setEnabled(true);
    }

    private void previewRule(ActionEvent e) {
        PresetRuleItem selected = presetRuleList.getSelectedValue();
        if (selected == null) return;

        try {
            ProcessingRule rule = selected.getRule();
            String json = RuleSerializer.exportRules(List.of(rule));
            
            JTextArea textArea = new JTextArea(json);
            textArea.setEditable(false);
            UIStyle.styleTextArea(textArea, true);
            JScrollPane scrollPane = UIStyle.scroll(textArea);
            scrollPane.setPreferredSize(new Dimension(500, 400));
            
            JOptionPane.showMessageDialog(this, scrollPane, 
                lang.getString("library.preview.title") + ": " + rule.getName(), 
                JOptionPane.INFORMATION_MESSAGE);
                
        } catch (Exception ex) {
            logger.error("Failed to preview rule", ex);
            JOptionPane.showMessageDialog(this, "Error previewing rule: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void addSelectedRule(ActionEvent e) {
        PresetRuleItem selected = presetRuleList.getSelectedValue();
        if (selected == null) return;

        try {
            ProcessingRule template = selected.getRule();
            if (selected.isAlreadyExists()) return;
            addDraft(template);
            JOptionPane.showMessageDialog(this, 
                lang.format("library.msg.added", template.getName()), 
                "Success", JOptionPane.INFORMATION_MESSAGE);
                
            refreshPresetRules(); // Refresh list to show the imported state
            
        } catch (Exception ex) {
            logger.error("Failed to add preset rule", ex);
            JOptionPane.showMessageDialog(this, "Error adding rule: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void customizeSelectedRule() {
        PresetRuleItem selected = presetRuleList.getSelectedValue();
        if (selected == null) return;
        ProcessingRule draft = selected.getRule().clone();
        draft.setId(selected.getRule().getId() + "-custom-" + java.util.UUID.randomUUID());
        draft.setEnabled(false);
        RuleEditDialog dialog = new RuleEditDialog(SwingUtilities.getWindowAncestor(this), draft, playgroundNavigator);
        dialog.setDraftOnly();
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            try {
                addDraft(dialog.getRule());
                refreshPresetRules();
            } catch (Exception ex) {
                logger.error("Failed to add customized preset", ex);
                JOptionPane.showMessageDialog(this, ex.getMessage(), lang.getString("error.title"), JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    void addDraft(ProcessingRule template) {
        ProcessingRule draft = template.clone();
        draft.setEnabled(false);
        ruleManager.addRuleAndSave(draft);
    }

    // ... helper methods remain same ...
    
    /**
     * Refresh the preset rules list
     */
    public void refreshPresetRules() {
        SwingUtilities.invokeLater(() -> {
            try {
                String query = searchField.getText();
                PresetRuleItem selected = presetRuleList.getSelectedValue();
                String id = selected == null ? null : selected.getRule().getId();
                rebuildUI();
                loading = true;
                searchField.setText(query);
                loading = false;
                loadPresetRules();
                for (int i = 0; i < listModel.size(); i++)
                    if (listModel.get(i).getRule().getId().equals(id)) presetRuleList.setSelectedIndex(i);
            } catch (Exception ex) {
                logger.error("Failed to refresh preset rules", ex);
            }
        });
    }

    private static class PresetRuleItem {
        private final ProcessingRule rule;
        private boolean alreadyExists;

        public PresetRuleItem(ProcessingRule rule, boolean alreadyExists) {
            this.rule = rule;
            this.alreadyExists = alreadyExists;
        }

        public ProcessingRule getRule() { return rule; }
        public boolean isAlreadyExists() { return alreadyExists; }
        public void setAlreadyExists(boolean alreadyExists) { this.alreadyExists = alreadyExists; }

        @Override
        public String toString() {
            return rule.getName();
        }
    }

    private static class PresetRuleListCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (value instanceof PresetRuleItem) {
                PresetRuleItem item = (PresetRuleItem) value;
                setText(item.toString());
                setToolTipText(item.toString() + " — " + LanguageManager.getInstance().getString(item.isAlreadyExists() ? "library.item.added" : "library.item.draft"));
                setIcon(UIStyle.dot(item.isAlreadyExists() ? UIStyle.success() : UIStyle.mutedText()));
            }
            return this;
        }
    }
}
