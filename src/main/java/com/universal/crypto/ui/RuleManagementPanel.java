package com.universal.crypto.ui;

import burp.api.montoya.MontoyaApi;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleCondition;
import com.universal.crypto.util.DebugUtil;
import com.universal.crypto.util.LanguageManager;
import com.universal.crypto.util.Logger;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Panel for managing processing rules
 */
public class RuleManagementPanel extends JPanel {

    private static final Logger logger = Logger.getInstance();
    private final LanguageManager lang = LanguageManager.getInstance();

    private final MontoyaApi api;
    private final RuleManager ruleManager;
    private final java.util.function.Consumer<com.universal.crypto.model.ProcessingAction> playgroundNavigator;

    // UI Components
    private JTable rulesTable;
    private RuleTableModel tableModel;
    
    // Buttons
    private JButton wizardButton;
    private JButton presetButton;
    private JButton importButton;
    private JButton exportButton;
    private JButton addButton;
    private JButton editButton;
    private JButton copyButton;
    private JButton deleteButton;
    private JButton enableButton;
    private JButton disableButton;
    
    // Details
    private JTextArea ruleDetailsArea;

    // Filters & Batch
    private JComboBox<String> categoryFilter;
    private JComboBox<String> statusFilter;
    private JLabel statisticsLabel;
    private JButton refreshButton;
    private JSplitPane splitPane;
    private boolean updatingCategories;

    // Current filter state
    private String currentCategoryFilter = "all";
    private String currentStatusFilter = "all";

    public RuleManagementPanel(MontoyaApi api, RuleManager ruleManager, java.util.function.Consumer<com.universal.crypto.model.ProcessingAction> playgroundNavigator) {
        this.api = api;
        this.ruleManager = ruleManager;
        this.playgroundNavigator = playgroundNavigator;

        rebuildUI();
        loadRules();
        logger.debug("RuleManagementPanel initialized");
    }

    public void rebuildUI() {
        this.removeAll();
        setLayout(new BorderLayout());
        setBorder(UIStyle.emptyBorder());
        setBackground(UIStyle.background());

        // Create main split pane
        double ratio = SplitPaneLayout.ratio(splitPane, 0.7);
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        SplitPaneLayout.initialize(splitPane, ratio);
        splitPane.setBorder(BorderFactory.createEmptyBorder());
        splitPane.setDividerSize(8);

        // Top panel - rules table and buttons
        JPanel topPanel = createRulesTablePanel();
        splitPane.setTopComponent(topPanel);

        // Bottom panel - rule details
        JPanel bottomPanel = createRuleDetailsPanel();
        splitPane.setBottomComponent(bottomPanel);

        add(splitPane, BorderLayout.CENTER);
        
        this.revalidate();
        this.repaint();
    }

    /**
     * Create the rules table panel
     */
    private JPanel createRulesTablePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(UIStyle.sectionBorder(lang.getString("rules.title")));
        panel.setBackground(UIStyle.background());

        JPanel controlsPanel = new JPanel(new BorderLayout(0, 8));
        controlsPanel.setOpaque(false);
        controlsPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        controlsPanel.add(createFilterAndBatchPanel(), BorderLayout.NORTH);
        controlsPanel.add(createActionsToolbar(), BorderLayout.CENTER);
        panel.add(controlsPanel, BorderLayout.NORTH);

        // Create table
        tableModel = new RuleTableModel(lang);
        rulesTable = new JTable(tableModel);
        rulesTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        rulesTable.setAutoCreateRowSorter(true);
        UIStyle.styleTable(rulesTable);
        rulesTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateButtonStates();
                displaySelectedRuleDetails();
            }
        });

        // Configure table columns 
        configureTableColumns();

        // Table scroll pane
        JScrollPane tableScrollPane = UIStyle.scroll(rulesTable);
        tableScrollPane.setPreferredSize(new Dimension(760, 300));
        tableScrollPane.setMinimumSize(new Dimension(360, 180));

        panel.add(tableScrollPane, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Create filter and batch operation panel
     */
    private JPanel createFilterAndBatchPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        panel.setOpaque(false);

        JPanel topRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topRow.setOpaque(false);

        topRow.add(new JLabel(lang.getString("rules.filter.category")));
        categoryFilter = new JComboBox<>(categoryOptions(ruleManager.getAllRules()));
        categoryFilter.setSelectedItem(currentCategoryFilter);
        categoryFilter.addActionListener(e -> applyFilters());
        topRow.add(categoryFilter);

        topRow.add(Box.createHorizontalStrut(10));
        topRow.add(new JLabel(lang.getString("rules.filter.status")));
        statusFilter = new JComboBox<>(new String[]{"all", "enabled", "disabled"});
        statusFilter.setSelectedItem(currentStatusFilter);
        statusFilter.addActionListener(e -> applyFilters());
        topRow.add(statusFilter);

        topRow.add(Box.createHorizontalStrut(10));
        refreshButton = UIStyle.button(lang.getString("rules.btn.refresh"));
        refreshButton.setIcon(UIStyle.icon(UIStyle.IconType.REFRESH));
        refreshButton.addActionListener(e -> refreshRules());
        topRow.add(refreshButton);

        topRow.add(Box.createHorizontalStrut(20));
        statisticsLabel = new JLabel(lang.format("rules.stats", 0, 0, ""));
        statisticsLabel.setFont(statisticsLabel.getFont().deriveFont(Font.BOLD, 12f));
        statisticsLabel.setForeground(UIStyle.mutedText());
        topRow.add(statisticsLabel);

        panel.add(wrapHorizontal(topRow, 38), BorderLayout.CENTER);
        return panel;
    }
    
    private void applyFilters() {
        if (updatingCategories) return;
        this.currentCategoryFilter = (String) categoryFilter.getSelectedItem();
        this.currentStatusFilter = (String) statusFilter.getSelectedItem();
        loadRules();
    }
    
    private void refreshRules() {
        loadRules();
    }

    private void configureTableColumns() {
        // Optimizing column widths
        rulesTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        rulesTable.getColumnModel().getColumn(0).setPreferredWidth(88);
        rulesTable.getColumnModel().getColumn(0).setMinWidth(72);
        rulesTable.getColumnModel().getColumn(1).setPreferredWidth(210);
        rulesTable.getColumnModel().getColumn(1).setMinWidth(140);
        rulesTable.getColumnModel().getColumn(2).setPreferredWidth(100);
        rulesTable.getColumnModel().getColumn(2).setMinWidth(82);
        rulesTable.getColumnModel().getColumn(3).setPreferredWidth(360);
        rulesTable.getColumnModel().getColumn(3).setMinWidth(180);
        rulesTable.getColumnModel().getColumn(4).setPreferredWidth(220);
        rulesTable.getColumnModel().getColumn(4).setMinWidth(130);
        
         // Enable/Disable renderer
        rulesTable.getColumnModel().getColumn(0).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if ("Y".equals(value) || (value instanceof Boolean && (Boolean)value)) {
                    setText(lang.getString("rules.status.enabled"));
                    setIcon(UIStyle.dot(UIStyle.success()));
                } else {
                    setText(lang.getString("rules.status.disabled"));
                    setIcon(UIStyle.dot(UIStyle.danger()));
                }
                setHorizontalAlignment(LEFT);
                setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
                return c;
            }
        });

        DefaultTableCellRenderer paddedRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                String text = value != null ? value.toString() : "";
                label.setText(text);
                label.setToolTipText(text);
                label.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
                return label;
            }
        };
        rulesTable.getColumnModel().getColumn(1).setCellRenderer(paddedRenderer);
        rulesTable.getColumnModel().getColumn(2).setCellRenderer(paddedRenderer);
        rulesTable.getColumnModel().getColumn(3).setCellRenderer(paddedRenderer);
        rulesTable.getColumnModel().getColumn(4).setCellRenderer(paddedRenderer);
    }

    private JComponent createActionsToolbar() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        panel.setOpaque(false);

        wizardButton = UIStyle.primaryButton(lang.getString("rules.btn.wizard"));
        wizardButton.setIcon(UIStyle.icon(UIStyle.IconType.WIZARD));
        wizardButton.setToolTipText(lang.getString("rules.btn.wizard"));
        wizardButton.addActionListener(e -> openWizard());
        panel.add(wizardButton);

        presetButton = UIStyle.button(lang.getString("rules.btn.presets"));
        presetButton.setIcon(UIStyle.icon(UIStyle.IconType.LIBRARY));
        presetButton.setToolTipText(lang.getString("rules.btn.presets"));
        presetButton.addActionListener(e -> openPresetLibrary());
        panel.add(presetButton);

        panel.add(toolbarSeparator());

        addButton = UIStyle.button(lang.getString("rules.btn.add"));
        addButton.setIcon(UIStyle.icon(UIStyle.IconType.ADD));
        addButton.setToolTipText(lang.getString("rules.btn.add"));
        addButton.addActionListener(this::addRule);
        panel.add(addButton);

        editButton = UIStyle.button(lang.getString("rules.btn.edit"));
        editButton.setIcon(UIStyle.icon(UIStyle.IconType.EDIT));
        editButton.setToolTipText(lang.getString("rules.btn.edit"));
        editButton.addActionListener(this::editRule);
        panel.add(editButton);

        copyButton = UIStyle.button(lang.getString("rules.btn.copy"));
        copyButton.setIcon(UIStyle.icon(UIStyle.IconType.COPY));
        copyButton.setToolTipText(lang.getString("rules.btn.copy"));
        copyButton.addActionListener(this::copyRule);
        panel.add(copyButton);

        deleteButton = UIStyle.dangerButton(lang.getString("rules.btn.delete"));
        deleteButton.setIcon(UIStyle.icon(UIStyle.IconType.DELETE));
        deleteButton.setToolTipText(lang.getString("rules.btn.delete"));
        deleteButton.addActionListener(this::deleteRule);
        panel.add(deleteButton);

        panel.add(toolbarSeparator());

        enableButton = UIStyle.button(lang.getString("rules.btn.enable"));
        enableButton.setToolTipText(lang.getString("rules.btn.enable"));
        enableButton.addActionListener(this::enableRule);
        panel.add(enableButton);

        disableButton = UIStyle.button(lang.getString("rules.btn.disable"));
        disableButton.setToolTipText(lang.getString("rules.btn.disable"));
        disableButton.addActionListener(this::disableRule);
        panel.add(disableButton);

        panel.add(toolbarSeparator());

        importButton = UIStyle.button(lang.getString("rules.btn.import"));
        importButton.setIcon(UIStyle.icon(UIStyle.IconType.IMPORT));
        importButton.setToolTipText(lang.getString("rules.btn.import"));
        importButton.addActionListener(this::importRules);
        panel.add(importButton);

        exportButton = UIStyle.button(lang.getString("rules.btn.export"));
        exportButton.setIcon(UIStyle.icon(UIStyle.IconType.EXPORT));
        exportButton.setToolTipText(lang.getString("rules.btn.export"));
        exportButton.addActionListener(this::exportRules);
        panel.add(exportButton);

        updateButtonStates();
        return wrapHorizontal(panel, 44);
    }

    private JComponent wrapHorizontal(JComponent component, int preferredHeight) {
        JScrollPane scrollPane = new JScrollPane(component,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.getViewport().setOpaque(false);
        scrollPane.setOpaque(false);
        scrollPane.setPreferredSize(new Dimension(0, Math.max(preferredHeight, component.getPreferredSize().height + scrollPane.getHorizontalScrollBar().getPreferredSize().height)));
        return scrollPane;
    }

    private JSeparator toolbarSeparator() {
        JSeparator separator = new JSeparator(SwingConstants.VERTICAL);
        separator.setPreferredSize(new Dimension(1, 28));
        return separator;
    }

    /**
     * Create rule details panel
     */
    private JPanel createRuleDetailsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(UIStyle.sectionBorder(lang.getString("rules.details.title")));
        panel.setBackground(UIStyle.background());

        ruleDetailsArea = new JTextArea();
        ruleDetailsArea.setEditable(false);
        UIStyle.styleTextArea(ruleDetailsArea, true);

        JScrollPane scrollPane = UIStyle.scroll(ruleDetailsArea);
        scrollPane.setPreferredSize(new Dimension(600, 200));
        scrollPane.setMinimumSize(new Dimension(360, 120));

        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private void loadRules() {
        try {
            List<String> selectedIds = selectedRules().stream().map(ProcessingRule::getId).toList();
            List<ProcessingRule> allRules = ruleManager.getAllRules();
            updatingCategories = true;
            try {
                String selected = currentCategoryFilter;
                String[] options = categoryOptions(allRules);
                categoryFilter.setModel(new DefaultComboBoxModel<>(options));
                currentCategoryFilter = Arrays.asList(options).contains(selected) ? selected : "all";
                categoryFilter.setSelectedItem(currentCategoryFilter);
            } finally { updatingCategories = false; }
            List<ProcessingRule> filtered = filterRules(allRules, currentCategoryFilter, currentStatusFilter);
            tableModel.setRules(filtered);
            restoreSelection(selectedIds);
            updateButtonStates();
            displaySelectedRuleDetails();
            if (statisticsLabel != null) {
                long enabled = filtered.stream().filter(ProcessingRule::isEnabled).count();
                statisticsLabel.setText(lang.format("rules.stats", enabled, filtered.size(), lang.getString("rules.status.enabled")));
            }
        } catch (Exception e) {
            logger.error("Failed to load rules", e);
        }
    }
    
    private String[] categoryOptions(List<ProcessingRule> rules) {
        return java.util.stream.Stream.concat(java.util.stream.Stream.of("all"),
                rules.stream().map(RuleActionDescriber::category).filter(value -> !"-".equals(value))
                        .distinct().sorted(String.CASE_INSENSITIVE_ORDER)).toArray(String[]::new);
    }

    private List<ProcessingRule> filterRules(List<ProcessingRule> rules, String category, String status) {
        if (rules == null) return new ArrayList<>();
        return rules.stream()
            .filter(r -> {
                // Status filter
                boolean statusMatch = "all".equals(status) || 
                       ("enabled".equals(status) && r.isEnabled()) || 
                       ("disabled".equals(status) && !r.isEnabled());
                
                // Category filter
                boolean categoryMatch = "all".equals(category) || 
                        RuleActionDescriber.category(r).equalsIgnoreCase(category);
                
                return statusMatch && categoryMatch;
            })
            .collect(Collectors.toList());
    }

    private List<ProcessingRule> selectedRules() {
        if (rulesTable == null) return List.of();
        return Arrays.stream(rulesTable.getSelectedRows())
                .map(rulesTable::convertRowIndexToModel).mapToObj(tableModel::getRuleAt)
                .filter(java.util.Objects::nonNull).toList();
    }

    private void restoreSelection(List<String> ids) {
        rulesTable.clearSelection();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            if (ids.contains(tableModel.getRuleAt(i).getId())) {
                int row = rulesTable.convertRowIndexToView(i);
                if (row >= 0) rulesTable.addRowSelectionInterval(row, row);
            }
        }
    }

    private void updateButtonStates() {
        List<ProcessingRule> selected = selectedRules();
        if (editButton != null) editButton.setEnabled(selected.size() == 1);
        if (copyButton != null) copyButton.setEnabled(!selected.isEmpty());
        if (deleteButton != null) deleteButton.setEnabled(!selected.isEmpty());
        if (enableButton != null) enableButton.setEnabled(selected.stream().anyMatch(r -> !r.isEnabled()));
        if (disableButton != null) disableButton.setEnabled(selected.stream().anyMatch(ProcessingRule::isEnabled));
    }

    private void displaySelectedRuleDetails() {
        int selectedRow = rulesTable.getSelectedRow();
        if (selectedRow >= 0) {
            ProcessingRule rule = tableModel.getRuleAt(rulesTable.convertRowIndexToModel(selectedRow));
            if (rule != null) {
                StringBuilder details = new StringBuilder();
                if (selectedRules().size() > 1) details.append(lang.format("rules.selection.detail", selectedRules().size())).append("\n\n");
                details.append("规则       : ").append(rule.getName()).append('\n');
                details.append("ID         : ").append(rule.getId()).append('\n');
                details.append("状态       : ").append(rule.isEnabled() ? lang.getString("rules.status.enabled") : lang.getString("rules.status.disabled")).append('\n');
                details.append("分类       : ").append(RuleActionDescriber.category(rule)).append('\n');
                details.append("优先级     : ").append(rule.getPriority()).append('\n');
                details.append("步骤       : ").append(RuleActionDescriber.summarizeRule(rule, lang)).append('\n');
                if (rule.getCondition() != null) {
                    details.append("Tool       : ").append(rule.getCondition().getToolSource() == null ? "ANY" : rule.getCondition().getToolSource()).append('\n');
                    details.append("Host       : ").append(RuleActionDescriber.listOrAny(rule.getCondition().getHosts())).append('\n');
                    details.append("路径       : ").append(RuleActionDescriber.listOrAny(rule.getCondition().getPaths())).append('\n');
                    details.append("方法       : ").append(RuleActionDescriber.listOrAny(rule.getCondition().getMethods())).append('\n');
                }
                if (rule.getDescription() != null && !rule.getDescription().trim().isEmpty()) {
                    details.append("\n").append(rule.getDescription()).append('\n');
                }
                details.append('\n').append(RuleActionDescriber.describeRule(rule, lang));
                ruleDetailsArea.setText(details.toString());
                ruleDetailsArea.setCaretPosition(0);
            }
        } else {
            ruleDetailsArea.setText("");
        }
    }

    // --- ACTIONS ---

    private void openPresetLibrary() {
        try {
            JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), lang.getString("rules.btn.presets"), Dialog.ModalityType.APPLICATION_MODAL);
            PresetRuleLibraryPanel libraryPanel = new PresetRuleLibraryPanel(api, ruleManager, playgroundNavigator);
            dialog.setContentPane(libraryPanel);
            dialog.setSize(800, 600);
            dialog.setLocationRelativeTo(this);
            dialog.setVisible(true);
            loadRules(); // Refresh
        } catch (Exception ex) {
            logger.error("Failed to open preset library", ex);
        }
    }

    private void openWizard() {
        try {
            QuickRuleWizardDialog dialog = new QuickRuleWizardDialog(
                SwingUtilities.getWindowAncestor(this), "", "");
            dialog.setVisible(true);
            if (dialog.isConfirmed() && dialog.getRule() != null) {
                ruleManager.addRuleAndSave(dialog.getRule());
                loadRules();
            }
        } catch (Exception ex) {
            showRuleSaveError(ex);
        }
    }
    
    private void addRule(ActionEvent e) {
        try {
            RuleEditDialog dialog = new RuleEditDialog(SwingUtilities.getWindowAncestor(this), null, playgroundNavigator);
            dialog.setVisible(true);
            if (dialog.isConfirmed() && dialog.getRule() != null) {
                ruleManager.addRuleAndSave(dialog.getRule());
                loadRules();
            }
        } catch (Exception ex) {
            showRuleSaveError(ex);
        }
    }

    private void editRule(ActionEvent e) {
        if (selectedRules().size() != 1) return;
        int selectedRow = rulesTable.getSelectedRow();
        if (selectedRow >= 0) {
            ProcessingRule rule = tableModel.getRuleAt(rulesTable.convertRowIndexToModel(selectedRow));
            if (rule != null) {
                try {
                    RuleEditDialog dialog = new RuleEditDialog(SwingUtilities.getWindowAncestor(this), rule, playgroundNavigator);
                    dialog.setVisible(true);
                    if (dialog.isConfirmed()) {
                        ruleManager.updateRuleAndSave(dialog.getRule());
                        loadRules();
                    }
                } catch (Exception ex) { showRuleSaveError(ex); }
            }
        }
    }
    
    private void copyRule(ActionEvent e) {
        try {
            List<ProcessingRule> copies = new ArrayList<>();
            for (ProcessingRule rule : selectedRules()) {
                ProcessingRule cloned = rule.clone();
                cloned.setId(rule.getId() + "-copy-" + java.util.UUID.randomUUID());
                cloned.setName(rule.getName() + " (Copy)");
                // A copied rule is a draft; enabling it must be an explicit choice.
                cloned.setEnabled(false);
                copies.add(cloned);
            }
            ruleManager.updateRulesAndSave(candidate -> candidate.addAll(copies));
            loadRules();
        } catch (Exception ex) { showRuleSaveError(ex); }
    }

    private void deleteRule(ActionEvent e) {
        List<ProcessingRule> selected = selectedRules();
        if (selected.isEmpty()) return;
        String names = selected.stream().map(ProcessingRule::getName).collect(Collectors.joining("\n"));
        if (JOptionPane.showConfirmDialog(this, lang.getString("rules.msg.confirm_delete") + "\n" + names,
                lang.getString("rules.btn.delete"), JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
            try {
                List<String> ids = selected.stream().map(ProcessingRule::getId).toList();
                ruleManager.updateRulesAndSave(candidate -> candidate.removeIf(rule -> ids.contains(rule.getId())));
                loadRules();
            } catch (Exception ex) { showRuleSaveError(ex); }
        }
    }

    private void enableRule(ActionEvent e) { toggleRuleStatus(true); }
    private void disableRule(ActionEvent e) { toggleRuleStatus(false); }

    private void toggleRuleStatus(boolean enabled) {
        try { saveSelectedRuleStatus(enabled); }
        catch (Exception ex) { showRuleSaveError(ex); }
    }

    void saveSelectedRuleStatus(boolean enabled) {
        List<ProcessingRule> selected = selectedRules();
        if (selected.isEmpty()) return;
        List<String> ids = selected.stream().map(ProcessingRule::getId).toList();
        ruleManager.updateRulesAndSave(candidate -> candidate.stream()
                .filter(rule -> ids.contains(rule.getId())).forEach(rule -> rule.setEnabled(enabled)));
        loadRules();
    }

    private void showRuleSaveError(Exception ex) {
        logger.error("Failed to save rule changes", ex);
        JOptionPane.showMessageDialog(this, ex.getMessage(), lang.getString("error.title"), JOptionPane.ERROR_MESSAGE);
    }

    private void importRules(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle(lang.getString("rules.import.title"));
        fileChooser.setFileFilter(new FileNameExtensionFilter(lang.getString("rules.export.file_filter"), "json"));
        
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                // Read file
                String json = java.nio.file.Files.readString(file.toPath(), java.nio.charset.StandardCharsets.UTF_8);
                List<ProcessingRule> importedRules = com.universal.crypto.model.RuleSerializer.importRules(json);
                
                if (importedRules == null || importedRules.isEmpty()) {
                    JOptionPane.showMessageDialog(this, 
                        lang.getString("rules.import.error").replace("{0}", "No rules found"), 
                        lang.getString("error.title"), JOptionPane.ERROR_MESSAGE);
                    return;
                }

                StringBuilder preview = new StringBuilder("导入规则默认禁用。脚本禁止直接访问 Java / 反射，请使用 Crypto / Bytes。\n");
                for (ProcessingRule incoming : importedRules) {
                    ProcessingRule existing = ruleManager.getRuleById(incoming.getId());
                    preview.append("\n=== ").append(incoming.getId()).append(" ===\n原规则:\n")
                        .append(existing == null ? "(新增)" : com.universal.crypto.model.RuleSerializer.toJson(existing))
                        .append("\n导入规则:\n").append(com.universal.crypto.model.RuleSerializer.toJson(incoming)).append("\n");
                }
                JTextArea previewArea = new JTextArea(preview.toString(), 20, 85);
                previewArea.setEditable(false);
                JScrollPane previewPane = new JScrollPane(previewArea);

                // Confirm Merge or Replace
                String[] options = {
                    lang.getString("rules.import.btn.merge"),
                    lang.getString("rules.import.btn.replace"),
                    lang.getString("settings.btn.discard")
                };
                
                int choice = JOptionPane.showOptionDialog(this,
                    previewPane,
                    lang.getString("rules.import.title"),
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    options,
                    options[0]);

                if (choice == 0) { // Merge
                    ruleManager.updateRulesAndSave(candidate -> {
                        for (ProcessingRule incoming : importedRules) {
                            int index = -1;
                            for (int i = 0; i < candidate.size(); i++)
                                if (incoming.getId().equals(candidate.get(i).getId())) { index = i; break; }
                            if (index >= 0) candidate.set(index, incoming);
                            else candidate.add(incoming);
                        }
                    });
                    finalizeImport(importedRules.size());
                } else if (choice == 1) { // Replace
                    ruleManager.updateRulesAndSave(candidate -> {
                        candidate.clear();
                        candidate.addAll(importedRules);
                    });
                    finalizeImport(importedRules.size());
                }

            } catch (Exception ex) {
                logger.error("Import failed", ex);
                JOptionPane.showMessageDialog(this, 
                    lang.getString("rules.import.error").replace("{0}", ex.getMessage()), 
                    lang.getString("error.title"), JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void finalizeImport(int count) {
        loadRules();
        JOptionPane.showMessageDialog(this, 
            lang.getString("rules.import.success").replace("{0}", String.valueOf(count)), 
            lang.getString("rules.import.title"), JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void exportRules(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle(lang.getString("rules.export.title"));
        fileChooser.setFileFilter(new FileNameExtensionFilter(lang.getString("rules.export.file_filter"), "json"));
        fileChooser.setSelectedFile(new File("rules_export.json"));

        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".json")) {
                file = new File(file.getParentFile(), file.getName() + ".json");
            }
            
            try {
                List<ProcessingRule> rules = ruleManager.getAllRules();
                String json = com.universal.crypto.model.RuleSerializer.exportRules(rules);
                java.nio.file.Files.write(file.toPath(), json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                
                JOptionPane.showMessageDialog(this, 
                    lang.getString("rules.export.success").replace("{0}", String.valueOf(rules.size())), 
                    lang.getString("rules.export.title"), JOptionPane.INFORMATION_MESSAGE);

            } catch (Exception ex) {
                logger.error("Export failed", ex);
                JOptionPane.showMessageDialog(this, 
                    lang.getString("rules.export.error").replace("{0}", ex.getMessage()), 
                    lang.getString("error.title"), JOptionPane.ERROR_MESSAGE);
            }
        }
    }


    /**
     * Refresh the panel
     */
    public void refresh() {
        List<String> ids = selectedRules().stream().map(ProcessingRule::getId).toList();
        java.util.List<? extends RowSorter.SortKey> sortKeys = new ArrayList<>(rulesTable.getRowSorter().getSortKeys());
        rebuildUI();
        loadRules();
        rulesTable.getRowSorter().setSortKeys(sortKeys);
        restoreSelection(ids);
        updateButtonStates();
        displaySelectedRuleDetails();
    }
    
    /**
     * Table model for rules
     */
    private static class RuleTableModel extends AbstractTableModel {
        private String[] columnNames;
        private List<ProcessingRule> rules = new ArrayList<>();
        private final LanguageManager lang;

        public RuleTableModel(LanguageManager lang) {
            this.lang = lang;
            updateColumnNames();
        }
        
        public void updateColumnNames() {
            columnNames = new String[]{
                lang.getString("rules.col.enabled"),
                lang.getString("rules.col.name"),
                lang.getString("rules.filter.category"),
                lang.getString("rules.col.action"),
                lang.getString("rules.col.host")
            };
        }

        public void setRules(List<ProcessingRule> rules) {
            this.rules = rules;
            fireTableDataChanged();
        }

        public ProcessingRule getRuleAt(int row) {
             if (row >= 0 && row < rules.size()) return rules.get(row);
             return null;
        }

        @Override
        public int getRowCount() { return rules.size(); }

        @Override
        public int getColumnCount() { return columnNames.length; }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ProcessingRule rule = rules.get(rowIndex);
            switch (columnIndex) {
                case 0: return rule.isEnabled() ? "Y" : "N";
                case 1: return rule.getName();
                case 2: return RuleActionDescriber.category(rule);
                case 3: return RuleActionDescriber.summarizeRule(rule, lang);
                case 4: return rule.getCondition() != null ? RuleActionDescriber.listOrAny(rule.getCondition().getHosts()) : "*";
                default: return "";
            }
        }
    }

}
