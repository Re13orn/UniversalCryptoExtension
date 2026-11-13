package com.universal.crypto.ui;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleCondition;
import com.universal.crypto.util.LanguageManager;
import com.universal.crypto.util.Logger;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Dialog for creating and editing processing rules
 */
public class RuleEditDialog extends JDialog {

    private static final Logger logger = Logger.getInstance();
    private final LanguageManager lang = LanguageManager.getInstance();

    private ProcessingRule rule;
    private boolean confirmed = false;

    // UI Components
    private JTextField nameField;
    private JTextArea descriptionArea;
    private JSpinner prioritySpinner;
    private JCheckBox enabledCheckBox;

    // Condition fields
    private JTextField hostsField;
    private JTextField pathsField;
    private JTextField methodsField;
    private JTextField contentTypeField;
    private JComboBox<String> toolSourceCombo;
    private String loadedHostsText = "";
    private String loadedPathsText = "";
    private String loadedMethodsText = "";
    private String loadedHeaderText = "";
    private JTextArea contentPatternArea;
    private JTextArea headerConditionsArea;

    // Action management components
    private DefaultListModel<ProcessingAction> requestActionsModel;
    private DefaultListModel<ProcessingAction> responseActionsModel;
    private JList<ProcessingAction> requestActionsList;
    private JList<ProcessingAction> responseActionsList;
    private JButton requestAddButton;
    private JButton requestEditButton;
    private JButton requestRemoveButton;
    private JButton requestUpButton;
    private JButton requestDownButton;
    private JButton requestDuplicateButton;
    private JButton responseAddButton;
    private JButton responseEditButton;
    private JButton responseRemoveButton;
    private JButton responseUpButton;
    private JButton responseDownButton;
    private JButton responseDuplicateButton;




    private final java.util.function.Consumer<com.universal.crypto.model.ProcessingAction> playgroundNavigator;

    public RuleEditDialog(Window parent, ProcessingRule rule, java.util.function.Consumer<com.universal.crypto.model.ProcessingAction> playgroundNavigator) {
        super(parent, rule == null ? LanguageManager.getInstance().getString("rule.dialog.create_title") : LanguageManager.getInstance().getString("rule.dialog.edit_title"), ModalityType.APPLICATION_MODAL);
        this.rule = rule == null ? null : rule.clone();
        this.playgroundNavigator = playgroundNavigator;
        initializeDialog();
        loadRuleData();
    }

    private void initializeDialog() {
        setLayout(new BorderLayout());
        setSize(820, 620);
        setMinimumSize(new Dimension(760, 560));
        setLocationRelativeTo(getParent());

        // Create main panel with tabs
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBorder(BorderFactory.createEmptyBorder(10, 12, 0, 12));
        tabbedPane.addTab(lang.getString("rule.tab.basic"), createBasicPanel());
        tabbedPane.addTab(lang.getString("rule.tab.conditions"), createConditionsPanel());
        tabbedPane.addTab(lang.getString("rule.tab.actions"), createActionsPanel());

        add(tabbedPane, BorderLayout.CENTER);
        add(createButtonPanel(), BorderLayout.SOUTH);
    }

    private JPanel createBasicPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 12));
        panel.setBorder(UIStyle.emptyBorder());
        panel.setBackground(UIStyle.background());

        JPanel form = new JPanel(new GridBagLayout());
        form.setBackground(UIStyle.background());
        form.setBorder(UIStyle.sectionBorder(lang.getString("rule.section.identity")));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        nameField = new JTextField(20);
        addFormRow(form, gbc, 0, lang.getString("rule.label.name"), nameField);

        descriptionArea = new JTextArea(4, 20);
        descriptionArea.setWrapStyleWord(true);
        descriptionArea.setLineWrap(true);
        UIStyle.styleTextArea(descriptionArea, false);
        JScrollPane descScroll = UIStyle.scroll(descriptionArea);
        descScroll.setPreferredSize(new Dimension(520, 96));
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        gbc.weighty = 0;
        form.add(new JLabel(lang.getString("rule.label.desc")), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0;
        gbc.weighty = 0;
        form.add(descScroll, gbc);

        JPanel options = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        options.setOpaque(false);
        gbc.fill = GridBagConstraints.NONE;
        options.add(new JLabel(lang.getString("rule.label.priority")));
        prioritySpinner = new JSpinner(new SpinnerNumberModel(100, Integer.MIN_VALUE, Integer.MAX_VALUE, 1));
        options.add(prioritySpinner);
        enabledCheckBox = new JCheckBox(lang.getString("rule.check.enabled"));
        enabledCheckBox.setSelected(false);
        options.add(enabledCheckBox);
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.weightx = 1.0;
        form.add(options, gbc);

        panel.add(form, BorderLayout.NORTH);
        panel.add(createReadOnlyNote(lang.getString("rule.help.basic")), BorderLayout.CENTER);

        return panel;
    }

    private JPanel createConditionsPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 12));
        panel.setBorder(UIStyle.emptyBorder());
        panel.setBackground(UIStyle.background());

        JPanel scopePanel = new JPanel(new GridBagLayout());
        scopePanel.setBackground(UIStyle.background());
        scopePanel.setBorder(UIStyle.sectionBorder(lang.getString("rule.section.match_scope")));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        hostsField = new JTextField(20);
        hostsField.setToolTipText(lang.getString("form.rule.hint.hosts"));
        addFormRow(scopePanel, gbc, 0, lang.getString("rule.label.hosts"), hostsField);

        pathsField = new JTextField(20);
        pathsField.setToolTipText(lang.getString("form.rule.hint.paths"));
        addFormRow(scopePanel, gbc, 1, lang.getString("rule.label.paths"), pathsField);

        methodsField = new JTextField(20);
        methodsField.setToolTipText(lang.getString("form.rule.hint.methods"));
        addFormRow(scopePanel, gbc, 2, lang.getString("rule.label.methods"), methodsField);

        contentTypeField = new JTextField(20);
        contentTypeField.setToolTipText(lang.getString("form.rule.hint.content_type"));
        addFormRow(scopePanel, gbc, 3, lang.getString("rule.label.content_type"), contentTypeField);

        java.util.List<String> sources = new ArrayList<>(Arrays.asList("ANY", "PROXY", "REPEATER", "INTRUDER", "SCANNER", "TARGET", "EXTENSIONS", "SEQUENCER", "DECODER", "COMPARER"));
        String original = rule == null || rule.getCondition() == null ? null : rule.getCondition().getToolSource();
        if (original != null && !original.isBlank() && !sources.contains(original)) sources.add(original);
        toolSourceCombo = new JComboBox<>(sources.toArray(String[]::new));
        addFormRow(scopePanel, gbc, 4, lang.getString("rule.label.tool_source"), toolSourceCombo);
        panel.add(scopePanel, BorderLayout.NORTH);

        JPanel advancedPanel = new JPanel(new GridLayout(1, 2, 12, 0));
        advancedPanel.setOpaque(false);

        headerConditionsArea = new JTextArea(3, 20);
        headerConditionsArea.setWrapStyleWord(true);
        headerConditionsArea.setLineWrap(true);
        headerConditionsArea.setToolTipText(lang.getString("form.rule.hint.header_conditions"));
        UIStyle.styleTextArea(headerConditionsArea, true);
        advancedPanel.add(wrapSection(lang.getString("rule.label.header_conditions"), headerConditionsArea, lang.getString("rule.help.header_conditions")));

        contentPatternArea = new JTextArea(3, 20);
        contentPatternArea.setWrapStyleWord(true);
        contentPatternArea.setLineWrap(true);
        contentPatternArea.setToolTipText(lang.getString("form.rule.hint.body_pattern"));
        UIStyle.styleTextArea(contentPatternArea, true);
        advancedPanel.add(wrapSection(lang.getString("rule.label.content_pattern"), contentPatternArea, lang.getString("rule.help.content_pattern")));

        CollapsibleSection advanced = new CollapsibleSection(lang.getString("rule.section.advanced"), advancedPanel);
        RuleCondition condition = rule == null ? null : rule.getCondition();
        advanced.setConfigured(condition != null && ((condition.getHeaders() != null && !condition.getHeaders().isEmpty())
                || (condition.getContentPattern() != null && !condition.getContentPattern().isEmpty())));
        JPanel advancedHolder = new JPanel(new BorderLayout());
        advancedHolder.setOpaque(false);
        advancedHolder.add(advanced, BorderLayout.NORTH);
        panel.add(advancedHolder, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createActionsPanel() {
        requestActionsModel = new DefaultListModel<>();
        responseActionsModel = new DefaultListModel<>();

        JPanel panel = new JPanel(new BorderLayout(0, 12));
        panel.setBorder(UIStyle.emptyBorder());
        panel.setBackground(UIStyle.background());

        JPanel summary = createReadOnlyNote(lang.getString("rule.help.actions"));
        panel.add(summary, BorderLayout.NORTH);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                createActionSection(lang.getString("rule.section.req_actions"), false),
                createActionSection(lang.getString("rule.section.res_actions"), true));
        SplitPaneLayout.initialize(splitPane, 0.5);
        splitPane.setDividerSize(8);
        splitPane.setBorder(BorderFactory.createEmptyBorder());
        panel.add(splitPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createActionSection(String title, boolean responseSection) {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBackground(UIStyle.background());
        wrapper.setBorder(UIStyle.sectionBorder(title));

        DefaultListModel<ProcessingAction> model = responseSection ? responseActionsModel : requestActionsModel;
        JList<ProcessingAction> list = new JList<>(model);
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setCellRenderer(new ActionListCellRenderer(responseSection));
        list.setFixedCellHeight(68);

        if (responseSection) {
            responseActionsList = list;
        } else {
            requestActionsList = list;
        }

        list.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateActionButtons(responseSection);
            }
        });

        JPanel flowHint = new JPanel(new BorderLayout());
        flowHint.setOpaque(false);
        flowHint.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        flowHint.add(UIStyle.mutedLabel(lang.getString("rule.help.step_flow")), BorderLayout.CENTER);
        wrapper.add(flowHint, BorderLayout.SOUTH);

        wrapper.add(UIStyle.scroll(list), BorderLayout.CENTER);

        JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        buttonsPanel.setOpaque(false);
        buttonsPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));

        JButton addButton = UIStyle.primaryButton(lang.getString("btn.add"));
        addButton.setIcon(UIStyle.icon(UIStyle.IconType.ADD));
        addButton.addActionListener(e -> addAction(responseSection));
        JButton templateButton = UIStyle.button(lang.getString("rules.btn.step_template"));
        templateButton.setIcon(UIStyle.icon(UIStyle.IconType.WIZARD));
        templateButton.addActionListener(e -> addPipelineTemplate(responseSection));
        JButton previewButton = UIStyle.button(lang.getString("rules.btn.preview_flow"));
        previewButton.setIcon(UIStyle.icon(UIStyle.IconType.RUN));
        previewButton.addActionListener(e -> previewActionFlow(responseSection));
        JButton editButton = UIStyle.button(lang.getString("btn.edit"));
        editButton.setIcon(UIStyle.icon(UIStyle.IconType.EDIT));
        editButton.addActionListener(e -> editAction(responseSection));
        JButton removeButton = UIStyle.dangerButton(lang.getString("btn.remove"));
        removeButton.setIcon(UIStyle.icon(UIStyle.IconType.DELETE));
        removeButton.addActionListener(e -> removeAction(responseSection));
        JButton duplicateButton = UIStyle.button(lang.getString("btn.copy"));
        duplicateButton.setIcon(UIStyle.icon(UIStyle.IconType.COPY));
        duplicateButton.addActionListener(e -> duplicateAction(responseSection));
        JButton upButton = UIStyle.button(lang.getString("btn.up"));
        upButton.setIcon(UIStyle.icon(UIStyle.IconType.UP));
        upButton.addActionListener(e -> moveAction(responseSection, -1));
        JButton downButton = UIStyle.button(lang.getString("btn.down"));
        downButton.setIcon(UIStyle.icon(UIStyle.IconType.DOWN));
        downButton.addActionListener(e -> moveAction(responseSection, 1));

        buttonsPanel.add(addButton);
        buttonsPanel.add(templateButton);
        buttonsPanel.add(previewButton);
        buttonsPanel.add(editButton);
        buttonsPanel.add(removeButton);
        buttonsPanel.add(duplicateButton);
        buttonsPanel.add(upButton);
        buttonsPanel.add(downButton);

        wrapper.add(buttonsPanel, BorderLayout.NORTH);

        if (responseSection) {
            responseAddButton = addButton;
            responseEditButton = editButton;
            responseRemoveButton = removeButton;
            responseDuplicateButton = duplicateButton;
            responseUpButton = upButton;
            responseDownButton = downButton;
        } else {
            requestAddButton = addButton;
            requestEditButton = editButton;
            requestRemoveButton = removeButton;
            requestDuplicateButton = duplicateButton;
            requestUpButton = upButton;
            requestDownButton = downButton;
        }

        updateActionButtons(responseSection);

        return wrapper;
    }

    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        panel.setBackground(UIStyle.surface());
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UIStyle.border()),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
        ));

        JButton cancelButton = UIStyle.button(lang.getString("btn.cancel"));
        cancelButton.addActionListener(e -> {
            confirmed = false;
            dispose();
        });

        JButton okButton = UIStyle.primaryButton(lang.getString("btn.ok"));
        okButton.addActionListener(this::saveRule);

        panel.add(cancelButton);
        panel.add(okButton);

        return panel;
    }

    private void addFormRow(JPanel panel, GridBagConstraints gbc, int row, String labelText, JComponent field) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        gbc.weighty = 0;
        gbc.fill = GridBagConstraints.NONE;
        JLabel label = new JLabel(labelText);
        panel.add(label, gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(field, gbc);
    }

    private JPanel createReadOnlyNote(String text) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(UIStyle.background());
        panel.setBorder(UIStyle.sectionBorder(lang.getString("rule.section.guide")));

        JTextArea note = new JTextArea(text);
        note.setEditable(false);
        note.setLineWrap(true);
        note.setWrapStyleWord(true);
        UIStyle.styleTextArea(note, false);
        panel.add(note, BorderLayout.CENTER);
        return panel;
    }

    private JPanel wrapSection(String title, JTextArea area, String hint) {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBackground(UIStyle.background());
        panel.setBorder(UIStyle.sectionBorder(title));

        if (hint != null && !hint.trim().isEmpty()) {
            panel.add(UIStyle.mutedLabel(hint), BorderLayout.NORTH);
        }

        JScrollPane scrollPane = UIStyle.scroll(area);
        scrollPane.setPreferredSize(new Dimension(260, 220));
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private void loadRuleData() {
        requestActionsModel.clear();
        responseActionsModel.clear();

        if (rule == null) {
            return;
        }

        // Basic fields
        nameField.setText(rule.getName());
        descriptionArea.setText(rule.getDescription());
        prioritySpinner.setValue(rule.getPriority());
        enabledCheckBox.setSelected(rule.isEnabled());

        // Condition fields
        RuleCondition condition = rule.getCondition();
        if (condition != null) {
            toolSourceCombo.setSelectedItem(condition.getToolSource() == null || condition.getToolSource().isBlank() ? "ANY" : condition.getToolSource());
            if (condition.getHosts() != null) {
                hostsField.setText(String.join(", ", condition.getHosts()));
            }
            if (condition.getPaths() != null) {
                pathsField.setText(String.join(", ", condition.getPaths()));
            }
            if (condition.getMethods() != null) {
                methodsField.setText(String.join(", ", condition.getMethods()));
            }
            contentTypeField.setText(condition.getContentType());
            contentPatternArea.setText(condition.getContentPattern());

            // Load header conditions
            if (condition.getHeaders() != null && !condition.getHeaders().isEmpty()) {
                StringBuilder headerText = new StringBuilder();
                for (Map.Entry<String, String> entry : condition.getHeaders().entrySet()) {
                    headerText.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
                }
                headerConditionsArea.setText(headerText.toString().trim());
            }
        }

        if (rule.getRequestActions() != null) {
            for (ProcessingAction action : rule.getRequestActions()) {
                requestActionsModel.addElement(action.clone());
            }
        }

        if (rule.getResponseActions() != null) {
            for (ProcessingAction action : rule.getResponseActions()) {
                responseActionsModel.addElement(action.clone());
            }
        }

        loadedHeaderText = headerConditionsArea.getText();
        loadedHostsText = hostsField.getText();
        loadedPathsText = pathsField.getText();
        loadedMethodsText = methodsField.getText();
        updateActionButtons(false);
        updateActionButtons(true);
    }

    private void saveRule(ActionEvent e) {
        try {
            ProcessingRule candidate = buildDraft();
            rule = candidate;
            confirmed = true;
            dispose();
        } catch (Exception ex) {
            logger.error("Failed to save rule", ex);
            JOptionPane.showMessageDialog(this, lang.getString("validation.rule_save_error").replace("{0}", String.valueOf(ex.getMessage())),
                    lang.getString("error.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Build and validate before publishing any edited state. */
    ProcessingRule buildDraft() throws Exception {
        if (nameField.getText().trim().isEmpty()) throw new IllegalArgumentException(lang.getString("validation.rule_name_required"));
        prioritySpinner.commitEdit();
        ProcessingRule candidate = rule == null ? new ProcessingRule(UUID.randomUUID().toString()) : rule.clone();
        candidate.setName(nameField.getText().trim());
        candidate.setDescription(descriptionArea.getText().trim());
        candidate.setPriority(((Number) prioritySpinner.getValue()).intValue());
        candidate.setEnabled(enabledCheckBox.isSelected());
        RuleCondition condition = candidate.getCondition() == null ? new RuleCondition() : candidate.getCondition();
        if (!hostsField.getText().equals(loadedHostsText)) condition.setHosts(csv(hostsField.getText()));
        if (!pathsField.getText().equals(loadedPathsText)) condition.setPaths(csv(pathsField.getText()));
        if (!methodsField.getText().equals(loadedMethodsText))
            condition.setMethods(csv(methodsField.getText()).stream().map(value -> value.toUpperCase(java.util.Locale.ROOT)).toList());
        condition.setContentType(blankToNull(contentTypeField.getText()));
        condition.setContentPattern(contentPatternArea.getText().isEmpty() ? null : contentPatternArea.getText());
        if (condition.getContentPattern() != null) java.util.regex.Pattern.compile(condition.getContentPattern());
        String source = String.valueOf(toolSourceCombo.getSelectedItem());
        if (!"ANY".equals(source) || condition.getToolSource() != null) condition.setToolSource(source);
        Map<String, String> headers = new java.util.LinkedHashMap<>();
        int row = 0;
        for (String line : headerConditionsArea.getText().split("\\R")) {
            row++;
            if (line.isBlank()) continue;
            int colon = line.indexOf(':');
            if (colon <= 0 || line.substring(0, colon).trim().isEmpty())
                throw new IllegalArgumentException(lang.format("rule.validation.header_line", row));
            String name = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            if (headers.containsKey(name)) throw new IllegalArgumentException(lang.format("rule.validation.header_duplicate", name));
            headers.put(name, value); // Empty pattern still requires the header to exist.
        }
        if (!headerConditionsArea.getText().equals(loadedHeaderText)) condition.setHeaders(headers);
        candidate.setCondition(condition);
        candidate.setRequestActions(collectActions(requestActionsModel));
        candidate.setResponseActions(collectActions(responseActionsModel));
        if (!candidate.hasRequestActions() && !candidate.hasResponseActions())
            throw new IllegalArgumentException(lang.getString("rule.validation.no_actions"));
        return candidate;
    }

    private java.util.List<String> csv(String value) {
        return Arrays.stream(value.split(",")).map(String::trim).filter(text -> !text.isEmpty()).toList();
    }

    private String blankToNull(String value) { return value == null || value.isBlank() ? null : value.trim(); }

    public void setDraftOnly() {
        enabledCheckBox.setSelected(false);
        enabledCheckBox.setEnabled(false);
        enabledCheckBox.setToolTipText(lang.getString("library.details.draft"));
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public ProcessingRule getRule() {
        return rule;
    }

    private java.util.List<ProcessingAction> collectActions(DefaultListModel<ProcessingAction> model) {
        java.util.List<ProcessingAction> actions = new java.util.ArrayList<>();
        for (int i = 0; i < model.size(); i++) {
            ProcessingAction original = model.getElementAt(i);
            actions.add(original.clone());
        }
        return actions;
    }

    private void addAction(boolean responseSection) {
        ActionEditDialog dialog = new ActionEditDialog(this, null, responseSection, playgroundNavigator);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            DefaultListModel<ProcessingAction> model = responseSection ? responseActionsModel : requestActionsModel;
            model.addElement(dialog.getAction());
            updateActionButtons(responseSection);
        }
    }

    private void addPipelineTemplate(boolean responseSection) {
        JPanel form = new JPanel(new GridBagLayout());
        form.setBackground(UIStyle.background());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JTextArea note = new JTextArea(lang.getString("rules.step_template.base64_aes.note"));
        note.setEditable(false);
        note.setLineWrap(true);
        note.setWrapStyleWord(true);
        UIStyle.styleTextArea(note, false);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        form.add(note, gbc);
        gbc.gridwidth = 1;

        JTextField fieldName = new JTextField("data", 24);
        JComboBox<String> algorithm = new JComboBox<>(new String[]{
                "AES-GCM", "AES-CBC", "AES-ECB", "SM4-CBC", "SM4-ECB", "DES-CBC", "3DES-CBC"
        });
        JTextField keyValue = new JTextField(24);
        JComboBox<String> keyFormat = new JComboBox<>(new String[]{"base64", "hex", "plain"});
        JTextField ivField = new JTextField("iv_b64", 24);
        JTextField ivLiteral = new JTextField(24);
        JComboBox<String> ivFormat = new JComboBox<>(new String[]{"base64", "hex", "plain"});

        int row = 1;
        addTemplateRow(form, gbc, row++, lang.getString("rules.step_template.field"), fieldName);
        addTemplateRow(form, gbc, row++, lang.getString("rules.step_template.algorithm"), algorithm);
        addTemplateRow(form, gbc, row++, lang.getString("rules.step_template.key"), keyValue);
        addTemplateRow(form, gbc, row++, lang.getString("rules.step_template.key_format"), keyFormat);
        addTemplateRow(form, gbc, row++, lang.getString("rules.step_template.iv_field"), ivField);
        addTemplateRow(form, gbc, row++, lang.getString("rules.step_template.iv_literal"), ivLiteral);
        addTemplateRow(form, gbc, row++, lang.getString("rules.step_template.iv_format"), ivFormat);
        JCheckBox responseEdit = new JCheckBox(lang.getString("rules.step_template.response_edit"));
        responseEdit.setOpaque(false);
        if (responseSection) addTemplateRow(form, gbc, row, "", responseEdit);

        int result = showResizableFormDialog(form, lang.getString("rules.step_template.title"));
        if (result != JOptionPane.OK_OPTION) {
            return;
        }

        if (fieldName.getText().trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, lang.getString("rules.step_template.field_required"),
                    lang.getString("validation.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (keyValue.getText().trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, lang.getString("rules.step_template.key_required"),
                    lang.getString("validation.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        PipelineTemplateFactory.Base64WrappedCipherFieldConfig config =
                new PipelineTemplateFactory.Base64WrappedCipherFieldConfig(
                        fieldName.getText(),
                        String.valueOf(algorithm.getSelectedItem()),
                        keyValue.getText(),
                        String.valueOf(keyFormat.getSelectedItem()),
                        ivField.getText(),
                        ivLiteral.getText(),
                        String.valueOf(ivFormat.getSelectedItem())
                );

        java.util.List<ProcessingAction> actions = responseSection
                ? (responseEdit.isSelected() ? PipelineTemplateFactory.base64WrappedCipherFieldResponseRoundTrip(config)
                        : PipelineTemplateFactory.base64WrappedCipherFieldResponseDecrypt(config))
                : PipelineTemplateFactory.base64WrappedCipherFieldRequestRoundTrip(config);

        DefaultListModel<ProcessingAction> model = responseSection ? responseActionsModel : requestActionsModel;
        for (ProcessingAction action : actions) {
            model.addElement(action);
        }
        JList<ProcessingAction> list = responseSection ? responseActionsList : requestActionsList;
        if (list != null && !actions.isEmpty()) {
            list.setSelectedIndex(model.size() - actions.size());
        }
        updateActionButtons(responseSection);
    }

    private int showResizableFormDialog(JPanel form, String title) {
        JScrollPane scrollPane = UIStyle.scroll(form);
        scrollPane.setPreferredSize(new Dimension(520, 380));
        scrollPane.setMinimumSize(new Dimension(420, 280));

        JOptionPane optionPane = new JOptionPane(
                scrollPane,
                JOptionPane.PLAIN_MESSAGE,
                JOptionPane.OK_CANCEL_OPTION
        );
        JDialog dialog = optionPane.createDialog(this, title);
        dialog.setResizable(true);
        dialog.setMinimumSize(new Dimension(480, 380));
        dialog.setSize(new Dimension(580, 500));
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);

        Object selected = optionPane.getValue();
        if (selected instanceof Integer) {
            return (Integer) selected;
        }
        return JOptionPane.CLOSED_OPTION;
    }

    private void addTemplateRow(JPanel panel, GridBagConstraints gbc, int row, String label, JComponent field) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        panel.add(new JLabel(label), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(field, gbc);
    }

    private void previewActionFlow(boolean responseSection) {
        java.util.List<ProcessingAction> actions = collectActions(responseSection ? responseActionsModel : requestActionsModel);
        if (actions.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    lang.getString("flow.preview.no_steps"),
                    lang.getString("flow.preview.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        Window owner = SwingUtilities.getWindowAncestor(this);
        StepFlowPreviewDialog dialog = new StepFlowPreviewDialog(owner, actions, !responseSection);
        dialog.setVisible(true);
    }

    private void editAction(boolean responseSection) {
        JList<ProcessingAction> list = responseSection ? responseActionsList : requestActionsList;
        int index = list.getSelectedIndex();
        if (index < 0) {
            return;
        }

        ProcessingAction selected = (responseSection ? responseActionsModel : requestActionsModel).getElementAt(index);
        ActionEditDialog dialog = new ActionEditDialog(this, selected.clone(), responseSection, playgroundNavigator);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            (responseSection ? responseActionsModel : requestActionsModel).set(index, dialog.getAction());
            updateActionButtons(responseSection);
        }
    }

    private void removeAction(boolean responseSection) {
        JList<ProcessingAction> list = responseSection ? responseActionsList : requestActionsList;
        int index = list.getSelectedIndex();
        if (index >= 0) {
            (responseSection ? responseActionsModel : requestActionsModel).remove(index);
            updateActionButtons(responseSection);
        }
    }

    private void duplicateAction(boolean responseSection) {
        JList<ProcessingAction> list = responseSection ? responseActionsList : requestActionsList;
        int index = list.getSelectedIndex();
        if (index < 0) {
            return;
        }

        DefaultListModel<ProcessingAction> model = responseSection ? responseActionsModel : requestActionsModel;
        ProcessingAction cloned = model.getElementAt(index).clone();
        model.add(index + 1, cloned);
        list.setSelectedIndex(index + 1);
        updateActionButtons(responseSection);
    }

    private void moveAction(boolean responseSection, int delta) {
        JList<ProcessingAction> list = responseSection ? responseActionsList : requestActionsList;
        int index = list.getSelectedIndex();
        DefaultListModel<ProcessingAction> model = responseSection ? responseActionsModel : requestActionsModel;
        int newIndex = index + delta;
        if (index < 0 || newIndex < 0 || newIndex >= model.size()) {
            return;
        }
        ProcessingAction action = model.remove(index);
        model.add(newIndex, action);
        list.setSelectedIndex(newIndex);
        updateActionButtons(responseSection);
    }

    private void updateActionButtons(boolean responseSection) {
        DefaultListModel<ProcessingAction> model = responseSection ? responseActionsModel : requestActionsModel;
        JList<ProcessingAction> list = responseSection ? responseActionsList : requestActionsList;
        boolean hasSelection = list != null && list.getSelectedIndex() >= 0;
        boolean hasItems = model != null && model.getSize() > 0;

        JButton addButton = responseSection ? responseAddButton : requestAddButton;
        JButton editButton = responseSection ? responseEditButton : requestEditButton;
        JButton removeButton = responseSection ? responseRemoveButton : requestRemoveButton;
        JButton duplicateButton = responseSection ? responseDuplicateButton : requestDuplicateButton;
        JButton upButton = responseSection ? responseUpButton : requestUpButton;
        JButton downButton = responseSection ? responseDownButton : requestDownButton;

        if (addButton != null) addButton.setEnabled(true);
        if (editButton != null) editButton.setEnabled(hasSelection);
        if (removeButton != null) removeButton.setEnabled(hasSelection);
        if (duplicateButton != null) duplicateButton.setEnabled(hasSelection);

        if (upButton != null) {
            boolean enable = hasSelection && list.getSelectedIndex() > 0;
            upButton.setEnabled(enable);
        }

        if (downButton != null) {
            boolean enable = hasSelection && list.getSelectedIndex() < model.getSize() - 1;
            downButton.setEnabled(enable);
        }

        // Ensure list focus updates when items added/removed
        if (!hasItems && list != null) {
            list.clearSelection();
        }
    }

    private static class ActionListCellRenderer extends JPanel implements ListCellRenderer<ProcessingAction> {
        private final JLabel stepLabel = new JLabel();
        private final JLabel titleLabel = new JLabel();
        private final JLabel detailLabel = new JLabel();

        private final boolean responseSection;
        ActionListCellRenderer(boolean responseSection) {
            this.responseSection = responseSection;
            setLayout(new BorderLayout(10, 0));
            setBorder(BorderFactory.createEmptyBorder(7, 10, 7, 10));
            setOpaque(true);
            stepLabel.setHorizontalAlignment(SwingConstants.CENTER);
            stepLabel.setPreferredSize(new Dimension(32, 32));
            stepLabel.setFont(stepLabel.getFont().deriveFont(Font.BOLD, 12f));
            titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 12f));
            detailLabel.setFont(detailLabel.getFont().deriveFont(11f));
            JPanel text = new JPanel(new BorderLayout(0, 3));
            text.setOpaque(false);
            text.add(titleLabel, BorderLayout.NORTH);
            text.add(detailLabel, BorderLayout.CENTER);
            add(stepLabel, BorderLayout.WEST);
            add(text, BorderLayout.CENTER);
        }

        @Override
        public Component getListCellRendererComponent(JList<? extends ProcessingAction> list,
                                                      ProcessingAction value,
                                                      int index,
                                                      boolean isSelected,
                                                      boolean cellHasFocus) {
            LanguageManager lang = LanguageManager.getInstance();
            if (value == null) {
                stepLabel.setText(String.valueOf(index + 1));
                titleLabel.setText("Null action");
                detailLabel.setText("");
            } else {
                stepLabel.setText(String.valueOf(index + 1));
                titleLabel.setText(actionTitle(value, lang));
                detailLabel.setText(actionDetail(value, lang));
            }

            if (isSelected) {
                setBackground(list.getSelectionBackground());
                stepLabel.setForeground(list.getSelectionForeground());
                titleLabel.setForeground(list.getSelectionForeground());
                detailLabel.setForeground(list.getSelectionForeground());
            } else {
                setBackground(index % 2 == 0 ? UIStyle.surface() : UIStyle.background());
                stepLabel.setForeground(UIStyle.accent());
                titleLabel.setForeground(UIStyle.text());
                detailLabel.setForeground(UIStyle.mutedText());
            }
            return this;
        }

        private String actionTitle(ProcessingAction action, LanguageManager lang) {
            return phaseLabel(action, lang) + " · " + input(action, lang) + " -> " + verb(action, lang) + " -> " + target(action, lang);
        }

        private static String actionDetail(ProcessingAction action, LanguageManager lang) {
            StringBuilder detail = new StringBuilder();
            detail.append(zh(lang) ? "处理方式: " : "processor: ").append(valueOr(action.getProcessor(), "-"));

            String algorithm = config(action, Constants.ConfigKey.ALGORITHM);
            if (!algorithm.isEmpty()) {
                detail.append(zh(lang) ? "  算法: " : "  algorithm: ").append(algorithm);
            }

            String provider = config(action, Constants.ConfigKey.CRYPTO_PROVIDER);
            if (!provider.isEmpty()) {
                detail.append(zh(lang) ? "  计算: " : "  engine: ").append(displayProvider(provider, lang));
            }

            String variable = config(action, Constants.ConfigKey.VARIABLE_NAME);
            if (!variable.isEmpty() || Constants.TargetType.VARIABLE.equalsIgnoreCase(action.getTargetType())) {
                detail.append(zh(lang) ? "  变量: " : "  variable: ")
                        .append(valueOr(variable, valueOr(action.getTargetName(), "-")));
            }

            if (!action.isEnabled()) {
                detail.append(zh(lang) ? "  已禁用" : "  disabled");
            }
            return detail.toString();
        }

        private static String input(ProcessingAction action, LanguageManager lang) {
            boolean zh = zh(lang);
            String source = config(action, Constants.ConfigKey.INPUT_SOURCE);
            String name = config(action, Constants.ConfigKey.INPUT_NAME);
            if (!source.isEmpty()) {
                if (Constants.InputSource.HEADER.equalsIgnoreCase(source)) {
                    return (zh ? "读 header " : "read header ") + valueOr(name, "*");
                }
                if (Constants.InputSource.VARIABLE.equalsIgnoreCase(source)) {
                    return (zh ? "读变量 " : "read variable ") + valueOr(name, "*");
                }
                if (Constants.InputSource.RESPONSE_BODY.equalsIgnoreCase(source)) {
                    return zh ? "读响应 body" : "read response body";
                }
                return zh ? "读请求 body" : "read request body";
            }

            String targetType = action.getTargetType() != null ? action.getTargetType().toLowerCase(java.util.Locale.ROOT) : "";
            if (Constants.TargetType.HEADER.equals(targetType)) {
                return (zh ? "读 header " : "read header ") + valueOr(action.getTargetName(), "*");
            }
            if (Constants.TargetType.VARIABLE.equals(targetType)) {
                return (zh ? "读变量 " : "read variable ") + valueOr(config(action, Constants.ConfigKey.VARIABLE_NAME), valueOr(action.getTargetName(), "*"));
            }
            return zh ? "读 body" : "read body";
        }

        private String phaseLabel(ProcessingAction action, LanguageManager lang) {
            String phase = config(action, Constants.ConfigKey.EXECUTION_PHASE);
            if (phase.isEmpty()) {
                phase = responseSection ? Constants.ExecutionPhase.RESPONSE_DISPLAY : Constants.ExecutionPhase.SEND;
            }
            if (phase.contains(",")) {
                return phase;
            }
            boolean zh = zh(lang);
            switch (phase.toLowerCase(java.util.Locale.ROOT)) {
                case Constants.ExecutionPhase.DISPLAY:
                    return zh ? "编辑器显示时" : "editor display";
                case Constants.ExecutionPhase.EDITOR_SEND:
                    return zh ? "编辑器发送时" : "editor send";
                case Constants.ExecutionPhase.SEND:
                    return zh ? "发送前" : "before send";
                case Constants.ExecutionPhase.RESPONSE_DISPLAY:
                    return zh ? "响应显示时" : "response display";
                case Constants.ExecutionPhase.RESPONSE_SEND:
                    return zh ? "响应发送时" : "response send";
                case Constants.ExecutionPhase.RESPONSE_EDITOR_SEND:
                    return zh ? "响应编辑后加密" : "encrypt edited response";
                case Constants.ExecutionPhase.ALWAYS:
                    return zh ? "始终" : "always";
                default:
                    return phase;
            }
        }

        private static String verb(ProcessingAction action, LanguageManager lang) {
            boolean zh = zh(lang);
            String type = action.getActionType() != null ? action.getActionType().toLowerCase(java.util.Locale.ROOT) : "";
            switch (type) {
                case Constants.ActionType.DECRYPT:
                    return zh ? "解密" : "decrypt";
                case Constants.ActionType.ENCRYPT:
                    return zh ? "加密" : "encrypt";
                case Constants.ActionType.SIGN:
                    return zh ? "签名写入" : "sign into";
                case Constants.ActionType.VERIFY:
                    return zh ? "验签" : "verify";
                case Constants.ActionType.REPLACE:
                    return zh ? "替换" : "replace";
                case Constants.ActionType.ADD:
                    return zh ? "添加" : "add";
                case Constants.ActionType.REMOVE:
                    return zh ? "移除" : "remove";
                default:
                    return type.isEmpty() ? (zh ? "处理" : "process") : type;
            }
        }

        private static String target(ProcessingAction action, LanguageManager lang) {
            String targetType = action.getTargetType() != null ? action.getTargetType().toLowerCase(java.util.Locale.ROOT) : "";
            switch (targetType) {
                case Constants.TargetType.BODY:
                    return zh(lang) ? "整个内容" : "body";
                case Constants.TargetType.HEADER:
                    return (zh(lang) ? "Header " : "header ") + valueOr(action.getTargetName(), "*");
                case Constants.TargetType.FIELD:
                    return "JSON " + valueOr(config(action, Constants.ConfigKey.FIELD_PATH), valueOr(action.getTargetName(), "*"));
                case Constants.TargetType.VARIABLE:
                    return (zh(lang) ? "变量 " : "variable ") + valueOr(config(action, Constants.ConfigKey.VARIABLE_NAME), valueOr(action.getTargetName(), "*"));
                default:
                    return targetType.isEmpty() ? "*" : targetType;
            }
        }

        private static String config(ProcessingAction action, String key) {
            if (action == null || action.getConfig() == null || action.getConfig().get(key) == null) {
                return "";
            }
            return String.valueOf(action.getConfig().get(key));
        }

        private static String valueOr(String value, String fallback) {
            return value == null || value.trim().isEmpty() ? fallback : value.trim();
        }

        private static boolean zh(LanguageManager lang) {
            return lang.getCurrentLocale() != null && "zh".equalsIgnoreCase(lang.getCurrentLocale().getLanguage());
        }

        private static String displayProvider(String provider, LanguageManager lang) {
            if (!zh(lang)) {
                return provider;
            }
            if ("internal".equalsIgnoreCase(provider)) {
                return "本地计算";
            }
            if ("external".equalsIgnoreCase(provider)) {
                return "调用外部服务";
            }
            return provider;
        }
    }

}
