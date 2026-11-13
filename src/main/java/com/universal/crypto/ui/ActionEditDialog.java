package com.universal.crypto.ui;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.ui.processor.*;

import com.universal.crypto.util.LanguageManager;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Dialog for creating or editing a single processing action.
 * Refactored to use Strategy Pattern for processor configuration.
 */
public class ActionEditDialog extends JDialog {

    private static final String[] ACTION_TYPES = {
        Constants.ActionType.DECRYPT,
        Constants.ActionType.ENCRYPT,
        Constants.ActionType.SIGN,
        Constants.ActionType.VERIFY,
        Constants.ActionType.REPLACE,
        Constants.ActionType.ADD,
        Constants.ActionType.REMOVE
    };

    private static final String[] TARGET_TYPES = {
        Constants.TargetType.BODY,
        Constants.TargetType.HEADER,
        Constants.TargetType.FIELD,
        Constants.TargetType.VARIABLE
    };

    private static final String[] PROCESSORS = {
        Constants.ProcessorType.CRYPTO,
        Constants.ProcessorType.SIGNATURE,
        Constants.ProcessorType.FIELD,
        Constants.ProcessorType.SCRIPT
    };

    private static final Set<String> HANDLED_KEYS = new HashSet<>();

    static {
        HANDLED_KEYS.add(ConfigKey.ALGORITHM);
        HANDLED_KEYS.add(ConfigKey.INPUT_SOURCE);
        HANDLED_KEYS.add(ConfigKey.INPUT_NAME);
        HANDLED_KEYS.add(ConfigKey.VARIABLE_NAME);
        HANDLED_KEYS.add(ConfigKey.CRYPTO_PROVIDER);
        HANDLED_KEYS.add(ConfigKey.KEY_SOURCE);
        HANDLED_KEYS.add(ConfigKey.KEY_VALUE);
        HANDLED_KEYS.add(ConfigKey.LOOKUP_METHOD);
        HANDLED_KEYS.add(ConfigKey.LOOKUP_ENDPOINT);
        HANDLED_KEYS.add(ConfigKey.RESPONSE_KEY_PATH);
        HANDLED_KEYS.add(ConfigKey.FALLBACK_LOOKUP);
        HANDLED_KEYS.add(ConfigKey.ENCRYPT_ENDPOINT);
        HANDLED_KEYS.add(ConfigKey.DECRYPT_ENDPOINT);
        HANDLED_KEYS.add(ConfigKey.ENCRYPT_METHOD);
        HANDLED_KEYS.add(ConfigKey.DECRYPT_METHOD);
        HANDLED_KEYS.add(ConfigKey.CIPHER_FIELD);
        HANDLED_KEYS.add(ConfigKey.PLAIN_FIELD);
        HANDLED_KEYS.add(ConfigKey.IV_FIELD);
        HANDLED_KEYS.add(ConfigKey.IV_LITERAL_VALUE);
        HANDLED_KEYS.add(ConfigKey.CIPHER_FORMAT);
        HANDLED_KEYS.add(ConfigKey.PLAIN_FORMAT);
        HANDLED_KEYS.add(ConfigKey.IV_FORMAT);
        HANDLED_KEYS.add(ConfigKey.PAYLOAD_FORMAT);
        HANDLED_KEYS.add(ConfigKey.CHARSET);
        HANDLED_KEYS.add(ConfigKey.GCM_TAG_LENGTH);
        HANDLED_KEYS.add(ConfigKey.RSA_PUBLIC_KEY);
        HANDLED_KEYS.add(ConfigKey.RSA_PRIVATE_KEY);
        HANDLED_KEYS.add(ConfigKey.RSA_MODE);
        HANDLED_KEYS.add(ConfigKey.RSA_PADDING);
        HANDLED_KEYS.add(ConfigKey.EXECUTION_PHASE);
        HANDLED_KEYS.add(ConfigKey.EDITOR_ONLY);
        HANDLED_KEYS.add(ConfigKey.SORT_KEYS);
        HANDLED_KEYS.add(ConfigKey.URL_ENCODE_VALUES);
        HANDLED_KEYS.add(ConfigKey.PAIR_SEPARATOR);
        HANDLED_KEYS.add(ConfigKey.KV_SEPARATOR);
        HANDLED_KEYS.add(ConfigKey.HASH_KEY_PLACEMENT);
        HANDLED_KEYS.add(ConfigKey.SIGNATURE_HEX_CASE);
        HANDLED_KEYS.add(ConfigKey.SIGN_CONTENT);
        HANDLED_KEYS.add(ConfigKey.CUSTOM_SIGN_TEMPLATE);
        HANDLED_KEYS.add(ConfigKey.HEADER_TEMPLATES);
        HANDLED_KEYS.add(ConfigKey.SIGNATURE_HEADER);
        HANDLED_KEYS.add(ConfigKey.EXPECTED_SIGNATURE);
        HANDLED_KEYS.add(ConfigKey.SIGNATURE_SOURCE);
        HANDLED_KEYS.add(ConfigKey.SIGNATURE_FIELD_PATH);
        HANDLED_KEYS.add(ConfigKey.SIGNATURE_QUERY_PARAM);
        HANDLED_KEYS.add(ConfigKey.SIGN_ENDPOINT);
        HANDLED_KEYS.add(ConfigKey.SIGN_METHOD);
        HANDLED_KEYS.add(ConfigKey.VERIFY_ENDPOINT);
        HANDLED_KEYS.add(ConfigKey.VERIFY_METHOD);
        HANDLED_KEYS.add(ConfigKey.TO);
        HANDLED_KEYS.add(ConfigKey.OVERWRITE);
        HANDLED_KEYS.add(ConfigKey.IGNORE_NOT_FOUND);
        HANDLED_KEYS.add(ConfigKey.OPERATION);
        HANDLED_KEYS.add(ConfigKey.FIELD_PATH);
        HANDLED_KEYS.add(ConfigKey.SCRIPT_CODE);
    }

    private final boolean responseAction;
    private ProcessingAction action;
    private boolean confirmed;
    private final Set<String> originalExtraKeys = new HashSet<>();
    
    private final LanguageManager lang = LanguageManager.getInstance();

    // General fields
    private JComboBox<String> actionTypeCombo;
    private JComboBox<String> targetTypeCombo;
    private JTextField targetNameField;
    
    // Input Source
    private JComboBox<String> inputSourceCombo;
    private JTextField inputNameField;
    private JPanel inputSourcePanel;
    
    private JComboBox<String> processorCombo;

    // Execution phases
    private JCheckBox phaseDisplayCheck;
    private JCheckBox phaseEditorSendCheck;
    private JCheckBox phaseSendCheck;
    private JCheckBox phaseResponseDisplayCheck;
    private JCheckBox phaseResponseSendCheck;
    private JCheckBox phaseResponseEditorSendCheck;
    private JCheckBox phaseAlwaysCheck;
    private JCheckBox editorOnlyCheck;
    private JTextField customPhaseField;

    // Processor Strategy
    private JPanel configCardPanel;
    private CardLayout configCardLayout;
    private Map<String, ProcessorConfigUI> processorUIMap;
    private ProcessorConfigUI currentProcessorUI;
    private boolean loadingAction;
    private boolean syncingActionDefaults;

    // Extra config table
    private DefaultTableModel extraConfigModel;
    private JTable extraConfigTable;
    
    private final java.util.function.Consumer<ProcessingAction> playgroundNavigator;
    
    public ActionEditDialog(Window owner, ProcessingAction action, boolean responseAction, java.util.function.Consumer<ProcessingAction> playgroundNavigator) {
        super(owner, action == null ? LanguageManager.getInstance().getString("action.dialog.add_title") : LanguageManager.getInstance().getString("action.dialog.edit_title"), ModalityType.APPLICATION_MODAL);
        this.action = action == null ? null : action.clone();
        this.responseAction = responseAction;
        this.playgroundNavigator = playgroundNavigator;
        initializeProcessors();
        buildUI();
        loadAction(this.action);
    }
    
    private void initializeProcessors() {
        processorUIMap = new HashMap<>();
        processorUIMap.put(Constants.ProcessorType.CRYPTO, new CryptoConfigPanel());
        processorUIMap.put(Constants.ProcessorType.SIGNATURE, new SignatureConfigPanel());
        processorUIMap.put(Constants.ProcessorType.FIELD, new FieldConfigPanel());
        processorUIMap.put(Constants.ProcessorType.SCRIPT, new ScriptConfigPanel());
    }

    private void buildUI() {
        setSize(820, 620);
        setMinimumSize(new Dimension(760, 560));
        setLocationRelativeTo(getParent());
        setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBorder(BorderFactory.createEmptyBorder(10, 12, 0, 12));
        tabbedPane.addTab(lang.getString("action.tab.general"), wrapWithScroll(createGeneralPanel()));
        tabbedPane.addTab(lang.getString("action.tab.config"), wrapWithScroll(createConfigPanel()));
        tabbedPane.addTab(lang.getString("action.tab.extra"), wrapWithScroll(createAdvancedPanel()));

        add(tabbedPane, BorderLayout.CENTER);
        add(createButtonPanel(), BorderLayout.SOUTH);
    }

    private JPanel createGeneralPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 12));
        panel.setBorder(UIStyle.emptyBorder());
        panel.setBackground(UIStyle.background());

        panel.add(createNote(lang.getString("action.help.general")), BorderLayout.NORTH);

        JPanel form = new JPanel(new GridBagLayout());
        form.setBackground(UIStyle.background());
        form.setBorder(UIStyle.sectionBorder(lang.getString("action.section.intent")));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        actionTypeCombo = new JComboBox<>(ACTION_TYPES);
        actionTypeCombo.addActionListener(e -> onActionTypeChanged());
        addFormRow(form, gbc, 0, lang.getString("action.label.type"), actionTypeCombo);

        targetTypeCombo = new JComboBox<>(TARGET_TYPES);
        targetTypeCombo.addActionListener(e -> updateTargetInputs());
        addFormRow(form, gbc, 1, lang.getString("action.label.target_type"), targetTypeCombo);

        targetNameField = new JTextField();
        targetNameField.setToolTipText(lang.getString("action.tooltip.header"));
        addFormRow(form, gbc, 2, lang.getString("action.label.target_name"), targetNameField);

        processorCombo = new JComboBox<>(PROCESSORS);
        processorCombo.addActionListener(e -> updateProcessorSelection());
        addFormRow(form, gbc, 3, lang.getString("action.label.processor"), processorCombo);

        JPanel center = new JPanel(new GridLayout(1, 2, 12, 0));
        center.setOpaque(false);
        center.add(createInputSourcePanel());
        center.add(createPhasePanel());

        panel.add(form, BorderLayout.CENTER);
        panel.add(center, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel createInputSourcePanel() {
        inputSourcePanel = new JPanel(new GridBagLayout());
        inputSourcePanel.setBackground(UIStyle.background());
        inputSourcePanel.setBorder(UIStyle.sectionBorder(lang.getString("action.group.input")));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        inputSourcePanel.add(UIStyle.mutedLabel(lang.getString("action.help.input")), gbc);
        gbc.gridwidth = 1;
        
        // Input Source Type
        gbc.gridx = 0; gbc.gridy = 1;
        inputSourcePanel.add(new JLabel(lang.getString("action.label.input_source")), gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        String[] sources = {
            lang.getString("action.input.default"),
            Constants.InputSource.REQUEST_BODY,
            Constants.InputSource.RESPONSE_BODY,
            Constants.InputSource.HEADER,
            Constants.InputSource.VARIABLE
        };
        inputSourceCombo = new JComboBox<>(sources);
        inputSourceCombo.addActionListener(e -> updateInputNameVisibility());
        inputSourcePanel.add(inputSourceCombo, gbc);
        
        // Input Name
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0.0;
        inputSourcePanel.add(new JLabel(lang.getString("action.label.input_name")), gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        inputNameField = new JTextField();
        inputSourcePanel.add(inputNameField, gbc);
        
        return inputSourcePanel;
    }

    private void updateTargetInputs() {
        String type = (String) targetTypeCombo.getSelectedItem();
        boolean isVariable = Constants.TargetType.VARIABLE.equals(type);
        boolean isHeader = Constants.TargetType.HEADER.equals(type);
        boolean isBody = Constants.TargetType.BODY.equals(type);
        
        if (isVariable) {
            targetNameField.setToolTipText(lang.getString("action.tooltip.var"));
            targetNameField.setEnabled(true);
        } else if (isHeader) {
            targetNameField.setToolTipText(lang.getString("action.tooltip.header"));
            targetNameField.setEnabled(true);
        } else {
            targetNameField.setToolTipText(lang.getString("action.tooltip.body_empty"));
            targetNameField.setEnabled(!isBody);
            if (isBody) targetNameField.setText("");
        }
    }

    private void updateInputNameVisibility() {
        String source = (String) inputSourceCombo.getSelectedItem();
        boolean needsName = Constants.InputSource.HEADER.equals(source) || Constants.InputSource.VARIABLE.equals(source);
        inputNameField.setEnabled(needsName);
        if (!needsName) inputNameField.setText("");
    }

    private JPanel createPhasePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(UIStyle.background());
        panel.setBorder(UIStyle.sectionBorder(lang.getString("action.label.phases")));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;

        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(UIStyle.mutedLabel(lang.getString("action.help.phases")), gbc);

        phaseDisplayCheck = new JCheckBox(lang.getString("action.phase.display"));
        phaseEditorSendCheck = new JCheckBox(lang.getString("action.phase.editor_send"));
        phaseSendCheck = new JCheckBox(lang.getString("action.phase.send"));
        phaseResponseDisplayCheck = new JCheckBox(lang.getString("action.phase.response_display"));
        phaseResponseSendCheck = new JCheckBox(lang.getString("action.phase.response_send"));
        phaseResponseEditorSendCheck = new JCheckBox(lang.getString("action.phase.response_editor_send"));
        phaseAlwaysCheck = new JCheckBox(lang.getString("action.phase.always"));

        java.util.List<JCheckBox> checks = Arrays.asList(
            phaseDisplayCheck,
            phaseEditorSendCheck,
            phaseSendCheck,
            phaseResponseDisplayCheck,
            phaseResponseSendCheck,
            phaseResponseEditorSendCheck,
            phaseAlwaysCheck
        );
        for (int i = 0; i < checks.size(); i++) {
            gbc.gridy = i + 1;
            JCheckBox check = checks.get(i);
            check.setOpaque(false);
            panel.add(check, gbc);
        }

        JPanel customRow = new JPanel(new BorderLayout(8, 0));
        customRow.setOpaque(false);
        customRow.add(new JLabel(lang.getString("action.phase.custom")), BorderLayout.WEST);
        customPhaseField = new JTextField(30);
        customRow.add(customPhaseField, BorderLayout.CENTER);
        gbc.gridy = checks.size() + 1;
        panel.add(customRow, gbc);
        editorOnlyCheck = new JCheckBox(lang.getString("action.editor_only"));
        editorOnlyCheck.setOpaque(false);
        editorOnlyCheck.setVisible(!responseAction);
        editorOnlyCheck.setToolTipText(lang.getString("action.editor_only.help"));
        gbc.gridy++;
        panel.add(editorOnlyCheck, gbc);
        return panel;
    }
    
    private JPanel createConfigPanel() {
        configCardLayout = new CardLayout();
        configCardPanel = new JPanel(configCardLayout);
        configCardPanel.setBorder(UIStyle.emptyBorder());
        configCardPanel.setBackground(UIStyle.background());
        
        for (Map.Entry<String, ProcessorConfigUI> entry : processorUIMap.entrySet()) {
            configCardPanel.add(entry.getValue().getPanel(), entry.getKey());
        }
        
        return configCardPanel;
    }

    private JPanel createAdvancedPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(UIStyle.emptyBorder());
        panel.setBackground(UIStyle.background());

        extraConfigModel = new DefaultTableModel(new Object[]{"Key", "Value"}, 0);
        extraConfigTable = new JTable(extraConfigModel);
        extraConfigTable.setFillsViewportHeight(true);
        UIStyle.styleTable(extraConfigTable);

        JPanel note = createNote(lang.getString("action.help.extra"));
        panel.add(note, BorderLayout.NORTH);
        panel.add(UIStyle.scroll(extraConfigTable), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.setOpaque(false);
        JButton addRow = UIStyle.button(lang.getString("btn.add"));
        addRow.setIcon(UIStyle.icon(UIStyle.IconType.ADD));
        addRow.addActionListener(e -> extraConfigModel.addRow(new Object[]{"", ""}));
        JButton removeRow = UIStyle.dangerButton(lang.getString("btn.remove"));
        removeRow.setIcon(UIStyle.icon(UIStyle.IconType.DELETE));
        removeRow.addActionListener(e -> {
            int row = extraConfigTable.getSelectedRow();
            if (row >= 0) {
                extraConfigModel.removeRow(row);
            }
        });
        buttons.add(addRow);
        buttons.add(removeRow);

        panel.add(buttons, BorderLayout.SOUTH);

        return panel;
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
        okButton.addActionListener(e -> saveAction());

        JButton testButton = UIStyle.button(lang.getString("action.btn.test"));
        testButton.setIcon(UIStyle.icon(UIStyle.IconType.RUN));
        testButton.addActionListener(e -> showTestDialog());

        panel.add(testButton);
        panel.add(Box.createHorizontalStrut(20)); // Spacer
        panel.add(cancelButton);
        panel.add(okButton);

        return panel;
    }

    private JComponent wrapWithScroll(JComponent component) {
        JScrollPane pane = new JScrollPane(component,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        pane.getVerticalScrollBar().setUnitIncrement(16);
        pane.setBorder(BorderFactory.createEmptyBorder());
        return pane;
    }

    private void addFormRow(JPanel panel, GridBagConstraints gbc, int row, String labelText, JComponent field) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel(labelText), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(field, gbc);
    }

    private JPanel createNote(String text) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(UIStyle.background());
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

        JTextArea note = new JTextArea(text);
        note.setEditable(false);
        note.setLineWrap(true);
        note.setWrapStyleWord(true);
        UIStyle.styleTextArea(note, false);
        panel.add(note, BorderLayout.CENTER);
        return panel;
    }

    private void loadAction(ProcessingAction existing) {
        loadingAction = true;
        if (existing == null) {
            // Defaults
            actionTypeCombo.setSelectedItem(responseAction ? Constants.ActionType.DECRYPT : Constants.ActionType.ENCRYPT);
            loadingAction = false;
            applyActionTypeDefaults(true);
            updateProcessorSelection();
            return;
        }

        if (existing.getActionType() != null) {
            boolean listed = false;
            for (int i = 0; i < actionTypeCombo.getItemCount(); i++) listed |= existing.getActionType().equals(actionTypeCombo.getItemAt(i));
            if (!listed) actionTypeCombo.addItem(existing.getActionType());
        }
        actionTypeCombo.setSelectedItem(existing.getActionType());
        targetTypeCombo.setSelectedItem(Constants.ProcessorType.FIELD.equals(existing.getProcessor()) && Constants.TargetType.BODY.equals(existing.getTargetType())
                ? Constants.TargetType.FIELD : existing.getTargetType());
        targetNameField.setText(Constants.TargetType.VARIABLE.equals(existing.getTargetType())
                ? existing.getConfigString(ConfigKey.VARIABLE_NAME, existing.getTargetName())
                : Constants.ProcessorType.FIELD.equals(existing.getProcessor()) ? existing.getConfigString(ConfigKey.FIELD_PATH, existing.getTargetName()) : existing.getTargetName());
        processorCombo.setSelectedItem(existing.getProcessor());

        Map<String, Object> config = existing.getConfig();
        if (config == null) {
            config = new HashMap<>();
        }
        
        // Load Input Source
        String inputSource = stringValue(config.get(ConfigKey.INPUT_SOURCE));
        if (inputSource != null && !inputSource.isEmpty()) {
            boolean listed = false;
            for (int i = 0; i < inputSourceCombo.getItemCount(); i++) listed |= inputSource.equals(inputSourceCombo.getItemAt(i));
            if (!listed) inputSourceCombo.addItem(inputSource);
            inputSourceCombo.setSelectedItem(inputSource);
            inputNameField.setText(stringValue(config.get(ConfigKey.INPUT_NAME)));
        } else {
            inputSourceCombo.setSelectedIndex(0); // Default
        }
        updateInputNameVisibility();
        updateTargetInputs();

        // Execution phase
        editorOnlyCheck.setSelected(Boolean.parseBoolean(stringValue(config.get(ConfigKey.EDITOR_ONLY))));
        String phaseValue = stringValue(config.get(ConfigKey.EXECUTION_PHASE));
        applyPhaseValue(phaseValue);

        // Load config into appropriate processor UI
        updateProcessorSelection();
        if (currentProcessorUI != null) {
            currentProcessorUI.loadConfig(existing);
            currentProcessorUI.onActionTypeChanged(existing.getActionType(), responseAction);
        }

        // Extra config
        extraConfigModel.setRowCount(0);
        for (Map.Entry<String, Object> entry : config.entrySet()) {
            if (HANDLED_KEYS.contains(entry.getKey())) {
                continue;
            }
            originalExtraKeys.add(entry.getKey());
            extraConfigModel.addRow(new Object[]{entry.getKey(), entry.getValue()});
        }
        loadingAction = false;
    }

    private void onActionTypeChanged() {
        if (!loadingAction) {
            applyActionTypeDefaults(true);
        }
        updateUIState();
    }

    private void applyActionTypeDefaults(boolean resetTargetAndPhase) {
        if (syncingActionDefaults) {
            return;
        }

        syncingActionDefaults = true;
        try {
            String actionType = (String) actionTypeCombo.getSelectedItem();
            String processor = recommendedProcessorForAction(actionType);
            if (processor != null && processorCombo != null && !Constants.ProcessorType.SCRIPT.equals(processorCombo.getSelectedItem())) {
                processorCombo.setSelectedItem(processor);
            }

            if (resetTargetAndPhase) {
                applyRecommendedTarget(actionType);
                applyRecommendedPhases(actionType);
            }
        } finally {
            syncingActionDefaults = false;
        }
    }

    private String recommendedProcessorForAction(String actionType) {
        if (Constants.ActionType.SIGN.equals(actionType) || Constants.ActionType.VERIFY.equals(actionType)) {
            return Constants.ProcessorType.SIGNATURE;
        }
        if (Constants.ActionType.ENCRYPT.equals(actionType) || Constants.ActionType.DECRYPT.equals(actionType)) {
            return Constants.ProcessorType.CRYPTO;
        }
        if (Constants.ActionType.REPLACE.equals(actionType)
                || Constants.ActionType.ADD.equals(actionType)
                || Constants.ActionType.REMOVE.equals(actionType)) {
            return Constants.ProcessorType.FIELD;
        }
        return null;
    }

    private void applyRecommendedTarget(String actionType) {
        if (targetTypeCombo == null || targetNameField == null) {
            return;
        }

        if (Constants.ActionType.SIGN.equals(actionType)) {
            targetTypeCombo.setSelectedItem(Constants.TargetType.HEADER);
            if (targetNameField.getText().trim().isEmpty()) {
                targetNameField.setText("X-Signature");
            }
        } else if (Constants.ActionType.VERIFY.equals(actionType)) {
            targetTypeCombo.setSelectedItem(Constants.TargetType.BODY);
            targetNameField.setText("");
        } else if (Constants.ActionType.REPLACE.equals(actionType)
                || Constants.ActionType.ADD.equals(actionType)
                || Constants.ActionType.REMOVE.equals(actionType)) {
            targetTypeCombo.setSelectedItem(Constants.TargetType.FIELD);
            if (targetNameField.getText().trim().isEmpty()) {
                targetNameField.setText("$.data");
            }
        } else {
            targetTypeCombo.setSelectedItem(Constants.TargetType.BODY);
            targetNameField.setText("");
        }
        updateTargetInputs();
    }

    private void applyRecommendedPhases(String actionType) {
        if (phaseDisplayCheck == null) {
            return;
        }

        phaseDisplayCheck.setSelected(false);
        phaseEditorSendCheck.setSelected(false);
        phaseSendCheck.setSelected(false);
        phaseResponseDisplayCheck.setSelected(false);
        phaseResponseSendCheck.setSelected(false);
        phaseResponseEditorSendCheck.setSelected(false);
        phaseAlwaysCheck.setSelected(false);
        customPhaseField.setText("");

        if (responseAction) {
            if (Constants.ActionType.ENCRYPT.equals(actionType)) phaseResponseEditorSendCheck.setSelected(true);
            else phaseResponseDisplayCheck.setSelected(true);
            return;
        }

        if (Constants.ActionType.DECRYPT.equals(actionType)) {
            phaseDisplayCheck.setSelected(true);
        } else if (Constants.ActionType.ENCRYPT.equals(actionType)) {
            phaseEditorSendCheck.setSelected(true);
        } else {
            phaseSendCheck.setSelected(true);
        }
    }
    
    private void updateProcessorSelection() {
        String processor = (String) processorCombo.getSelectedItem();
        configCardLayout.show(configCardPanel, processor);
        currentProcessorUI = processorUIMap.get(processor);
        updateUIState();
    }
    
    private void updateUIState() {
        String actionType = (String) actionTypeCombo.getSelectedItem();
        if (currentProcessorUI != null) {
            currentProcessorUI.onActionTypeChanged(actionType, responseAction);
        }

        // Some panels might need to know about Action Type (e.g. FieldConfigPanel hides value for remove)
        if (currentProcessorUI instanceof FieldConfigPanel) {
            ((FieldConfigPanel) currentProcessorUI).updateVisibility(actionType);
        }
        if (currentProcessorUI instanceof CryptoConfigPanel) {
            ((CryptoConfigPanel) currentProcessorUI).updateVisibility();
        }
    }

    private void saveAction() {
        if (extraConfigTable.isEditing() && !extraConfigTable.getCellEditor().stopCellEditing()) return;
        if (targetNameField.getText().trim().isEmpty() && !Constants.TargetType.BODY.equals(targetTypeCombo.getSelectedItem())) {
             JOptionPane.showMessageDialog(this, lang.getString("validation.action.target_name"));
             return;
        }
        
        if (currentProcessorUI == null || !currentProcessorUI.validateConfig()) {
            return;
        }

        try {
            action = buildAction();
            confirmed = true;
            dispose();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), lang.getString("error.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    ProcessingAction buildAction() {
        if (extraConfigTable.isEditing() && !extraConfigTable.getCellEditor().stopCellEditing())
            throw new IllegalArgumentException(lang.getString("action.validation.pending_edit"));
        ProcessingAction candidate = action == null ? new ProcessingAction() : action.clone();
        candidate.setActionType((String) actionTypeCombo.getSelectedItem());
        candidate.setTargetType((String) targetTypeCombo.getSelectedItem());
        candidate.setTargetName(targetNameField.getText().trim());
        candidate.setProcessor((String) processorCombo.getSelectedItem());
        Map<String, Object> config = candidate.getConfig();
        originalExtraKeys.forEach(config::remove);
        for (String key : new String[]{ConfigKey.EXECUTION_PHASE, ConfigKey.EDITOR_ONLY, ConfigKey.INPUT_SOURCE, ConfigKey.INPUT_NAME, ConfigKey.VARIABLE_NAME}) config.remove(key);
        savePhases(candidate);
        if (inputSourceCombo.getSelectedIndex() > 0) {
            config.put(ConfigKey.INPUT_SOURCE, inputSourceCombo.getSelectedItem());
            config.put(ConfigKey.INPUT_NAME, inputNameField.getText());
        }
        if (Constants.TargetType.VARIABLE.equals(candidate.getTargetType())) config.put(ConfigKey.VARIABLE_NAME, candidate.getTargetName());
        currentProcessorUI.saveConfig(candidate);
        if (Constants.ProcessorType.FIELD.equals(candidate.getProcessor())) {
            config.put(ConfigKey.OPERATION, candidate.getActionType());
            if (Constants.TargetType.FIELD.equals(candidate.getTargetType())) config.put(ConfigKey.FIELD_PATH, candidate.getTargetName());
        }
        Set<String> extraKeys = new HashSet<>();
        Set<String> commonKeys = Set.of(ConfigKey.EXECUTION_PHASE, ConfigKey.EDITOR_ONLY, ConfigKey.INPUT_SOURCE, ConfigKey.INPUT_NAME, ConfigKey.VARIABLE_NAME);
        for (int i = 0; i < extraConfigModel.getRowCount(); i++) {
            Object key = extraConfigModel.getValueAt(i, 0);
            if (key == null || key.toString().trim().isEmpty()) continue;
            String name = key.toString().trim();
            if (commonKeys.contains(name)) throw new IllegalArgumentException(lang.format("action.validation.common_override", name));
            if (!extraKeys.add(name)) throw new IllegalArgumentException(lang.format("action.validation.duplicate_key", name));
            config.put(name, extraConfigModel.getValueAt(i, 1));
        }
        return candidate;
    }

    private void savePhases(ProcessingAction action) {
        if (!responseAction && editorOnlyCheck.isSelected()) action.setConfig(ConfigKey.EDITOR_ONLY, true);
        StringBuilder sb = new StringBuilder();
        if (phaseDisplayCheck.isSelected()) sb.append("display,");
        if (phaseEditorSendCheck.isSelected()) sb.append("editor-send,");
        if (phaseSendCheck.isSelected()) sb.append("send,");
        if (phaseResponseDisplayCheck.isSelected()) sb.append("response-display,");
        if (phaseResponseSendCheck.isSelected()) sb.append("response-send,");
        if (phaseResponseEditorSendCheck.isSelected()) sb.append("response-editor-send,");
        if (phaseAlwaysCheck.isSelected()) sb.append("always,");
        
        String custom = customPhaseField.getText().trim();
        if (!custom.isEmpty()) {
             sb.append(custom);
        }
        
        String val = sb.toString();
        if (val.endsWith(",")) val = val.substring(0, val.length() - 1);
        
        if (!val.isEmpty()) {
            action.getConfig().put(ConfigKey.EXECUTION_PHASE, val);
        }
    }

    private void applyPhaseValue(String value) {
        phaseDisplayCheck.setSelected(false);
        phaseEditorSendCheck.setSelected(false);
        phaseSendCheck.setSelected(false);
        phaseResponseDisplayCheck.setSelected(false);
        phaseResponseSendCheck.setSelected(false);
        phaseResponseEditorSendCheck.setSelected(false);
        phaseAlwaysCheck.setSelected(false);
        customPhaseField.setText("");

        if (value == null || value.isEmpty()) return;

        String[] parts = value.split(",");
        StringBuilder custom = new StringBuilder();

        for (String p : parts) {
            String t = p.trim();
            switch (t) {
                case "display": phaseDisplayCheck.setSelected(true); break;
                case "editor-send": phaseEditorSendCheck.setSelected(true); break;
                case "send": phaseSendCheck.setSelected(true); break;
                case "response-display": phaseResponseDisplayCheck.setSelected(true); break;
                case "response-send": phaseResponseSendCheck.setSelected(true); break;
                case "response-editor-send": phaseResponseEditorSendCheck.setSelected(true); break;
                case "always": phaseAlwaysCheck.setSelected(true); break;
                default: 
                    if (!t.isEmpty()) custom.append(t).append(","); 
                    break;
            }
        }
        
        String c = custom.toString();
        if (c.endsWith(",")) c = c.substring(0, c.length() - 1);
        customPhaseField.setText(c);
    }
    
    private void showTestDialog() {
        if (playgroundNavigator != null) {
            try {
                ProcessingAction draft = buildAction();
                if (playgroundNavigator instanceof ActionTestNavigator navigator) navigator.open(this, draft, responseAction);
                else playgroundNavigator.accept(draft);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), lang.getString("error.title"), JOptionPane.ERROR_MESSAGE);
            }
        } else {
             JOptionPane.showMessageDialog(this, lang.getString("validation.action.playground_hint"));
        }
    }

    public ProcessingAction getAction() {
        return action;
    }

    public boolean isConfirmed() {
        return confirmed;
    }
    
    private String stringValue(Object obj) {
        return obj == null ? "" : obj.toString();
    }
}
