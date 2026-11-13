package com.universal.crypto.ui;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleCondition;
import com.universal.crypto.util.LanguageManager;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Scenario-first wizard for creating common rules without exposing the internal
 * rule/action/processor/phase model.
 */
public class QuickRuleWizardDialog extends JDialog {

    private final LanguageManager lang = LanguageManager.getInstance();

    private ProcessingRule generatedRule;
    private boolean confirmed = false;

    private JList<Scenario> scenarioList;
    private JTextField ruleNameField;
    private JTextField hostField;
    private JTextField pathField;
    private JTextField methodsField;
    private JTextField contentTypeField;
    private JComboBox<String> providerCombo;
    private JComboBox<String> algorithmCombo;
    private JTextField keyField;
    private JTextField externalEndpointField;
    private JComboBox<String> keyFormatCombo;
    private JComboBox<String> payloadFormatCombo;
    private JTextField cipherField;
    private JTextField ivField;
    private JTextField ivLiteralField;
    private JComboBox<String> ivFormatCombo;
    private JLabel keyFormatLabel, payloadFormatLabel, cipherLabel, ivLabel, ivLiteralLabel, ivFormatLabel;
    private JTextField headerNameField;
    private JTextField fieldPathField;
    private JTextField replacementValueField;
    private JTextArea summaryArea;

    private JLabel providerLabel;
    private JLabel algorithmLabel;
    private JLabel keyLabel;
    private JLabel externalEndpointLabel;
    private JLabel contentTypeLabel;
    private JLabel headerNameLabel;
    private JLabel fieldPathLabel;
    private JLabel replacementValueLabel;
    private SourceRequest sourceRequest;

    public QuickRuleWizardDialog(Window owner, String host, String path) {
        super(owner, LanguageManager.getInstance().getString("wizard.title"), ModalityType.APPLICATION_MODAL);
        initializeUI(host, path);
    }

    public QuickRuleWizardDialog(Window owner, SourceRequest sourceRequest) {
        super(owner, LanguageManager.getInstance().getString("wizard.title"), ModalityType.APPLICATION_MODAL);
        this.sourceRequest = sourceRequest;
        initializeUI(sourceRequest != null ? sourceRequest.host() : "", sourceRequest != null ? sourceRequest.path() : "");
    }

    private void initializeUI(String host, String path) {
        setLayout(new BorderLayout());
        setSize(760, 560);
        setMinimumSize(new Dimension(680, 500));
        setLocationRelativeTo(getParent());

        JPanel content = new JPanel(new BorderLayout(14, 0));
        content.setBorder(UIStyle.emptyBorder());
        content.setBackground(UIStyle.background());
        add(content, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, createScenarioPanel(), createDetailsPanel(host, path));
        SplitPaneLayout.initialize(split, 0.34);
        split.getLeftComponent().setMinimumSize(new Dimension(190, 0));
        split.getRightComponent().setMinimumSize(new Dimension(0, 0));
        content.add(split, BorderLayout.CENTER);
        add(createButtonPanel(), BorderLayout.SOUTH);

        scenarioList.setSelectedIndex(0);
        applySourceRequestDefaults();
        updateScenario();
    }

    private JPanel createScenarioPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setPreferredSize(new Dimension(250, 420));
        panel.setBackground(UIStyle.background());
        panel.setBorder(UIStyle.sectionBorder(lang.getString("wizard.section.scenario")));

        DefaultListModel<Scenario> model = new DefaultListModel<>();
        Arrays.stream(Scenario.values()).forEach(model::addElement);
        scenarioList = new JList<>(model);
        scenarioList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        scenarioList.setFixedCellHeight(74);
        scenarioList.setCellRenderer(new ScenarioRenderer());
        scenarioList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateScenario();
            }
        });

        panel.add(UIStyle.scroll(scenarioList), BorderLayout.CENTER);
        return panel;
    }

    private JPanel createDetailsPanel(String host, String path) {
        JPanel panel = new JPanel(new BorderLayout(0, 12));
        panel.setOpaque(false);

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBackground(UIStyle.background());
        formPanel.setBorder(UIStyle.sectionBorder(lang.getString("wizard.section.scope")));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;
        ruleNameField = new JTextField();
        addFormRow(formPanel, gbc, row++, lang.getString("wizard.label.rule_name"), ruleNameField);

        hostField = new JTextField(host != null ? host : "");
        addFormRow(formPanel, gbc, row++, lang.getString("wizard.label.host"), hostField);

        pathField = new JTextField(path != null && !path.trim().isEmpty() ? path : "/*");
        addFormRow(formPanel, gbc, row++, lang.getString("wizard.label.path"), pathField);

        methodsField = new JTextField("POST");
        addFormRow(formPanel, gbc, row++, lang.getString("wizard.label.methods"), methodsField);

        contentTypeLabel = new JLabel(lang.getString("wizard.label.content_type"));
        contentTypeField = new JTextField();
        contentTypeField.setToolTipText(lang.getString("wizard.tip.content_type"));
        addFormRow(formPanel, gbc, row++, contentTypeLabel, contentTypeField);

        providerLabel = new JLabel(lang.getString("wizard.label.provider"));
        providerCombo = new JComboBox<>(new String[]{
                lang.getString("wizard.provider.internal"),
                lang.getString("wizard.provider.external")
        });
        providerCombo.setToolTipText(lang.getString("wizard.tip.provider"));
        providerCombo.addActionListener(e -> { updateEnvelopeVisibility(); updateSummary(); });
        addFormRow(formPanel, gbc, row++, providerLabel, providerCombo);

        algorithmLabel = new JLabel(lang.getString("wizard.label.algorithm"));
        algorithmCombo = new JComboBox<>();
        algorithmCombo.setEditable(true);
        algorithmCombo.addActionListener(e -> { updateEnvelopeVisibility(); updateSummary(); });
        addFormRow(formPanel, gbc, row++, algorithmLabel, algorithmCombo);

        keyLabel = new JLabel(lang.getString("wizard.label.key"));
        keyField = new JTextField();
        addFormRow(formPanel, gbc, row++, keyLabel, keyField);

        keyFormatLabel = new JLabel(lang.getString("wizard.label.key_format"));
        keyFormatCombo = new JComboBox<>(new String[]{"base64", "hex", "plain"});
        addFormRow(formPanel, gbc, row++, keyFormatLabel, keyFormatCombo);
        payloadFormatLabel = new JLabel(lang.getString("wizard.label.payload_format"));
        payloadFormatCombo = new JComboBox<>(new String[]{"json", "raw"});
        payloadFormatCombo.addActionListener(e -> { updateEnvelopeVisibility(); updateSummary(); revalidate(); });
        addFormRow(formPanel, gbc, row++, payloadFormatLabel, payloadFormatCombo);
        cipherLabel = new JLabel(lang.getString("wizard.label.cipher_field"));
        cipherField = new JTextField("ciphertext_b64");
        addFormRow(formPanel, gbc, row++, cipherLabel, cipherField);
        ivLabel = new JLabel(lang.getString("wizard.label.iv_field"));
        ivField = new JTextField("iv_b64");
        addFormRow(formPanel, gbc, row++, ivLabel, ivField);
        ivLiteralLabel = new JLabel(lang.getString("wizard.label.iv_literal"));
        ivLiteralField = new JTextField();
        ivLiteralField.setToolTipText(lang.getString("wizard.tip.iv_literal"));
        addFormRow(formPanel, gbc, row++, ivLiteralLabel, ivLiteralField);
        ivFormatLabel = new JLabel(lang.getString("wizard.label.iv_format"));
        ivFormatCombo = new JComboBox<>(new String[]{"base64", "hex", "plain"});
        addFormRow(formPanel, gbc, row++, ivFormatLabel, ivFormatCombo);

        externalEndpointLabel = new JLabel(lang.getString("wizard.label.external_endpoint"));
        externalEndpointField = new JTextField();
        externalEndpointField.setToolTipText(lang.getString("wizard.tip.external_endpoint"));
        addFormRow(formPanel, gbc, row++, externalEndpointLabel, externalEndpointField);

        headerNameLabel = new JLabel(lang.getString("wizard.label.header_name"));
        headerNameField = new JTextField("X-Signature");
        addFormRow(formPanel, gbc, row++, headerNameLabel, headerNameField);

        fieldPathLabel = new JLabel(lang.getString("wizard.label.field_path"));
        fieldPathField = new JTextField("$.data.id");
        addFormRow(formPanel, gbc, row++, fieldPathLabel, fieldPathField);

        replacementValueLabel = new JLabel(lang.getString("wizard.label.replacement_value"));
        replacementValueField = new JTextField();
        addFormRow(formPanel, gbc, row++, replacementValueLabel, replacementValueField);

        JScrollPane formScroll = UIStyle.scroll(formPanel);
        formScroll.setMinimumSize(new Dimension(0, 0));

        JPanel summaryPanel = new JPanel(new BorderLayout());
        summaryPanel.setBackground(UIStyle.background());
        summaryPanel.setBorder(UIStyle.sectionBorder(lang.getString("wizard.section.summary")));
        summaryArea = new JTextArea();
        summaryArea.setEditable(false);
        summaryArea.setLineWrap(true);
        summaryArea.setWrapStyleWord(true);
        UIStyle.styleTextArea(summaryArea, false);
        summaryPanel.add(UIStyle.scroll(summaryArea), BorderLayout.CENTER);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, formScroll, summaryPanel);
        SplitPaneLayout.initialize(split, 0.65);
        summaryPanel.setMinimumSize(new Dimension(0, 100));
        panel.add(split, BorderLayout.CENTER);
        javax.swing.event.DocumentListener summaryListener = new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateSummary(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateSummary(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateSummary(); }
        };
        for (JTextField field : new JTextField[]{ruleNameField, hostField, pathField, methodsField, contentTypeField,
                keyField, cipherField, ivField, ivLiteralField, externalEndpointField, headerNameField,
                fieldPathField, replacementValueField}) field.getDocument().addDocumentListener(summaryListener);
        keyFormatCombo.addActionListener(e -> updateSummary());
        ivFormatCombo.addActionListener(e -> updateSummary());
        return panel;
    }

    private void addFormRow(JPanel panel, GridBagConstraints gbc, int row, String label, JComponent field) {
        addFormRow(panel, gbc, row, new JLabel(label), field);
    }

    private void addFormRow(JPanel panel, GridBagConstraints gbc, int row, JLabel label, JComponent field) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0.0;
        gbc.fill = GridBagConstraints.NONE;
        panel.add(label, gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(field, gbc);
    }

    private void applySourceRequestDefaults() {
        if (sourceRequest == null) {
            return;
        }
        if (!sourceRequest.method().isBlank()) {
            methodsField.setText(sourceRequest.method());
        }
        if (!sourceRequest.contentType().isBlank()) {
            contentTypeField.setText(sourceRequest.contentType());
        }
        if (!sourceRequest.signatureHeader().isBlank()) {
            headerNameField.setText(sourceRequest.signatureHeader());
        }
        selectScenario(sourceRequest.response()
                ? Scenario.DECRYPT_RESPONSE
                : (!sourceRequest.signatureHeader().isBlank() ? Scenario.REPEATER_AUTO_RESIGN : Scenario.EDIT_PLAINTEXT_REQUEST));
    }

    private void selectScenario(Scenario scenario) {
        ListModel<Scenario> model = scenarioList.getModel();
        for (int i = 0; i < model.getSize(); i++) {
            if (model.getElementAt(i) == scenario) {
                scenarioList.setSelectedIndex(i);
                return;
            }
        }
    }

    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        panel.setBackground(UIStyle.surface());
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UIStyle.border()),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
        ));

        JButton cancelButton = UIStyle.button(lang.getString("btn.cancel"));
        cancelButton.addActionListener(e -> dispose());

        JButton okButton = UIStyle.primaryButton(lang.getString("wizard.btn.generate"));
        okButton.setIcon(UIStyle.icon(UIStyle.IconType.WIZARD));
        okButton.addActionListener(e -> generateRule());

        panel.add(cancelButton);
        panel.add(okButton);
        return panel;
    }

    private void updateScenario() {
        Scenario scenario = scenarioList.getSelectedValue();
        if (scenario == null) {
            return;
        }

        if (ruleNameField.getText().trim().isEmpty() || ruleNameField.getText().startsWith(lang.getString("wizard.rule_name_prefix"))) {
            ruleNameField.setText(lang.getString("wizard.rule_name_prefix") + scenario.title(lang));
        }

        algorithmCombo.removeAllItems();
        for (String algorithm : scenario.algorithms()) {
            algorithmCombo.addItem(algorithm);
        }
        methodsField.setText(defaultMethodsFor(scenario));
        if (scenario == Scenario.SIGN_BODY
                && (fieldPathField.getText().trim().isEmpty() || fieldPathField.getText().trim().startsWith("$."))) {
            fieldPathField.setText("signature");
        } else if (scenario == Scenario.REPLACE_JSON_FIELD
                && (fieldPathField.getText().trim().isEmpty() || "signature".equals(fieldPathField.getText().trim()))) {
            fieldPathField.setText("$.data.id");
        }
        if (scenario.usesSignatureHeader() && headerNameField.getText().trim().isEmpty()) {
            headerNameField.setText("X-Signature");
        }

        setVisible(providerLabel, providerCombo, scenario.needsCryptoProvider());
        setVisible(algorithmLabel, algorithmCombo, scenario.needsAlgorithm());
        setVisible(keyLabel, keyField, scenario.needsKey());
        setVisible(externalEndpointLabel, externalEndpointField,
                scenario.needsCryptoProvider() && "external".equalsIgnoreCase(selectedProvider()));
        setVisible(contentTypeLabel, contentTypeField, true);
        setVisible(headerNameLabel, headerNameField, scenario.usesSignatureHeader());
        setVisible(fieldPathLabel, fieldPathField, scenario == Scenario.REPLACE_JSON_FIELD || scenario == Scenario.SIGN_BODY);
        setVisible(replacementValueLabel, replacementValueField, scenario == Scenario.REPLACE_JSON_FIELD);

        updateEnvelopeVisibility();
        updateSummary();
        revalidate();
        repaint();
    }

    private void updateEnvelopeVisibility() {
        Scenario scenario = thisScenario();
        if (scenario == null || keyFormatCombo == null || ivFormatCombo == null) return;
        boolean crypto = scenario == Scenario.EDIT_PLAINTEXT_REQUEST || scenario == Scenario.DECRYPT_RESPONSE
                || scenario == Scenario.EDIT_PLAINTEXT_RESPONSE || scenario == Scenario.ENCRYPT_REQUEST_ON_SEND;
        boolean internal = "internal".equalsIgnoreCase(selectedProvider());
        boolean symmetric = crypto && isSymmetricAlgorithm(String.valueOf(algorithmCombo.getSelectedItem()));
        setVisible(keyFormatLabel, keyFormatCombo, internal && symmetric);
        setVisible(payloadFormatLabel, payloadFormatCombo, crypto && (!internal || !symmetric));
        if (internal && symmetric && !"json".equals(payloadFormatCombo.getSelectedItem())) payloadFormatCombo.setSelectedItem("json");
        boolean json = "json".equals(payloadFormatCombo.getSelectedItem());
        setVisible(cipherLabel, cipherField, crypto && internal && json);
        boolean usesIv = internal && symmetric && !String.valueOf(algorithmCombo.getSelectedItem()).toUpperCase(Locale.ROOT).contains("ECB");
        setVisible(ivLabel, ivField, usesIv);
        setVisible(ivLiteralLabel, ivLiteralField, usesIv);
        setVisible(ivFormatLabel, ivFormatCombo, usesIv);
        setVisible(externalEndpointLabel, externalEndpointField, scenario.needsCryptoProvider() && !internal);
    }

    private static boolean isSymmetricAlgorithm(String algorithm) {
        String value = algorithm.toUpperCase(Locale.ROOT);
        return value.startsWith("AES") || value.startsWith("DES") || value.startsWith("3DES") || value.startsWith("SM4");
    }

    private String defaultMethodsFor(Scenario scenario) {
        if (sourceRequest != null && !sourceRequest.method().isBlank()) {
            return sourceRequest.method();
        }
        return scenario.defaultMethods();
    }

    private void setVisible(JLabel label, JComponent field, boolean visible) {
        label.setVisible(visible);
        field.setVisible(visible);
    }

    private void updateSummary() {
        Scenario scenario = scenarioList != null ? scenarioList.getSelectedValue() : null;
        if (scenario == null || summaryArea == null) {
            return;
        }

        StringBuilder summary = new StringBuilder();
        summary.append(scenario.description(lang)).append("\n\n");
        summary.append(lang.getString("wizard.summary.scope")).append("\n");
        summary.append("  Host: ").append(emptyToWildcard(hostField != null ? hostField.getText() : "")).append("\n");
        summary.append(lang.getString("form.wizard.summary.path")).append(emptyToWildcard(pathField != null ? pathField.getText() : "")).append("\n");
        summary.append(lang.getString("form.wizard.summary.methods")).append(emptyToAny(methodsField != null ? methodsField.getText() : "")).append("\n\n");
        if (sourceRequest != null) {
            summary.append(lang.getString("wizard.summary.from_request")).append("\n");
            summary.append("  URL: ").append(sourceRequest.displayUrl()).append("\n");
            if (!sourceRequest.contentType().isBlank()) {
                summary.append("  Content-Type: ").append(sourceRequest.contentType()).append("\n");
            }
            if (!sourceRequest.signatureHeader().isBlank()) {
                summary.append(lang.getString("form.wizard.summary.signature_header")).append(sourceRequest.signatureHeader()).append("\n");
            }
            summary.append('\n');
        }
        if (scenario.needsCryptoProvider()) {
            summary.append(lang.getString("wizard.summary.engine")).append("\n");
            summary.append("  ").append(lang.getString("wizard.summary.provider")).append(": ")
                    .append(providerCombo != null ? providerCombo.getSelectedItem() : lang.getString("wizard.provider.internal"))
                    .append("\n");
            summary.append(lang.getString("form.wizard.summary.algorithm")).append(algorithmCombo != null ? algorithmCombo.getSelectedItem() : "").append("\n");
            if (externalEndpointField != null && externalEndpointField.isVisible()) {
                summary.append(lang.getString("form.wizard.summary.endpoint")).append(emptyToAny(externalEndpointField.getText())).append("\n");
            }
            summary.append('\n');
        }
        summary.append(lang.getString("wizard.summary.generated")).append("\n");
        summary.append(scenario.generatedSummary(lang));
        summary.append("\n\n").append(lang.getString("wizard.summary.draft"));
        if (cipherField != null && cipherField.isVisible())
            summary.append("\n").append(lang.getString("wizard.label.cipher_field")).append(": ").append(cipherField.getText());
        if (ivField != null && ivField.isVisible())
            summary.append("\n").append(lang.getString("wizard.label.iv_field")).append(": ").append(ivField.getText());
        if (isSymmetricAlgorithm(String.valueOf(algorithmCombo.getSelectedItem())) && "internal".equalsIgnoreCase(selectedProvider()))
            summary.append("\n").append(lang.getString("wizard.summary.json_only"));
        summaryArea.setText(summary.toString());
        summaryArea.setCaretPosition(0);
    }

    private String emptyToWildcard(String value) {
        return value == null || value.trim().isEmpty() ? "*" : value.trim();
    }

    private String emptyToAny(String value) {
        return value == null || value.trim().isEmpty() ? "ANY" : value.trim();
    }

    private void generateRule() {
        Scenario scenario = scenarioList.getSelectedValue();
        if (scenario == null) {
            return;
        }

        if (hostField.getText().trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, lang.getString("validation.host_required"),
                    lang.getString("validation.title"), JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (scenario.needsKey() && keyField.getText().trim().isEmpty()
                && !algorithmDoesNotNeedKey(String.valueOf(algorithmCombo.getSelectedItem()))) {
            JOptionPane.showMessageDialog(this, lang.getString("wizard.validation.key_required"),
                    lang.getString("validation.title"), JOptionPane.ERROR_MESSAGE);
            return;
        }

        if ((scenario == Scenario.REPLACE_JSON_FIELD || scenario == Scenario.SIGN_BODY) && fieldPathField.getText().trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, lang.getString("wizard.validation.field_required"),
                    lang.getString("validation.title"), JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (scenario == Scenario.SIGN_BODY && !fieldPathField.getText().trim().matches("[A-Za-z_][A-Za-z0-9_-]*")) {
            JOptionPane.showMessageDialog(this, lang.getString("wizard.validation.signature_field"),
                    lang.getString("validation.title"), JOptionPane.ERROR_MESSAGE);
            return;
        }

        generatedRule = new ProcessingRule(UUID.randomUUID().toString());
        generatedRule.setName(ruleNameField.getText().trim().isEmpty()
                ? lang.getString("wizard.rule_name_prefix") + scenario.title(lang)
                : ruleNameField.getText().trim());
        generatedRule.setDescription(scenario.description(lang));
        generatedRule.setEnabled(false);
        generatedRule.setPriority(10);
        generatedRule.setShowInEditor(scenario == Scenario.EDIT_PLAINTEXT_REQUEST || scenario == Scenario.DECRYPT_RESPONSE || scenario == Scenario.EDIT_PLAINTEXT_RESPONSE);
        generatedRule.setCondition(createCondition());

        scenario.applyTo(generatedRule, this);

        confirmed = true;
        dispose();
    }

    private RuleCondition createCondition() {
        RuleCondition condition = new RuleCondition();
        condition.setHosts(Collections.singletonList(hostField.getText().trim()));

        String path = pathField.getText().trim();
        if (!path.isEmpty() && !"/*".equals(path) && !"*".equals(path)) {
            condition.setPaths(Collections.singletonList(path));
        }

        String methods = methodsField.getText().trim();
        if (!methods.isEmpty()) {
            condition.setMethods(Arrays.asList(methods.split("\\s*,\\s*")));
        }

        String contentType = contentTypeField.getText().trim();
        if (!contentType.isEmpty()) {
            condition.setContentType(contentType);
        }

        condition.setToolSource(Constants.ToolSource.ANY);
        return condition;
    }

    private ProcessingAction cryptoAction(String actionType, String phase) {
        ProcessingAction action = new ProcessingAction();
        action.setActionType(actionType);
        action.setTargetType(Constants.TargetType.BODY);
        action.setProcessor(Constants.ProcessorType.CRYPTO);
        action.setEnabled(true);
        action.setConfig(baseCryptoConfig(phase, actionType));
        return action;
    }

    private Map<String, Object> baseCryptoConfig(String phase, String actionType) {
        Map<String, Object> config = new HashMap<>();
        String algorithm = String.valueOf(algorithmCombo.getSelectedItem());
        String provider = selectedProvider();

        config.put(Constants.ConfigKey.ALGORITHM, algorithm);
        config.put(Constants.ConfigKey.CRYPTO_PROVIDER, provider);
        config.put(Constants.ConfigKey.EXECUTION_PHASE, phase);
        config.put(Constants.ConfigKey.PAYLOAD_FORMAT, String.valueOf(payloadFormatCombo.getSelectedItem()));
        config.put(Constants.ConfigKey.CIPHER_FIELD, cipherField.getText().trim());
        config.put(Constants.ConfigKey.PLAIN_FIELD, cipherField.getText().trim());
        config.put(Constants.ConfigKey.KEY_FORMAT, String.valueOf(keyFormatCombo.getSelectedItem()));
        config.put(Constants.ConfigKey.IV_FIELD, ivField.getText().trim());
        config.put(Constants.ConfigKey.IV_LITERAL_VALUE, ivLiteralField.getText().trim());
        config.put(Constants.ConfigKey.IV_FORMAT, String.valueOf(ivFormatCombo.getSelectedItem()));
        if (Constants.ExecutionPhase.EDITOR_SEND.equals(phase)) config.put(Constants.ConfigKey.EDITOR_ONLY, true);
        config.put(Constants.ConfigKey.CIPHER_FORMAT, "base64");
        config.put(Constants.ConfigKey.PLAIN_FORMAT, "plain");
        config.put(Constants.ConfigKey.CHARSET, "UTF-8");

        if (algorithmDoesNotNeedKey(algorithm) && "internal".equalsIgnoreCase(provider)) {
            config.put(Constants.ConfigKey.KEY_SOURCE, "none");
        } else {
            config.put(Constants.ConfigKey.KEY_SOURCE, Constants.KeySource.STATIC);
            config.put(Constants.ConfigKey.KEY_VALUE, keyField.getText().trim());
        }

        if ("external".equalsIgnoreCase(provider) && externalEndpointField != null
                && !externalEndpointField.getText().trim().isEmpty()) {
            if (Constants.ActionType.ENCRYPT.equalsIgnoreCase(actionType)) {
                config.put(Constants.ConfigKey.ENCRYPT_ENDPOINT, externalEndpointField.getText().trim());
                config.put(Constants.ConfigKey.ENCRYPT_METHOD, "POST");
            } else if (Constants.ActionType.DECRYPT.equalsIgnoreCase(actionType)) {
                config.put(Constants.ConfigKey.DECRYPT_ENDPOINT, externalEndpointField.getText().trim());
                config.put(Constants.ConfigKey.DECRYPT_METHOD, "POST");
            }
        }

        return config;
    }

    private ProcessingAction signAction(String signContent, boolean writeToBodyField) {
        ProcessingAction action = new ProcessingAction();
        action.setActionType(Constants.ActionType.SIGN);
        action.setTargetType(writeToBodyField ? Constants.TargetType.FIELD : Constants.TargetType.HEADER);
        action.setTargetName(writeToBodyField
                ? (fieldPathField.getText().trim().isEmpty() ? "signature" : fieldPathField.getText().trim())
                : (headerNameField.getText().trim().isEmpty() ? "X-Signature" : headerNameField.getText().trim()));
        action.setProcessor(Constants.ProcessorType.SIGNATURE);
        action.setEnabled(true);

        Map<String, Object> config = new HashMap<>();
        config.put(Constants.ConfigKey.ALGORITHM, String.valueOf(algorithmCombo.getSelectedItem()));
        config.put(Constants.ConfigKey.KEY_SOURCE, Constants.KeySource.STATIC);
        config.put(Constants.ConfigKey.KEY_VALUE, keyField.getText().trim());
        config.put(Constants.ConfigKey.CRYPTO_PROVIDER, selectedProvider());
        config.put(Constants.ConfigKey.SIGN_CONTENT, signContent);
        config.put(Constants.ConfigKey.INPUT_SOURCE, Constants.InputSource.REQUEST_BODY);
        config.put(Constants.ConfigKey.EXECUTION_PHASE, Constants.ExecutionPhase.SEND);
        config.put(Constants.ConfigKey.CIPHER_FORMAT, "hex");
        config.put(Constants.ConfigKey.SIGNATURE_HEX_CASE, "lower");
        if ("custom".equalsIgnoreCase(signContent)) {
            config.put(Constants.ConfigKey.CUSTOM_SIGN_TEMPLATE, signatureTemplateForScenario());
        }
        if (thisScenario() == Scenario.SIGN_QUERY) {
            config.put(Constants.ConfigKey.SORT_KEYS, true);
            config.put(Constants.ConfigKey.PAIR_SEPARATOR, "&");
            config.put(Constants.ConfigKey.KV_SEPARATOR, "=");
            config.put(Constants.ConfigKey.URL_ENCODE_VALUES, false);
        }
        if ("external".equalsIgnoreCase(selectedProvider())
                && externalEndpointField != null && !externalEndpointField.getText().trim().isEmpty()) {
            config.put(Constants.ConfigKey.SIGN_ENDPOINT, externalEndpointField.getText().trim());
            config.put(Constants.ConfigKey.SIGN_METHOD, "POST");
        }
        action.setConfig(config);
        return action;
    }

    private Scenario thisScenario() {
        return scenarioList != null ? scenarioList.getSelectedValue() : null;
    }

    private boolean algorithmDoesNotNeedKey(String algorithm) {
        if (algorithm == null) {
            return false;
        }
        String normalized = algorithm.trim().toLowerCase(java.util.Locale.ROOT);
        return switch (normalized) {
            case "base64", "base64-encode", "base64-decode",
                    "hex", "hex-encode", "hex-decode",
                    "url", "url-encode", "url-decode", "urlencode", "urldecode",
                    "md5", "sha1", "sha-1", "sha256", "sha-256", "sha512", "sha-512", "sm3" -> true;
            default -> false;
        };
    }

    private String selectedProvider() {
        return rawOption(providerCombo != null ? String.valueOf(providerCombo.getSelectedItem()) : "internal");
    }

    private String rawOption(String label) {
        if (label == null) return "";
        switch (label.trim()) {
            case "本地计算": return "internal";
            case "调用外部服务": return "external";
            default:
        }
        int start = label.lastIndexOf('(');
        int end = label.lastIndexOf(')');
        if (start >= 0 && end > start) {
            return label.substring(start + 1, end).trim();
        }
        return label.trim();
    }

    private String signatureTemplateForScenario() {
        Scenario scenario = thisScenario();
        if (scenario == Scenario.REPEATER_AUTO_RESIGN) {
            return "${method}${path}?${query}${body}";
        }
        if (scenario == Scenario.SIGN_QUERY) {
            return "${query}";
        }
        return "${method}${path}${body}";
    }

    private ProcessingAction removeOldSignatureAction() {
        ProcessingAction action = new ProcessingAction(Constants.ActionType.REMOVE, Constants.TargetType.FIELD, Constants.ProcessorType.FIELD);
        action.setTargetName(fieldPathField.getText().trim());
        action.setConfig(Constants.ConfigKey.OPERATION, Constants.ActionType.REMOVE);
        action.setConfig(Constants.ConfigKey.FIELD_PATH, "$." + fieldPathField.getText().trim());
        action.setConfig(Constants.ConfigKey.IGNORE_NOT_FOUND, true);
        action.setConfig(Constants.ConfigKey.EXECUTION_PHASE, Constants.ExecutionPhase.SEND);
        return action;
    }

    private ProcessingAction replaceFieldAction() {
        ProcessingAction action = new ProcessingAction();
        action.setActionType(Constants.ActionType.REPLACE);
        action.setTargetType(Constants.TargetType.FIELD);
        action.setTargetName(fieldPathField.getText().trim());
        action.setProcessor(Constants.ProcessorType.FIELD);
        action.setEnabled(true);

        Map<String, Object> config = new HashMap<>();
        config.put(Constants.ConfigKey.OPERATION, Constants.ActionType.REPLACE);
        config.put(Constants.ConfigKey.FIELD_PATH, fieldPathField.getText().trim());
        config.put(Constants.ConfigKey.TO, replacementValueField.getText());
        config.put(Constants.ConfigKey.EXECUTION_PHASE, Constants.ExecutionPhase.SEND);
        action.setConfig(config);
        return action;
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public ProcessingRule getRule() {
        return generatedRule;
    }

    public static SourceRequest sourceRequest(String method, String url, Map<String, String> headers, boolean response) {
        String host = "";
        String path = "/*";
        String displayUrl = url != null ? url : "";
        try {
            java.net.URL parsed = url != null ? new java.net.URL(url) : null;
            if (parsed != null) {
                host = parsed.getHost() != null ? parsed.getHost() : "";
                path = parsed.getPath() != null && !parsed.getPath().isBlank() ? parsed.getPath() : "/";
            }
        } catch (Exception ignored) {
            // Keep user-editable defaults when URL parsing fails.
        }
        Map<String, String> safeHeaders = headers != null ? new LinkedHashMap<>(headers) : Collections.emptyMap();
        return new SourceRequest(
                method != null ? method.trim().toUpperCase(Locale.ROOT) : "",
                host,
                path,
                displayUrl,
                headerIgnoreCase(safeHeaders, "Content-Type"),
                inferSignatureHeader(safeHeaders),
                response
        );
    }

    private static String headerIgnoreCase(Map<String, String> headers, String name) {
        if (headers == null || name == null) {
            return "";
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (name.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue() != null ? entry.getValue() : "";
            }
        }
        return "";
    }

    private static String inferSignatureHeader(Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) {
            return "";
        }
        String[] preferred = {"Sign", "Signature", "X-Signature", "X-Api-Signature"};
        for (String name : preferred) {
            String actual = findHeaderName(headers, name);
            if (actual != null) {
                return actual;
            }
        }
        for (String name : headers.keySet()) {
            String lower = name.toLowerCase(Locale.ROOT);
            if (lower.contains("sign") || lower.contains("signature")) {
                return name;
            }
        }
        return "";
    }

    private static String findHeaderName(Map<String, String> headers, String expected) {
        for (String name : headers.keySet()) {
            if (expected.equalsIgnoreCase(name)) {
                return name;
            }
        }
        return null;
    }

    public record SourceRequest(
            String method,
            String host,
            String path,
            String displayUrl,
            String contentType,
            String signatureHeader,
            boolean response
    ) {
        public SourceRequest {
            method = method != null ? method : "";
            host = host != null ? host : "";
            path = path != null && !path.isBlank() ? path : "/*";
            displayUrl = displayUrl != null ? displayUrl : "";
            contentType = contentType != null ? contentType : "";
            signatureHeader = signatureHeader != null ? signatureHeader : "";
        }
    }

    private enum Scenario {
        EDIT_PLAINTEXT_REQUEST("wizard.scenario.edit_plain", "wizard.scenario.edit_plain.desc") {
            @Override
            void applyTo(ProcessingRule rule, QuickRuleWizardDialog dialog) {
                rule.addRequestAction(dialog.cryptoAction(Constants.ActionType.DECRYPT, Constants.ExecutionPhase.DISPLAY));
                rule.addRequestAction(dialog.cryptoAction(Constants.ActionType.ENCRYPT, Constants.ExecutionPhase.EDITOR_SEND));
            }

            @Override
            String generatedSummary(LanguageManager lang) {
                return lang.getString("wizard.summary.edit_plain");
            }
        },
        DECRYPT_RESPONSE("wizard.scenario.decrypt_response", "wizard.scenario.decrypt_response.desc") {
            @Override
            void applyTo(ProcessingRule rule, QuickRuleWizardDialog dialog) {
                rule.addResponseAction(dialog.cryptoAction(Constants.ActionType.DECRYPT, Constants.ExecutionPhase.RESPONSE_DISPLAY));
            }

            @Override
            String generatedSummary(LanguageManager lang) {
                return lang.getString("wizard.summary.decrypt_response");
            }
        },
        EDIT_PLAINTEXT_RESPONSE("wizard.scenario.edit_response", "wizard.scenario.edit_response.desc") {
            @Override void applyTo(ProcessingRule rule, QuickRuleWizardDialog dialog) {
                rule.addResponseAction(dialog.cryptoAction(Constants.ActionType.DECRYPT, Constants.ExecutionPhase.RESPONSE_DISPLAY));
                rule.addResponseAction(dialog.cryptoAction(Constants.ActionType.ENCRYPT, Constants.ExecutionPhase.RESPONSE_EDITOR_SEND));
            }
            @Override String generatedSummary(LanguageManager lang) { return lang.getString("wizard.summary.edit_response"); }
        },
        ENCRYPT_REQUEST_ON_SEND("wizard.scenario.encrypt_request", "wizard.scenario.encrypt_request.desc") {
            @Override
            void applyTo(ProcessingRule rule, QuickRuleWizardDialog dialog) {
                rule.addRequestAction(dialog.cryptoAction(Constants.ActionType.ENCRYPT, Constants.ExecutionPhase.SEND));
            }

            @Override
            String generatedSummary(LanguageManager lang) {
                return lang.getString("wizard.summary.encrypt_request");
            }
        },
        REPEATER_AUTO_RESIGN("wizard.scenario.repeater_resign", "wizard.scenario.repeater_resign.desc") {
            @Override
            void applyTo(ProcessingRule rule, QuickRuleWizardDialog dialog) {
                RuleCondition condition = rule.getCondition();
                if (condition != null) {
                    condition.setToolSource(Constants.ToolSource.REPEATER);
                }
                rule.addRequestAction(dialog.signAction("custom", false));
            }

            @Override
            String generatedSummary(LanguageManager lang) {
                return lang.getString("wizard.summary.repeater_resign");
            }
        },
        SIGN_HEADER("wizard.scenario.sign_header", "wizard.scenario.sign_header.desc") {
            @Override
            void applyTo(ProcessingRule rule, QuickRuleWizardDialog dialog) {
                rule.addRequestAction(dialog.signAction("method+path+body", false));
            }

            @Override
            String generatedSummary(LanguageManager lang) {
                return lang.getString("wizard.summary.sign_header");
            }
        },
        SIGN_BODY("wizard.scenario.sign_body", "wizard.scenario.sign_body.desc") {
            @Override
            void applyTo(ProcessingRule rule, QuickRuleWizardDialog dialog) {
                rule.addRequestAction(dialog.removeOldSignatureAction());
                rule.addRequestAction(dialog.signAction("body", true));
            }

            @Override
            String generatedSummary(LanguageManager lang) {
                return lang.getString("wizard.summary.sign_body");
            }
        },
        SIGN_QUERY("wizard.scenario.sign_query", "wizard.scenario.sign_query.desc") {
            @Override
            void applyTo(ProcessingRule rule, QuickRuleWizardDialog dialog) {
                rule.addRequestAction(dialog.signAction("custom", false));
            }

            @Override
            String generatedSummary(LanguageManager lang) {
                return lang.getString("wizard.summary.sign_query");
            }
        },
        REPLACE_JSON_FIELD("wizard.scenario.replace_field", "wizard.scenario.replace_field.desc") {
            @Override
            void applyTo(ProcessingRule rule, QuickRuleWizardDialog dialog) {
                rule.addRequestAction(dialog.replaceFieldAction());
            }

            @Override
            String generatedSummary(LanguageManager lang) {
                return lang.getString("wizard.summary.replace_field");
            }
        };

        private final String titleKey;
        private final String descriptionKey;

        Scenario(String titleKey, String descriptionKey) {
            this.titleKey = titleKey;
            this.descriptionKey = descriptionKey;
        }

        String title(LanguageManager lang) {
            return lang.getString(titleKey);
        }

        String description(LanguageManager lang) {
            return lang.getString(descriptionKey);
        }

        boolean needsCryptoProvider() {
            return this != REPLACE_JSON_FIELD;
        }

        boolean needsAlgorithm() {
            return this != REPLACE_JSON_FIELD;
        }

        boolean needsKey() {
            return this != REPLACE_JSON_FIELD;
        }

        boolean usesSignatureHeader() {
            return this == REPEATER_AUTO_RESIGN || this == SIGN_HEADER || this == SIGN_QUERY;
        }

        String defaultMethods() {
            return switch (this) {
                case DECRYPT_RESPONSE, EDIT_PLAINTEXT_RESPONSE -> "GET, POST";
                case REPEATER_AUTO_RESIGN -> "GET, POST, PUT, DELETE, PATCH";
                case SIGN_QUERY -> "GET";
                default -> "POST";
            };
        }

        String[] algorithms() {
            if (this == REPEATER_AUTO_RESIGN || this == SIGN_HEADER || this == SIGN_BODY || this == SIGN_QUERY) {
                return new String[]{"HMAC-SHA256", "HMAC-SHA1", "HMAC-SHA512", "SHA256withRSA"};
            }
            if (this == REPLACE_JSON_FIELD) {
                return new String[]{""};
            }
            if (this == EDIT_PLAINTEXT_REQUEST || this == EDIT_PLAINTEXT_RESPONSE)
                return new String[]{"AES-GCM", "AES-CBC", "AES-ECB", "DES-CBC", "3DES-CBC", "SM4-CBC", "Base64", "Hex", "URL"};
            return new String[]{"AES-GCM", "AES-CBC", "AES-ECB", "DES-CBC", "3DES-CBC", "SM4-CBC", "RSA-OAEP", "SM2", "Base64", "Hex", "URL"};
        }

        abstract void applyTo(ProcessingRule rule, QuickRuleWizardDialog dialog);

        abstract String generatedSummary(LanguageManager lang);

        @Override
        public String toString() {
            return name();
        }
    }

    private final class ScenarioRenderer extends JPanel implements ListCellRenderer<Scenario> {
        private final JLabel title = new JLabel();
        private final JTextArea description = new JTextArea();

        private ScenarioRenderer() {
            setLayout(new BorderLayout(0, 3));
            setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
            title.setFont(title.getFont().deriveFont(Font.BOLD, 12f));
            description.setEditable(false);
            description.setLineWrap(true);
            description.setWrapStyleWord(true);
            description.setOpaque(false);
            description.setFont(description.getFont().deriveFont(11f));
            add(title, BorderLayout.NORTH);
            add(description, BorderLayout.CENTER);
        }

        @Override
        public Component getListCellRendererComponent(JList<? extends Scenario> list, Scenario value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            title.setText(value.title(lang));
            description.setText(value.description(lang));

            Color bg = isSelected ? list.getSelectionBackground() : UIStyle.surface();
            Color fg = isSelected ? list.getSelectionForeground() : UIStyle.text();
            setBackground(bg);
            title.setForeground(fg);
            description.setForeground(isSelected ? fg : UIStyle.mutedText());
            return this;
        }
    }
}
