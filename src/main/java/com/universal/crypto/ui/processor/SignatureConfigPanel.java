package com.universal.crypto.ui.processor;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.universal.crypto.ui.CollapsibleSection;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;

import com.universal.crypto.util.LanguageManager;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class SignatureConfigPanel implements ProcessorConfigUI {

    private final LanguageManager lang = LanguageManager.getInstance();
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final String[] KEY_SOURCES = {
            lang.getString("form.option.static"),
            lang.getString("form.option.lookup"),
            lang.getString("form.option.cached"),
            lang.getString("form.option.none")
    };
    private final String[] PROVIDERS = {
            lang.getString("form.option.internal"),
            lang.getString("form.option.external")
    };
    private static final String[] FORMAT_OPTIONS = {"base64", "plain", "hex"};
    private final String[] HASH_KEY_PLACEMENT_OPTIONS = {
            lang.getString("form.option.suffix"),
            lang.getString("form.option.no_concat"),
            lang.getString("form.option.prefix"),
            lang.getString("form.option.both")
    };
    private static final String[] HEX_CASE_OPTIONS = {"lower", "upper"};
    private final String[] VERIFICATION_SOURCES = {
            lang.getString("form.option.header"),
            lang.getString("form.option.body"),
            lang.getString("form.option.query"),
            lang.getString("form.option.fixed_sig")
    };
    private static final String[] ALGORITHM_OPTIONS = {
        "MD5", "SHA-1", "SHA-256", "SHA-512", "SM3",
        "HmacSHA256", "HmacSHA1", "HmacSM3",
        "SHA1withRSA", "SHA256withRSA", "SHA512withRSA", "MD5withRSA"
    };
    private CollapsibleSection canonicalSection;
    private final JPanel mainPanel;
    private final JTextArea tipsArea;
    
    // Core Config
    private JComboBox<String> protocolPresetCombo;
    private JTextArea protocolGuideArea;
    private JComboBox<String> conceptGuideCombo;
    private JTextArea conceptGuideArea;
    private JComboBox<String> algorithmCombo;
    private JComboBox<String> providerCombo;
    private JComboBox<String> keySourceCombo;
    private JTextArea keyValueField;
    
    // Lookup Config
    private JTextField lookupEndpointField;
    private JTextField lookupMethodField;
    private JTextField responseKeyPathField;
    private JCheckBox fallbackLookupCheck;

    // Formats
    private JComboBox<String> cipherFormatCombo;
    private JComboBox<String> hashKeyPlacementCombo;
    private JComboBox<String> hexCaseCombo;
    private JPanel formatRow;

    // Canonicalization
    private JCheckBox sortKeysCheck;
    private JCheckBox urlEncodeCheck;
    private JTextField pairSeparatorField;
    private JTextField kvSeparatorField;

    // Template Builder
    private JTextArea customSignTemplateArea;
    private JTextArea headerTemplatesArea;
    private JPanel templateBuilderPanel;
    private JPanel lookupPanel;
    private JPanel externalServicePanel;
    private JPanel verificationPanel;
    private JTextField signEndpointField;
    private JTextField signMethodField;
    private JTextField verifyEndpointField;
    private JTextField verifyMethodField;
    private JComboBox<String> verificationSourceCombo;
    private JTextField signatureHeaderField;
    private JTextField signatureFieldPathField;
    private JTextField signatureQueryParamField;
    private JTextField expectedSignatureField;
    private String currentActionType = Constants.ActionType.SIGN;
    private String loadedSignContent;
    private String loadedTemplateDisplay;
    private Object loadedTemplateConfig;
    private boolean loadingConfig;
    private boolean autoKeyless;
    private String previousKeySource = "static";

    private final Map<JComponent, Component> fieldLabels = new HashMap<>();

    public SignatureConfigPanel() {
        mainPanel = ProcessorUIStyle.formPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBackground(ProcessorUIStyle.background());
        mainPanel.setBorder(ProcessorUIStyle.pageBorder());

        tipsArea = ProcessorUIStyle.note(lang.getString("sign.tips"));
        tipsArea.setAlignmentX(Component.LEFT_ALIGNMENT);
        mainPanel.add(tipsArea);
        mainPanel.add(Box.createVerticalStrut(12));

        JPanel presetPanel = createProtocolPresetPanel();
        presetPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JPanel helpContent = new JPanel();
        helpContent.setLayout(new BoxLayout(helpContent, BoxLayout.Y_AXIS));
        helpContent.setOpaque(false);
        helpContent.add(presetPanel);

        JPanel conceptPanel = createConceptGuidePanel();
        conceptPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        helpContent.add(conceptPanel);
        CollapsibleSection helpSection = new CollapsibleSection(lang.getString("sign.group.guide"), helpContent);

        // Group: Core Signature
        JPanel corePanel = createGroupPanel(lang.getString("sign.group.algo"));
        corePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints gbc = createGbc();
        int row = 0;

        algorithmCombo = new JComboBox<>(ALGORITHM_OPTIONS);
        algorithmCombo.setEditable(true);
        algorithmCombo.setToolTipText(lang.getString("form.hint.sign_algo"));
        algorithmCombo.addActionListener(e -> updateVisibility());
        addLabelAndField(corePanel, lang.getString("sign.label.algo"), algorithmCombo, gbc, row++);

        providerCombo = new JComboBox<>(PROVIDERS);
        providerCombo.setToolTipText(lang.getString("form.hint.sign_provider"));
        providerCombo.addActionListener(e -> updateVisibility());
        addLabelAndField(corePanel, lang.getString("form.label.provider"), providerCombo, gbc, row++);

        keySourceCombo = new JComboBox<>(KEY_SOURCES);
        keySourceCombo.setToolTipText(lang.getString("form.hint.sign_key_source"));
        keySourceCombo.addActionListener(e -> updateVisibility());
        addLabelAndField(corePanel, lang.getString("sign.label.key_source"), keySourceCombo, gbc, row++);

        keyValueField = new JTextArea(3, 20); // 3 rows default
        keyValueField.setLineWrap(true);
        keyValueField.setToolTipText(lang.getString("form.hint.sign_key"));
        ProcessorUIStyle.styleTextArea(keyValueField, false);
        JScrollPane keyScroll = new JScrollPane(keyValueField);
        addLabelAndField(corePanel, lang.getString("sign.label.key_value"), keyScroll, gbc, row++);
        
        // Formats Row (Signature usually only output format matters)
        formatRow = new JPanel(new BorderLayout());
        formatRow.setMinimumSize(new Dimension(0, 0));
        cipherFormatCombo = new JComboBox<>(FORMAT_OPTIONS);
        cipherFormatCombo.setToolTipText(lang.getString("form.hint.output"));
        formatRow.add(cipherFormatCombo, BorderLayout.CENTER);
        
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0.0;
        JLabel formatLabel = new JLabel(lang.getString("sign.output.formats"));
        corePanel.add(formatLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        corePanel.add(formatRow, gbc);
        fieldLabels.put(formatRow, formatLabel);
        row++;

        hashKeyPlacementCombo = new JComboBox<>(HASH_KEY_PLACEMENT_OPTIONS);
        hashKeyPlacementCombo.setToolTipText(lang.getString("form.hint.placement"));
        hashKeyPlacementCombo.addActionListener(e -> updateVisibility());
        addLabelAndField(corePanel, lang.getString("sign.label.hash_key_placement"), hashKeyPlacementCombo, gbc, row++);

        hexCaseCombo = new JComboBox<>(HEX_CASE_OPTIONS);
        hexCaseCombo.setToolTipText(lang.getString("form.hint.hex"));
        addLabelAndField(corePanel, lang.getString("sign.label.hex_case"), hexCaseCombo, gbc, row++);
        
        mainPanel.add(corePanel);
        mainPanel.add(Box.createVerticalStrut(12));

        // Group: Key Lookup
        lookupPanel = createGroupPanel(lang.getString("sign.group.lookup"));
        lookupPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        row = 0;
        
        lookupEndpointField = new JTextField();
        addLabelAndField(lookupPanel, lang.getString("sign.label.lookup_endpoint"), lookupEndpointField, gbc, row++);

        lookupMethodField = new JTextField("POST");
        addLabelAndField(lookupPanel, lang.getString("sign.label.lookup_method"), lookupMethodField, gbc, row++);

        responseKeyPathField = new JTextField("key");
        addLabelAndField(lookupPanel, lang.getString("sign.label.lookup_path"), responseKeyPathField, gbc, row++);

        fallbackLookupCheck = new JCheckBox(lang.getString("sign.check.fallback"));
        addLabelAndField(lookupPanel, "", fallbackLookupCheck, gbc, row++);
        
        mainPanel.add(lookupPanel);

        externalServicePanel = createGroupPanel(lang.getString("form.sign.external"));
        externalServicePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        row = 0;

        signEndpointField = new JTextField();
        signEndpointField.setToolTipText(lang.getString("form.hint.sign_endpoint"));
        addLabelAndField(externalServicePanel, lang.getString("form.label.sign_endpoint"), signEndpointField, gbc, row++);

        signMethodField = new JTextField("POST");
        addLabelAndField(externalServicePanel, lang.getString("form.label.sign_method"), signMethodField, gbc, row++);

        verifyEndpointField = new JTextField();
        verifyEndpointField.setToolTipText(lang.getString("form.hint.verify_endpoint"));
        addLabelAndField(externalServicePanel, lang.getString("form.label.verify_endpoint"), verifyEndpointField, gbc, row++);

        verifyMethodField = new JTextField("POST");
        addLabelAndField(externalServicePanel, lang.getString("form.label.verify_method"), verifyMethodField, gbc, row++);

        mainPanel.add(externalServicePanel);

        verificationPanel = createGroupPanel(lang.getString("form.sign.verify"));
        verificationPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        row = 0;

        verificationSourceCombo = new JComboBox<>(VERIFICATION_SOURCES);
        verificationSourceCombo.setToolTipText(lang.getString("form.hint.verify_source"));
        verificationSourceCombo.addActionListener(e -> updateVisibility());
        addLabelAndField(verificationPanel, lang.getString("form.label.verify_source"), verificationSourceCombo, gbc, row++);

        signatureHeaderField = new JTextField("X-Signature");
        addLabelAndField(verificationPanel, lang.getString("form.label.verify_header"), signatureHeaderField, gbc, row++);

        signatureFieldPathField = new JTextField("$.signature");
        signatureFieldPathField.setToolTipText(lang.getString("form.hint.json_path"));
        addLabelAndField(verificationPanel, lang.getString("form.label.verify_body"), signatureFieldPathField, gbc, row++);

        signatureQueryParamField = new JTextField("sign");
        addLabelAndField(verificationPanel, lang.getString("form.label.verify_query"), signatureQueryParamField, gbc, row++);

        expectedSignatureField = new JTextField();
        expectedSignatureField.setToolTipText(lang.getString("form.hint.fixed_sig"));
        addLabelAndField(verificationPanel, lang.getString("form.label.fixed_sig"), expectedSignatureField, gbc, row++);

        mainPanel.add(verificationPanel);

        // Group: Canonicalization
        JPanel canonPanel = createGroupPanel(lang.getString("sign.group.canon"));
        canonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        row = 0;
        
        sortKeysCheck = new JCheckBox(lang.getString("sign.check.sort"));
        addLabelAndField(canonPanel, lang.getString("sign.group.canon") + ":", sortKeysCheck, gbc, row++);
        
        urlEncodeCheck = new JCheckBox(lang.getString("sign.check.url_encode"));
        addLabelAndField(canonPanel, "", urlEncodeCheck, gbc, row++);
        
        pairSeparatorField = new JTextField("&");
        addLabelAndField(canonPanel, lang.getString("sign.label.pair_sep"), pairSeparatorField, gbc, row++);
        
        kvSeparatorField = new JTextField("=");
        addLabelAndField(canonPanel, lang.getString("sign.label.kv_sep"), kvSeparatorField, gbc, row++);
        
        canonicalSection = new CollapsibleSection(lang.getString("form.advanced"), canonPanel);

        // Group: Template Builder
        JPanel templatePanel = createGroupPanel(lang.getString("sign.group.template"));
        templatePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        row = 0;
        
        customSignTemplateArea = new JTextArea(3, 20);
        customSignTemplateArea.setLineWrap(true);
        customSignTemplateArea.setToolTipText(lang.getString("form.hint.template"));
        ProcessorUIStyle.styleTextArea(customSignTemplateArea, true);
        JScrollPane templateScroll = new JScrollPane(customSignTemplateArea);
        addLabelAndField(templatePanel, lang.getString("sign.label.custom_template"), templateScroll, gbc, row++);

        headerTemplatesArea = new JTextArea(3, 20);
        headerTemplatesArea.setLineWrap(true);
        headerTemplatesArea.setToolTipText(lang.getString("form.hint.header_templates"));
        ProcessorUIStyle.styleTextArea(headerTemplatesArea, true);
        JScrollPane headerTemplatesScroll = new JScrollPane(headerTemplatesArea);
        addLabelAndField(templatePanel, lang.getString("sign.label.header_templates"), headerTemplatesScroll, gbc, row++);

        // Presets
        JPanel presetsPanel = new JPanel(new BorderLayout());
        presetsPanel.setMinimumSize(new Dimension(0, 0));
        JComboBox<String> presetsCombo = new JComboBox<>(new String[]{
            lang.getString("form.sign.insert.choose"),
            lang.getString("form.sign.insert.body"),
            lang.getString("form.sign.insert.timestamp"),
            lang.getString("form.sign.insert.method"),
            lang.getString("form.sign.insert.hmac"),
            lang.getString("form.sign.insert.sorted"),
            lang.getString("form.sign.stable_preset"),
            lang.getString("form.sign.insert.uuid")
        });
        presetsCombo.addActionListener(e -> {
            String sel = (String) presetsCombo.getSelectedItem();
            if (sel != null && !sel.startsWith("---")) {
                String template = sel.substring(sel.indexOf(":") + 1).trim();
                if (template.startsWith("{")) {
                    headerTemplatesArea.setText(template);
                } else {
                    customSignTemplateArea.setText(template);
                }
            }
        });
        presetsCombo.setMinimumSize(new Dimension(0, presetsCombo.getPreferredSize().height));
        presetsPanel.add(presetsCombo, BorderLayout.CENTER);
        
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0.0;
        JLabel presetLabel = new JLabel(lang.getString("sign.label.presets"));
        templatePanel.add(presetLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        templatePanel.add(presetsPanel, gbc);
        fieldLabels.put(presetsPanel, presetLabel);
        row++;
        
        templateBuilderPanel = new JPanel(new GridLayout(0, 4, 4, 4));
        templateBuilderPanel.setMinimumSize(new Dimension(0, 0));
        JButton btnMethod = new JButton(lang.getString("form.sign.insert.method_button")); btnMethod.addActionListener(e -> insertTemplateVar("${method}"));
        JButton btnPath = new JButton(lang.getString("form.sign.insert.path_button")); btnPath.addActionListener(e -> insertTemplateVar("${path}"));
        JButton btnBody = new JButton(lang.getString("form.sign.insert.body_button")); btnBody.addActionListener(e -> insertTemplateVar("${body}"));
        JButton btnTime = new JButton(lang.getString("form.sign.insert.time_button")); btnTime.addActionListener(e -> insertTemplateVar("${timestamp}"));
        JButton btnJson = new JButton(lang.getString("form.sign.insert.json")); btnJson.addActionListener(e -> insertJsonVar());
        JButton btnHeader = new JButton(lang.getString("form.sign.insert.header_button")); btnHeader.addActionListener(e -> insertHeaderVar());
        JButton btnCanon = new JButton(lang.getString("form.sign.insert.canon_button")); btnCanon.addActionListener(e -> insertCanonVar());
        
        // Small buttons
        for (Component c : new Component[]{btnMethod, btnPath, btnBody, btnTime, btnJson, btnHeader, btnCanon}) {
            c.setFont(c.getFont().deriveFont(11f));
            if (c instanceof AbstractButton) {
                ProcessorUIStyle.styleButton((AbstractButton) c);
            }
            templateBuilderPanel.add(c);
        }
        
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0.0;
        JLabel builderLabel = new JLabel(lang.getString("sign.label.helper"));
        templatePanel.add(builderLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        templatePanel.add(templateBuilderPanel, gbc);
        fieldLabels.put(templateBuilderPanel, builderLabel);
        
        mainPanel.add(templatePanel);
        mainPanel.add(canonicalSection);
        mainPanel.add(helpSection);
        
        // Glue
        mainPanel.add(Box.createVerticalGlue());
    }

    private JPanel createGroupPanel(String title) {
        return ProcessorUIStyle.section(title);
    }

    private JPanel createProtocolPresetPanel() {
        JPanel panel = createGroupPanel(lang.getString("form.sign.protocol"));
        GridBagConstraints gbc = createGbc();

        protocolPresetCombo = new JComboBox<>(new String[]{
                lang.getString("form.sign.custom"),
                lang.getString("form.sign.hmac"),
                lang.getString("form.sign.hash")
        });

        JButton applyButton = new JButton(lang.getString("form.sign.apply"));
        ProcessorUIStyle.styleButton(applyButton);
        applyButton.addActionListener(e -> applySelectedProtocolPreset());

        JPanel rowPanel = new JPanel(new BorderLayout(8, 0));
        rowPanel.setOpaque(false);
        rowPanel.add(protocolPresetCombo, BorderLayout.CENTER);
        rowPanel.add(applyButton, BorderLayout.EAST);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0.0;
        JLabel presetLabel = new JLabel(lang.getString("form.sign.protocol_label"));
        presetLabel.setForeground(ProcessorUIStyle.text());
        panel.add(presetLabel, gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(rowPanel, gbc);

        protocolGuideArea = ProcessorUIStyle.note(lang.getString("form.sign.guide.protocol"));
        protocolGuideArea.setRows(4);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        panel.add(protocolGuideArea, gbc);

        return panel;
    }

    private JPanel createConceptGuidePanel() {
        JPanel panel = createGroupPanel(lang.getString("form.sign.examples"));
        GridBagConstraints gbc = createGbc();

        conceptGuideCombo = new JComboBox<>(new String[]{
                lang.getString("form.sign.topic.formula"),
                lang.getString("form.sign.topic.keys"),
                lang.getString("form.sign.topic.template"),
                lang.getString("form.sign.topic.headers"),
                lang.getString("form.sign.topic.canon"),
                lang.getString("form.sign.topic.payload")
        });
        conceptGuideCombo.addActionListener(e -> updateConceptGuide());

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0.0;
        JLabel topicLabel = new JLabel(lang.getString("form.sign.topic"));
        topicLabel.setForeground(ProcessorUIStyle.text());
        panel.add(topicLabel, gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(conceptGuideCombo, gbc);

        conceptGuideArea = ProcessorUIStyle.note("");
        conceptGuideArea.setRows(8);
        conceptGuideArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        panel.add(conceptGuideArea, gbc);

        updateConceptGuide();
        return panel;
    }

    private void updateConceptGuide() {
        if (conceptGuideArea == null || conceptGuideCombo == null) {
            return;
        }
        int topic = conceptGuideCombo.getSelectedIndex();

        if (topic == 1) {
            conceptGuideArea.setText(lang.getString("form.sign.guide.keys"));
            return;
        }

        if (topic == 2) {
            conceptGuideArea.setText(lang.getString("form.sign.guide.variables"));
            return;
        }

        if (topic == 3) {
            conceptGuideArea.setText(lang.getString("form.sign.guide.headers"));
            return;
        }

        if (topic == 4) {
            conceptGuideArea.setText(lang.getString("form.sign.guide.canon"));
            return;
        }

        if (topic == 5) {
            conceptGuideArea.setText(lang.getString("form.sign.guide.payload"));
            return;
        }

        conceptGuideArea.setText(lang.getString("form.sign.guide.formula"));
    }

    private void applySelectedProtocolPreset() {
        switch (protocolPresetCombo.getSelectedIndex()) {
            case 1 -> applyHmacHeaderPreset();
            case 2 -> applyPlainHashPreset();
            default -> { }
        }
    }

    private void applyHmacHeaderPreset() {
        algorithmCombo.setSelectedItem("HmacSHA256");
        selectValue(providerCombo, "internal");
        selectValue(keySourceCombo, "static");
        cipherFormatCombo.setSelectedItem("hex");
        selectValue(hashKeyPlacementCombo, "suffix");
        hexCaseCombo.setSelectedItem("lower");
        customSignTemplateArea.setText("${method}\\n${path}\\n${header.Timestamp}\\n${body}");
        headerTemplatesArea.setText("{\"Timestamp\":\"${timestamp}\"}");
        protocolGuideArea.setText(lang.getString("form.sign.guide.applied.hmac"));
        updateVisibility();
    }

    private void applyPlainHashPreset() {
        algorithmCombo.setSelectedItem("SHA-256");
        selectValue(providerCombo, "internal");
        selectValue(keySourceCombo, "none");
        keyValueField.setText("");
        cipherFormatCombo.setSelectedItem("hex");
        selectValue(hashKeyPlacementCombo, "none");
        hexCaseCombo.setSelectedItem("upper");
        customSignTemplateArea.setText("SECRET${method}${path}${stablejson:payload}");
        headerTemplatesArea.setText("{}");
        protocolGuideArea.setText(lang.getString("form.sign.guide.applied.hash"));
        updateVisibility();
    }
    
    private GridBagConstraints createGbc() {
        return ProcessorUIStyle.gbc();
    }

    private void addLabelAndField(JPanel p, String labelText, JComponent field, GridBagConstraints gbc, int row) {
        gbc.gridx = 0; 
        gbc.gridy = row;
        gbc.weightx = 0.0;
        JLabel label = new JLabel(labelText);
        label.setForeground(ProcessorUIStyle.text());
        p.add(label, gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        if (field instanceof JCheckBox) {
            field.setOpaque(false);
        }
        field.setMinimumSize(new Dimension(0, field.getMinimumSize().height));
        p.add(field, gbc);
        
        fieldLabels.put(field, label);
    }

    private void setVisible(Component comp, boolean visible) {
        if (comp == null) return;
        comp.setVisible(visible);
        Component label = fieldLabels.get(comp);
        if (label != null) {
            label.setVisible(visible);
        }
        if (comp.getParent() instanceof JViewport && comp.getParent().getParent() instanceof JScrollPane) {
            JScrollPane scroll = (JScrollPane) comp.getParent().getParent();
            scroll.setVisible(visible);
            Component scrollLabel = fieldLabels.get(scroll);
            if (scrollLabel != null) scrollLabel.setVisible(visible);
        }
    }

    private void insertTemplateVar(String text) {
        if (!customSignTemplateArea.isEnabled()) return;
        customSignTemplateArea.replaceSelection(text);
        customSignTemplateArea.requestFocusInWindow();
    }

    private void insertJsonVar() {
        String field = JOptionPane.showInputDialog(mainPanel, lang.getString("sign.prompt.json_path"));
        if (field != null && !field.trim().isEmpty()) {
            insertTemplateVar("${json:" + field.trim() + "}");
        }
    }

    private void insertHeaderVar() {
        String header = JOptionPane.showInputDialog(mainPanel, lang.getString("sign.prompt.header_name"));
        if (header != null && !header.trim().isEmpty()) {
            insertTemplateVar("${header." + header.trim() + "}");
        }
    }

    private void insertCanonVar() {
        JPanel p = new JPanel(new GridLayout(3, 2));
        JTextField pathF = new JTextField("json:params");
        JTextField pairF = new JTextField("&");
        JTextField kvF = new JTextField("=");
        p.add(new JLabel(lang.getString("sign.prompt.source"))); p.add(pathF);
        p.add(new JLabel(lang.getString("sign.prompt.pair_sep"))); p.add(pairF);
        p.add(new JLabel(lang.getString("sign.prompt.kv_sep"))); p.add(kvF);
        
        int res = JOptionPane.showConfirmDialog(mainPanel, p, lang.getString("sign.prompt.canon_func"), JOptionPane.OK_CANCEL_OPTION);
        if (res == JOptionPane.OK_OPTION) {
            String path = pathF.getText().trim();
            if (path.isEmpty()) path = "body";
            insertTemplateVar("${canonicalize:" + path + ":" + pairF.getText() + ":" + kvF.getText() + "}");
        }
    }

    @Override
    public JPanel getPanel() {
        return mainPanel;
    }

    @Override
    public void onActionTypeChanged(String actionType, boolean responseAction) {
        if (actionType != null && !actionType.isBlank()) {
            currentActionType = actionType;
        }
        updateVisibility();
    }

    public void updateVisibility() {
        String algorithm = selectedAlgorithm();
        String provider = selectedValue(providerCombo);
        String placement = selectedValue(hashKeyPlacementCombo);
        boolean pureHashWithoutKey = isPureHashAlgorithm(algorithm) && "none".equalsIgnoreCase(placement);
        String selectedSource = selectedValue(keySourceCombo);
        if (!loadingConfig && pureHashWithoutKey) {
            if (!autoKeyless) { previousKeySource = "none".equalsIgnoreCase(selectedSource) ? "static" : selectedSource; autoKeyless = true; }
            if (!"none".equalsIgnoreCase(selectedSource)) { selectValue(keySourceCombo, "none"); return; }
        }
        if (!loadingConfig && autoKeyless && !pureHashWithoutKey) {
            autoKeyless = false;
            if ("none".equalsIgnoreCase(selectedSource)) { selectValue(keySourceCombo, previousKeySource); return; }
        }

        String keySource = selectedValue(keySourceCombo);
        boolean isLookup = "lookup".equalsIgnoreCase(keySource);
        boolean isStatic = "static".equalsIgnoreCase(keySource);
        boolean isCached = "cached".equalsIgnoreCase(keySource);
        boolean isExternal = "external".equalsIgnoreCase(provider);
        boolean isSign = Constants.ActionType.SIGN.equalsIgnoreCase(currentActionType);
        boolean isVerify = Constants.ActionType.VERIFY.equalsIgnoreCase(currentActionType);
        String verifySource = selectedValue(verificationSourceCombo);

        setVisible(keySourceCombo, !pureHashWithoutKey);
        setVisible(keyValueField, isStatic && !pureHashWithoutKey);
        setVisible(lookupEndpointField, isLookup);
        setVisible(lookupMethodField, isLookup);
        setVisible(responseKeyPathField, isLookup);
        setVisible(fallbackLookupCheck, isLookup || isCached);
        if (lookupPanel != null) {
            lookupPanel.setVisible(isLookup || isCached);
        }
        if (externalServicePanel != null) {
            externalServicePanel.setVisible(isExternal);
        }
        setVisible(signEndpointField, isExternal && isSign);
        setVisible(signMethodField, isExternal && isSign);
        setVisible(verifyEndpointField, isExternal && isVerify);
        setVisible(verifyMethodField, isExternal && isVerify);
        if (verificationPanel != null) {
            verificationPanel.setVisible(isVerify);
        }
        setVisible(verificationSourceCombo, isVerify);
        setVisible(signatureHeaderField, isVerify && "header".equalsIgnoreCase(verifySource));
        setVisible(signatureFieldPathField, isVerify && "body-field".equalsIgnoreCase(verifySource));
        setVisible(signatureQueryParamField, isVerify && "query".equalsIgnoreCase(verifySource));
        setVisible(expectedSignatureField, isVerify && "fixed".equalsIgnoreCase(verifySource));
        setVisible(headerTemplatesArea, !isVerify);
        mainPanel.revalidate();
        mainPanel.repaint();
    }

    @Override
    public void loadConfig(ProcessingAction action) {
        loadingConfig = true;
        autoKeyless = false;
        try {
        currentActionType = action.getActionType() != null ? action.getActionType() : Constants.ActionType.SIGN;
        Map<String, Object> config = action.getConfig();
        if (config == null) config = new HashMap<>();

        algorithmCombo.setSelectedItem(stringValue(config.get(ConfigKey.ALGORITHM)));
        selectValue(providerCombo, stringValueOrDefault(config.get(ConfigKey.CRYPTO_PROVIDER), "internal"));
        selectValue(keySourceCombo, stringValueOrDefault(config.get(ConfigKey.KEY_SOURCE), "static"));
        keyValueField.setText(stringValue(config.get(ConfigKey.KEY_VALUE)));
        lookupEndpointField.setText(stringValue(config.get(ConfigKey.LOOKUP_ENDPOINT)));
        lookupMethodField.setText(stringValueOrDefault(config.get(ConfigKey.LOOKUP_METHOD), "POST"));
        responseKeyPathField.setText(stringValueOrDefault(config.get(ConfigKey.RESPONSE_KEY_PATH), "key"));
        fallbackLookupCheck.setSelected(booleanValue(config.get(ConfigKey.FALLBACK_LOOKUP)));
        signEndpointField.setText(stringValue(config.get(ConfigKey.SIGN_ENDPOINT)));
        signMethodField.setText(stringValueOrDefault(config.get(ConfigKey.SIGN_METHOD), "POST"));
        verifyEndpointField.setText(stringValue(config.get(ConfigKey.VERIFY_ENDPOINT)));
        verifyMethodField.setText(stringValueOrDefault(config.get(ConfigKey.VERIFY_METHOD), "POST"));

        cipherFormatCombo.setSelectedItem(stringValueOrDefault(config.get(ConfigKey.CIPHER_FORMAT), "base64"));
        selectValue(hashKeyPlacementCombo, stringValueOrDefault(config.get(ConfigKey.HASH_KEY_PLACEMENT), "suffix"));
        hexCaseCombo.setSelectedItem(stringValueOrDefault(config.get(ConfigKey.SIGNATURE_HEX_CASE), "lower"));
        
        sortKeysCheck.setSelected(booleanValue(config.get(ConfigKey.SORT_KEYS)));
        urlEncodeCheck.setSelected(booleanValue(config.get(ConfigKey.URL_ENCODE_VALUES)));
        pairSeparatorField.setText(stringValueOrDefault(config.get(ConfigKey.PAIR_SEPARATOR), "&"));
        kvSeparatorField.setText(stringValueOrDefault(config.get(ConfigKey.KV_SEPARATOR), "="));
        
        // Backfill legacy SIGN_CONTENT modes with equivalent templates
        String customTemplate = stringValue(config.get(ConfigKey.CUSTOM_SIGN_TEMPLATE));
        if (customTemplate.isEmpty()) {
            String legacyContent = stringValue(config.get(ConfigKey.SIGN_CONTENT));
            if ("method+path+body".equalsIgnoreCase(legacyContent)) {
                customTemplate = "${method}${path}${body}";
            } else if ("body".equalsIgnoreCase(legacyContent)) {
                customTemplate = "${body}";
            }
        }
        customSignTemplateArea.setText(customTemplate);
        loadedSignContent = stringValue(config.get(ConfigKey.SIGN_CONTENT));
        loadedTemplateDisplay = customTemplate;
        loadedTemplateConfig = config.get(ConfigKey.CUSTOM_SIGN_TEMPLATE);
        headerTemplatesArea.setText(formatHeaderTemplates(config.get(ConfigKey.HEADER_TEMPLATES)));
        selectValue(verificationSourceCombo, stringValueOrDefault(config.get(ConfigKey.SIGNATURE_SOURCE),
                stringValue(config.get(ConfigKey.EXPECTED_SIGNATURE)).isEmpty() ? "header" : "fixed"));
        signatureHeaderField.setText(stringValueOrDefault(config.get(ConfigKey.SIGNATURE_HEADER), "X-Signature"));
        signatureFieldPathField.setText(stringValueOrDefault(config.get(ConfigKey.SIGNATURE_FIELD_PATH), "$.signature"));
        signatureQueryParamField.setText(stringValueOrDefault(config.get(ConfigKey.SIGNATURE_QUERY_PARAM), "sign"));
        expectedSignatureField.setText(stringValue(config.get(ConfigKey.EXPECTED_SIGNATURE)));
        
        } finally { loadingConfig = false; }
        canonicalSection.setConfigured(sortKeysCheck.isSelected() || urlEncodeCheck.isSelected()
                || !"&".equals(pairSeparatorField.getText()) || !"=".equals(kvSeparatorField.getText()));
        updateVisibility();
    }

    @Override
    public void saveConfig(ProcessingAction action) {
        Map<String, Object> config = action.getConfig();
        if (config == null) {
            config = new HashMap<>();
            action.setConfig(config);
        }
        
        config.put(ConfigKey.ALGORITHM, algorithmCombo.getSelectedItem());
        config.put(ConfigKey.CRYPTO_PROVIDER, selectedValue(providerCombo));
        config.put(ConfigKey.KEY_SOURCE, selectedValue(keySourceCombo));
        config.put(ConfigKey.KEY_VALUE, keyValueField.getText());
        config.put(ConfigKey.LOOKUP_ENDPOINT, lookupEndpointField.getText());
        config.put(ConfigKey.LOOKUP_METHOD, lookupMethodField.getText());
        config.put(ConfigKey.RESPONSE_KEY_PATH, responseKeyPathField.getText());
        config.put(ConfigKey.FALLBACK_LOOKUP, fallbackLookupCheck.isSelected());
        config.put(ConfigKey.SIGN_ENDPOINT, signEndpointField.getText().trim());
        config.put(ConfigKey.SIGN_METHOD, signMethodField.getText().trim().isEmpty() ? "POST" : signMethodField.getText().trim());
        config.put(ConfigKey.VERIFY_ENDPOINT, verifyEndpointField.getText().trim());
        config.put(ConfigKey.VERIFY_METHOD, verifyMethodField.getText().trim().isEmpty() ? "POST" : verifyMethodField.getText().trim());
        
        config.put(ConfigKey.CIPHER_FORMAT, cipherFormatCombo.getSelectedItem());
        config.put(ConfigKey.HASH_KEY_PLACEMENT, selectedValue(hashKeyPlacementCombo));
        config.put(ConfigKey.SIGNATURE_HEX_CASE, hexCaseCombo.getSelectedItem());
        
        config.put(ConfigKey.SORT_KEYS, sortKeysCheck.isSelected());
        config.put(ConfigKey.URL_ENCODE_VALUES, urlEncodeCheck.isSelected());
        config.put(ConfigKey.PAIR_SEPARATOR, pairSeparatorField.getText());
        config.put(ConfigKey.KV_SEPARATOR, kvSeparatorField.getText());
        
        String template = customSignTemplateArea.getText();
        boolean unchangedMode = loadedSignContent != null && !loadedSignContent.isBlank() && template.equals(loadedTemplateDisplay);
        config.put(ConfigKey.SIGN_CONTENT, unchangedMode ? loadedSignContent : "custom");
        if (unchangedMode && loadedTemplateConfig == null) config.remove(ConfigKey.CUSTOM_SIGN_TEMPLATE);
        else config.put(ConfigKey.CUSTOM_SIGN_TEMPLATE, unchangedMode ? loadedTemplateConfig : template);
        config.put(ConfigKey.HEADER_TEMPLATES, Constants.ActionType.VERIFY.equalsIgnoreCase(currentActionType)
                ? new LinkedHashMap<>()
                : parseHeaderTemplates(headerTemplatesArea.getText()));
        config.put(ConfigKey.SIGNATURE_SOURCE, selectedValue(verificationSourceCombo));
        config.put(ConfigKey.SIGNATURE_HEADER, signatureHeaderField.getText());
        config.put(ConfigKey.SIGNATURE_FIELD_PATH, signatureFieldPathField.getText().trim().isEmpty()
                ? "$.signature"
                : signatureFieldPathField.getText().trim());
        config.put(ConfigKey.SIGNATURE_QUERY_PARAM, signatureQueryParamField.getText().trim().isEmpty()
                ? "sign"
                : signatureQueryParamField.getText().trim());
        config.put(ConfigKey.EXPECTED_SIGNATURE, expectedSignatureField.getText().trim());
    }

    @Override
    public boolean validateConfig() {
        if (Constants.ActionType.VERIFY.equalsIgnoreCase(currentActionType)) {
            return true;
        }
        String headerTemplates = headerTemplatesArea.getText();
        if (headerTemplates != null && !headerTemplates.trim().isEmpty()) {
            try {
                objectMapper.readValue(headerTemplates, new TypeReference<Map<String, String>>() {});
            } catch (Exception e) {
                JOptionPane.showMessageDialog(mainPanel,
                        lang.getString("form.error.header_template"),
                        lang.getString("form.error.header_title"),
                        JOptionPane.WARNING_MESSAGE);
                headerTemplatesArea.requestFocusInWindow();
                return false;
            }
        }
        return true;
    }

    private String stringValue(Object obj) {
        return obj == null ? "" : obj.toString();
    }
    
    private String stringValueOrDefault(Object obj, String def) {
        if (obj == null) return def;
        String s = obj.toString();
        return s.isEmpty() ? def : s;
    }

    private boolean booleanValue(Object obj) {
        if (obj instanceof Boolean) return (Boolean) obj;
        return "true".equalsIgnoreCase(stringValue(obj));
    }

    private String[] optionValues(JComboBox<String> combo) {
        if (combo == providerCombo) return new String[]{"internal", "external"};
        if (combo == keySourceCombo) return new String[]{"static", "lookup", "cached", "none"};
        if (combo == hashKeyPlacementCombo) return new String[]{"suffix", "none", "prefix", "both"};
        if (combo == verificationSourceCombo) return new String[]{"header", "body-field", "query", "fixed"};
        return null;
    }

    private String selectedValue(JComboBox<String> combo) {
        String[] values = optionValues(combo);
        int index = combo.getSelectedIndex();
        return values != null && index >= 0 && index < values.length ? values[index] : rawOption(String.valueOf(combo.getSelectedItem()));
    }

    private void selectValue(JComboBox<String> combo, String rawValue) {
        for (int i = 0; i < combo.getItemCount(); i++) {
            if (rawValue.equalsIgnoreCase(optionValues(combo) == null ? rawOption(combo.getItemAt(i)) : optionValues(combo)[i])) {
                combo.setSelectedIndex(i);
                return;
            }
        }
        combo.setSelectedItem(rawValue);
    }

    private String rawOption(String label) {
        if (label == null) return "";
        switch (label.trim()) {
            case "本地计算": return "internal";
            case "调用外部服务": return "external";
            case "固定值": return "static";
            case "从接口查询": return "lookup";
            case "使用缓存": return "cached";
            case "不需要密钥": return "none";
            case "追加密钥": return "suffix";
            case "不拼接密钥": return "none";
            case "前置密钥": return "prefix";
            case "前后都拼接": return "both";
            case "从 Header 读取": return "header";
            case "从 Body JSON 字段读取": return "body-field";
            case "从 Query 参数读取": return "query";
            case "使用固定签名值": return "fixed";
            default:
        }
        int start = label.lastIndexOf('(');
        int end = label.lastIndexOf(')');
        if (start >= 0 && end > start) {
            return label.substring(start + 1, end).trim();
        }
        return label.trim();
    }

    private String selectedAlgorithm() {
        Object selected = algorithmCombo != null ? algorithmCombo.getSelectedItem() : null;
        return selected == null ? "" : selected.toString();
    }

    private boolean isPureHashAlgorithm(String algorithm) {
        if (algorithm == null) {
            return false;
        }
        String normalized = algorithm.replace("-", "").replace("_", "").toUpperCase();
        return normalized.equals("MD5")
                || normalized.equals("SHA1")
                || normalized.equals("SHA256")
                || normalized.equals("SHA512")
                || normalized.equals("SM3");
    }

    @SuppressWarnings("unchecked")
    private String formatHeaderTemplates(Object value) {
        if (value == null) {
            return "";
        }
        if (value instanceof String) {
            return (String) value;
        }
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return value.toString();
        }
    }

    private Map<String, String> parseHeaderTemplates(String value) {
        if (value == null || value.trim().isEmpty()) {
            return new LinkedHashMap<>();
        }
        try {
            return objectMapper.readValue(value, new TypeReference<Map<String, String>>() {});
        } catch (Exception e) {
            throw new IllegalArgumentException(lang.getString("form.error.header_object"), e);
        }
    }
}
