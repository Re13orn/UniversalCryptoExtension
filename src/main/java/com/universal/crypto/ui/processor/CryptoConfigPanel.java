package com.universal.crypto.ui.processor;

import com.universal.crypto.ui.CollapsibleSection;
import com.universal.crypto.util.LanguageManager;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

public class CryptoConfigPanel implements ProcessorConfigUI {

    private final LanguageManager lang = LanguageManager.getInstance();

    private final String[] KEY_SOURCES = {
            lang.getString("form.option.static"),
            lang.getString("form.option.lookup"),
            lang.getString("form.option.cached"),
            lang.getString("form.option.none")
    };
    private final String[] PROVIDERS = {
            lang.getString("form.option.external"),
            lang.getString("form.option.internal")
    };
    private static final String[] FORMAT_OPTIONS = {"base64", "plain", "hex"};
    private static final String[] IV_FORMAT_OPTIONS = {"base64", "hex"};
    private static final String[] PAYLOAD_FORMATS = {"json", "raw"};
    private static final String[] ALGORITHM_OPTIONS = {
        "AES-GCM", "AES-CBC", "AES-ECB",
        "DES-CBC", "DES-ECB",
        "3DES-CBC", "3DES-ECB",
        "SM4-CBC", "SM4-ECB",
        "RSA-ECB", "RSA-OAEP",
        "SM2",
        "MD5", "SHA-1", "SHA-256", "SHA-512", "SM3",
        "Base64", "Hex", "URL"
    };

    private CollapsibleSection advancedSection;
    private JPanel advancedPanel;
    private final JPanel mainPanel;
    private final JTextArea tipsArea;
    
    // Core Config
    private JComboBox<String> cryptoProviderCombo;
    private JComboBox<String> algorithmCombo;
    private JComboBox<String> keySourceCombo;
    private JTextField keyValueField;
    
    // Lookup Config
    private JTextField lookupEndpointField;
    private JTextField lookupMethodField;
    private JTextField responseKeyPathField;
    private JCheckBox fallbackLookupCheck;

    // Internal Crypto Config
    private JComboBox<String> payloadFormatCombo;
    private JTextField cipherFieldField;
    private JTextField plainFieldField;
    private JTextField ivFieldField;
    private JTextField ivLiteralField;
    private JComboBox<String> cipherFormatCombo;
    private JComboBox<String> plainFormatCombo;
    private JComboBox<String> ivFormatCombo;
    private JTextField charsetField;
    private JTextField gcmTagLengthField;
    private JPanel formatRow;
    private JLabel formatLabel;

    // External Config
    private JTextField encryptEndpointField;
    private JTextField encryptMethodField;
    private JTextField decryptEndpointField;
    private JTextField decryptMethodField;

    // RSA Config
    private JTextArea rsaPublicKeyArea;
    private JTextArea rsaPrivateKeyArea;
    private JTextField rsaModeField;
    private JTextField rsaPaddingField;
    private JPanel rsaParamsRow;
    private JLabel rsaParamLabel;
    private JPanel lookupPanel;
    private JPanel internalPanel;
    private JPanel externalPanel;
    private JPanel rsaPanel;
    private boolean loadingConfig;
    private boolean autoKeyless;
    private String previousKeySource = "static";
    private String currentActionType = Constants.ActionType.ENCRYPT;
    
    private final Map<JComponent, Component> fieldLabels = new HashMap<>();

    public CryptoConfigPanel() {
        mainPanel = ProcessorUIStyle.formPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBackground(ProcessorUIStyle.background());
        mainPanel.setBorder(ProcessorUIStyle.pageBorder());

        tipsArea = ProcessorUIStyle.note(lang.getString("form.crypto.intro")
                + lang.getString("form.crypto.intro.local")
                + lang.getString("form.crypto.intro.external")
                + lang.getString("form.crypto.intro.scope"));
        tipsArea.setRows(4);
        ProcessorUIStyle.keepPreferredHeight(tipsArea);
        tipsArea.setAlignmentX(Component.LEFT_ALIGNMENT);
        mainPanel.add(tipsArea);
        mainPanel.add(Box.createVerticalStrut(12));

        // Group: Core Settings
        JPanel corePanel = createGroupPanel(lang.getString("form.crypto.common"));
        corePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints gbc = createGbc();
        int row = 0;

        cryptoProviderCombo = new JComboBox<>(PROVIDERS);
        cryptoProviderCombo.addActionListener(e -> updateVisibility());
        addLabelAndField(corePanel, lang.getString("form.label.provider"), cryptoProviderCombo, gbc, row++);

        algorithmCombo = new JComboBox<>(ALGORITHM_OPTIONS);
        algorithmCombo.setEditable(true);
        algorithmCombo.addActionListener(e -> updateVisibility());
        addLabelAndField(corePanel, lang.getString("form.label.algorithm"), algorithmCombo, gbc, row++);

        keySourceCombo = new JComboBox<>(KEY_SOURCES);
        keySourceCombo.addActionListener(e -> updateVisibility());
        addLabelAndField(corePanel, lang.getString("form.label.key_source"), keySourceCombo, gbc, row++);

        keyValueField = new JTextField();
        addLabelAndField(corePanel, lang.getString("form.label.key"), keyValueField, gbc, row++);
        
        addSection(corePanel);
        mainPanel.add(Box.createVerticalStrut(12));

        // Group: Key Lookup
        lookupPanel = createGroupPanel(lang.getString("form.crypto.lookup"));
        lookupPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        row = 0;
        
        lookupEndpointField = new JTextField();
        addLabelAndField(lookupPanel, lang.getString("form.label.lookup"), lookupEndpointField, gbc, row++);

        lookupMethodField = new JTextField("POST");
        addLabelAndField(lookupPanel, lang.getString("form.label.method"), lookupMethodField, gbc, row++);

        responseKeyPathField = new JTextField("key");
        addLabelAndField(lookupPanel, lang.getString("form.label.key_path"), responseKeyPathField, gbc, row++);

        fallbackLookupCheck = new JCheckBox(lang.getString("form.check.fallback"));
        addLabelAndField(lookupPanel, "", fallbackLookupCheck, gbc, row++);
        
        addSection(lookupPanel);

        // Group: Local data processing
        internalPanel = createGroupPanel(lang.getString("form.crypto.payload"));
        internalPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        row = 0;

        payloadFormatCombo = new JComboBox<>(PAYLOAD_FORMATS);
        addLabelAndField(internalPanel, lang.getString("form.label.payload"), payloadFormatCombo, gbc, row++);

        cipherFieldField = new JTextField();
        cipherFieldField.setToolTipText(lang.getString("form.hint.field"));
        addLabelAndField(internalPanel, lang.getString("form.label.cipher_field"), cipherFieldField, gbc, row++);

        plainFieldField = new JTextField();
        plainFieldField.setToolTipText(lang.getString("form.hint.field"));
        addLabelAndField(internalPanel, lang.getString("form.label.plain_field"), plainFieldField, gbc, row++);

        ivFieldField = new JTextField();
        ivFieldField.setToolTipText(lang.getString("form.hint.field"));
        addLabelAndField(internalPanel, lang.getString("form.label.iv_field"), ivFieldField, gbc, row++);

        ivLiteralField = new JTextField();
        ivLiteralField.setToolTipText(lang.getString("form.hint.iv"));
        addLabelAndField(internalPanel, lang.getString("form.label.iv"), ivLiteralField, gbc, row++);

        // Three encoding selectors share the available width, including narrow dialogs.
        formatRow = new JPanel(new GridLayout(2, 3, 6, 4));
        formatRow.setMinimumSize(new Dimension(0, 0));
        formatRow.add(new JLabel(lang.getString("form.label.cipher")));
        formatRow.add(new JLabel(lang.getString("form.label.plain")));
        formatRow.add(new JLabel("IV"));
        cipherFormatCombo = new JComboBox<>(FORMAT_OPTIONS);
        plainFormatCombo = new JComboBox<>(FORMAT_OPTIONS);
        ivFormatCombo = new JComboBox<>(IV_FORMAT_OPTIONS);
        formatRow.add(cipherFormatCombo); formatRow.add(plainFormatCombo); formatRow.add(ivFormatCombo);

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0.0;
        formatLabel = new JLabel(lang.getString("form.label.encoding"));
        internalPanel.add(formatLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        internalPanel.add(formatRow, gbc);
        fieldLabels.put(formatRow, formatLabel);
        row++;

        advancedPanel = createGroupPanel(lang.getString("crypto.group.advanced"));
        int advancedRow = 0;
        charsetField = new JTextField("UTF-8");
        addLabelAndField(advancedPanel, lang.getString("form.label.charset"), charsetField, gbc, advancedRow++);
        
        gcmTagLengthField = new JTextField("128");
        addLabelAndField(advancedPanel, lang.getString("form.label.tag"), gcmTagLengthField, gbc, advancedRow++);
        
        addSection(internalPanel);
        advancedSection = new CollapsibleSection(lang.getString("form.advanced"), advancedPanel);
        mainPanel.add(advancedSection);
        mainPanel.add(Box.createVerticalStrut(12));

        // Group: External API
        externalPanel = createGroupPanel(lang.getString("form.option.external"));
        externalPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        row = 0;
        
        encryptEndpointField = new JTextField();
        addLabelAndField(externalPanel, lang.getString("form.label.encrypt_endpoint"), encryptEndpointField, gbc, row++);

        encryptMethodField = new JTextField();
        addLabelAndField(externalPanel, lang.getString("form.label.encrypt_method"), encryptMethodField, gbc, row++);

        decryptEndpointField = new JTextField();
        addLabelAndField(externalPanel, lang.getString("form.label.decrypt_endpoint"), decryptEndpointField, gbc, row++);

        decryptMethodField = new JTextField();
        addLabelAndField(externalPanel, lang.getString("form.label.decrypt_method"), decryptMethodField, gbc, row++);
        
        addSection(externalPanel);

        // Group: RSA
        rsaPanel = createGroupPanel(lang.getString("form.crypto.rsa"));
        rsaPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        row = 0;
        
        rsaPublicKeyArea = new JTextArea(3, 20);
        rsaPublicKeyArea.setLineWrap(true);
        ProcessorUIStyle.styleTextArea(rsaPublicKeyArea, true);
        JScrollPane rsaPubScroll = new JScrollPane(rsaPublicKeyArea);
        addLabelAndField(rsaPanel, lang.getString("form.label.public_key"), rsaPubScroll, gbc, row++);

        rsaPrivateKeyArea = new JTextArea(3, 20);
        rsaPrivateKeyArea.setLineWrap(true);
        ProcessorUIStyle.styleTextArea(rsaPrivateKeyArea, true);
        JScrollPane rsaPrivScroll = new JScrollPane(rsaPrivateKeyArea);
        addLabelAndField(rsaPanel, lang.getString("form.label.private_key"), rsaPrivScroll, gbc, row++);

        rsaParamsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        rsaParamsRow.add(new JLabel(lang.getString("form.label.mode")));
        rsaModeField = new JTextField("ECB", 5);
        rsaParamsRow.add(rsaModeField);
        rsaParamsRow.add(Box.createHorizontalStrut(10));
        rsaParamsRow.add(new JLabel(lang.getString("form.label.padding")));
        rsaPaddingField = new JTextField("PKCS1Padding", 10);
        rsaParamsRow.add(rsaPaddingField);
        
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0.0;
        rsaParamLabel = new JLabel(lang.getString("form.label.rsa_details"));
        rsaPanel.add(rsaParamLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        rsaPanel.add(rsaParamsRow, gbc);
        fieldLabels.put(rsaParamsRow, rsaParamLabel);
        
        addSection(rsaPanel);
        
        // Add glue to push everything up
        mainPanel.add(Box.createVerticalGlue());
    }
    
    private JPanel createGroupPanel(String title) {
        return ProcessorUIStyle.section(title);
    }

    private void addSection(JPanel section) {
        mainPanel.add(section);
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
        
        // Register parent panel for visibility control if needed
        field.putClientProperty("groupPanel", p);
    }
    
    private void setVisible(Component comp, boolean visible) {
        if (comp == null) return;
        comp.setVisible(visible);
        Component label = fieldLabels.get(comp);
        if (label != null) {
            label.setVisible(visible);
        }
        // Handle JScrollPane parents for TextAreas
        if (comp.getParent() instanceof JViewport && comp.getParent().getParent() instanceof JScrollPane) {
            JScrollPane scroll = (JScrollPane) comp.getParent().getParent();
            scroll.setVisible(visible);
            Component scrollLabel = fieldLabels.get(scroll);
            if (scrollLabel != null) scrollLabel.setVisible(visible);
        }
        
        // Check if group panel should be hidden (optimization)
        // Ideally we check if all children of a group panel are hidden, then hide the group.
        // For now, let's just control field visibility. Layout managers usually handle zero-height components well.
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
        String provider = selectedValue(cryptoProviderCombo);
        String keySource = selectedValue(keySourceCombo);
        String algorithm = String.valueOf(algorithmCombo.getSelectedItem());
        String normalizedAlgorithm = algorithm != null ? algorithm.trim().toUpperCase(java.util.Locale.ROOT) : "";
        boolean isInternal = "internal".equalsIgnoreCase(provider);
        boolean isLookup = "lookup".equalsIgnoreCase(keySource);
        boolean isStatic = "static".equalsIgnoreCase(keySource);
        boolean isCached = "cached".equalsIgnoreCase(keySource);
        boolean isEncryptAction = Constants.ActionType.ENCRYPT.equalsIgnoreCase(currentActionType);
        boolean isDecryptAction = Constants.ActionType.DECRYPT.equalsIgnoreCase(currentActionType);
        boolean isRsa = normalizedAlgorithm.contains("RSA");
        boolean isCodecOrHash = isCodecOrHashAlgorithm(normalizedAlgorithm);
        boolean needsIv = !normalizedAlgorithm.isEmpty()
                && !isCodecOrHash
                && !normalizedAlgorithm.contains("ECB")
                && !normalizedAlgorithm.contains("RSA")
                && !normalizedAlgorithm.equals("SM2");
        boolean needsGcmTag = normalizedAlgorithm.contains("GCM");

        if (!loadingConfig && isInternal && isCodecOrHash) {
            if (!autoKeyless) {
                previousKeySource = "none".equalsIgnoreCase(keySource) ? "static" : keySource;
                autoKeyless = true;
            }
            if (!"none".equalsIgnoreCase(keySource)) { selectValue(keySourceCombo, "none"); return; }
        }
        if (!loadingConfig && autoKeyless && (!isInternal || !isCodecOrHash)) {
            autoKeyless = false;
            if ("none".equalsIgnoreCase(keySource)) { selectValue(keySourceCombo, previousKeySource); return; }
        }

        setVisible(keySourceCombo, !isCodecOrHash);
        setVisible(keyValueField, !isCodecOrHash && isStatic);
        setVisible(lookupEndpointField, !isCodecOrHash && isLookup);
        setVisible(lookupMethodField, !isCodecOrHash && isLookup);
        setVisible(responseKeyPathField, !isCodecOrHash && isLookup);
        setVisible(fallbackLookupCheck, !isCodecOrHash && (isLookup || isCached));
        if (lookupPanel != null) {
            lookupPanel.setVisible(!isCodecOrHash && (isLookup || isCached));
        }

        setVisible(encryptEndpointField, !isInternal && isEncryptAction);
        setVisible(encryptMethodField, !isInternal && isEncryptAction);
        setVisible(decryptEndpointField, !isInternal && isDecryptAction);
        setVisible(decryptMethodField, !isInternal && isDecryptAction);
        if (externalPanel != null) {
            externalPanel.setVisible(!isInternal);
        }

        setVisible(payloadFormatCombo, isInternal);
        setVisible(cipherFieldField, isInternal && !isHashOnlyAlgorithm(normalizedAlgorithm));
        setVisible(plainFieldField, isInternal && !isHashOnlyAlgorithm(normalizedAlgorithm));
        setVisible(ivFieldField, isInternal && needsIv);
        setVisible(ivLiteralField, isInternal && needsIv);
        setVisible(formatRow, isInternal);
        formatLabel.setVisible(isInternal);
        setVisible(charsetField, isInternal);
        setVisible(gcmTagLengthField, isInternal && needsGcmTag);
        if (internalPanel != null) {
            internalPanel.setVisible(isInternal);
            advancedSection.setVisible(isInternal);
        }
        
        setVisible(rsaPublicKeyArea.getParent().getParent(), isInternal && isRsa);
        setVisible(rsaPrivateKeyArea.getParent().getParent(), isInternal && isRsa);
        setVisible(rsaParamsRow, isInternal && isRsa);
        rsaParamLabel.setVisible(isInternal && isRsa);
        if (rsaPanel != null) {
            rsaPanel.setVisible(isInternal && isRsa);
        }

        mainPanel.revalidate();
        mainPanel.repaint();
    }

    @Override
    public void loadConfig(ProcessingAction action) {
        loadingConfig = true;
        autoKeyless = false;
        try {
        Map<String, Object> config = action.getConfig();
        if (config == null) config = new HashMap<>();

        selectValue(cryptoProviderCombo, stringValueOrDefault(config.get(ConfigKey.CRYPTO_PROVIDER), "external"));
        algorithmCombo.setSelectedItem(stringValue(config.get(ConfigKey.ALGORITHM)));
        selectValue(keySourceCombo, stringValueOrDefault(config.get(ConfigKey.KEY_SOURCE), "static"));
        keyValueField.setText(stringValue(config.get(ConfigKey.KEY_VALUE)));
        lookupEndpointField.setText(stringValue(config.get(ConfigKey.LOOKUP_ENDPOINT)));
        lookupMethodField.setText(stringValueOrDefault(config.get(ConfigKey.LOOKUP_METHOD), "POST"));
        responseKeyPathField.setText(stringValueOrDefault(config.get(ConfigKey.RESPONSE_KEY_PATH), "key"));
        fallbackLookupCheck.setSelected(booleanValue(config.get(ConfigKey.FALLBACK_LOOKUP)));

        payloadFormatCombo.setSelectedItem(stringValueOrDefault(config.get(ConfigKey.PAYLOAD_FORMAT), "json"));
        cipherFieldField.setText(stringValueOrDefault(config.get(ConfigKey.CIPHER_FIELD), "ciphertext_b64"));
        plainFieldField.setText(stringValue(config.get(ConfigKey.PLAIN_FIELD)));
        ivFieldField.setText(stringValueOrDefault(config.get(ConfigKey.IV_FIELD), "iv_b64"));
        ivLiteralField.setText(stringValue(config.get(ConfigKey.IV_LITERAL_VALUE)));
        cipherFormatCombo.setSelectedItem(stringValueOrDefault(config.get(ConfigKey.CIPHER_FORMAT), "base64"));
        plainFormatCombo.setSelectedItem(stringValueOrDefault(config.get(ConfigKey.PLAIN_FORMAT), "plain"));
        ivFormatCombo.setSelectedItem(stringValueOrDefault(config.get(ConfigKey.IV_FORMAT), "base64"));
        charsetField.setText(stringValueOrDefault(config.get(ConfigKey.CHARSET), "UTF-8"));
        gcmTagLengthField.setText(stringValueOrDefault(config.get(ConfigKey.GCM_TAG_LENGTH), "128"));

        encryptEndpointField.setText(stringValue(config.get(ConfigKey.ENCRYPT_ENDPOINT)));
        encryptMethodField.setText(stringValue(config.get(ConfigKey.ENCRYPT_METHOD)));
        decryptEndpointField.setText(stringValue(config.get(ConfigKey.DECRYPT_ENDPOINT)));
        decryptMethodField.setText(stringValue(config.get(ConfigKey.DECRYPT_METHOD)));

        rsaPublicKeyArea.setText(stringValue(config.get(ConfigKey.RSA_PUBLIC_KEY)));
        rsaPrivateKeyArea.setText(stringValue(config.get(ConfigKey.RSA_PRIVATE_KEY)));
        rsaModeField.setText(stringValueOrDefault(config.get(ConfigKey.RSA_MODE), "ECB"));
        rsaPaddingField.setText(stringValueOrDefault(config.get(ConfigKey.RSA_PADDING), "PKCS1Padding"));
        
        } finally { loadingConfig = false; }
        advancedSection.setConfigured(!"UTF-8".equalsIgnoreCase(charsetField.getText()) || !"128".equals(gcmTagLengthField.getText()));
        updateVisibility();
    }

    @Override
    public void saveConfig(ProcessingAction action) {
        Map<String, Object> config = action.getConfig();
        if (config == null) {
            config = new HashMap<>();
            action.setConfig(config);
        }
        
        config.put(ConfigKey.CRYPTO_PROVIDER, selectedValue(cryptoProviderCombo));
        config.put(ConfigKey.ALGORITHM, algorithmCombo.getSelectedItem());
        config.put(ConfigKey.KEY_SOURCE, selectedValue(keySourceCombo));
        config.put(ConfigKey.KEY_VALUE, keyValueField.getText());
        config.put(ConfigKey.LOOKUP_ENDPOINT, lookupEndpointField.getText());
        config.put(ConfigKey.LOOKUP_METHOD, lookupMethodField.getText());
        config.put(ConfigKey.RESPONSE_KEY_PATH, responseKeyPathField.getText());
        config.put(ConfigKey.FALLBACK_LOOKUP, fallbackLookupCheck.isSelected());
        
        config.put(ConfigKey.PAYLOAD_FORMAT, payloadFormatCombo.getSelectedItem());
        config.put(ConfigKey.CIPHER_FIELD, cipherFieldField.getText());
        config.put(ConfigKey.PLAIN_FIELD, plainFieldField.getText());
        config.put(ConfigKey.IV_FIELD, ivFieldField.getText());
        config.put(ConfigKey.IV_LITERAL_VALUE, ivLiteralField.getText());
        config.put(ConfigKey.CIPHER_FORMAT, cipherFormatCombo.getSelectedItem());
        config.put(ConfigKey.PLAIN_FORMAT, plainFormatCombo.getSelectedItem());
        config.put(ConfigKey.IV_FORMAT, ivFormatCombo.getSelectedItem());
        config.put(ConfigKey.CHARSET, charsetField.getText());
        config.put(ConfigKey.GCM_TAG_LENGTH, gcmTagLengthField.getText());
        
        config.put(ConfigKey.ENCRYPT_ENDPOINT, encryptEndpointField.getText());
        config.put(ConfigKey.ENCRYPT_METHOD, encryptMethodField.getText());
        config.put(ConfigKey.DECRYPT_ENDPOINT, decryptEndpointField.getText());
        config.put(ConfigKey.DECRYPT_METHOD, decryptMethodField.getText());
        
        config.put(ConfigKey.RSA_PUBLIC_KEY, rsaPublicKeyArea.getText());
        config.put(ConfigKey.RSA_PRIVATE_KEY, rsaPrivateKeyArea.getText());
        config.put(ConfigKey.RSA_MODE, rsaModeField.getText());
        config.put(ConfigKey.RSA_PADDING, rsaPaddingField.getText());
    }

    @Override
    public boolean validateConfig() {
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

    private boolean isCodecOrHashAlgorithm(String algorithm) {
        return isHashOnlyAlgorithm(algorithm)
                || algorithm.startsWith("BASE64")
                || algorithm.startsWith("HEX")
                || algorithm.startsWith("URL");
    }

    private boolean isHashOnlyAlgorithm(String algorithm) {
        return "MD5".equals(algorithm)
                || "SHA-1".equals(algorithm)
                || "SHA1".equals(algorithm)
                || "SHA-256".equals(algorithm)
                || "SHA256".equals(algorithm)
                || "SHA-512".equals(algorithm)
                || "SHA512".equals(algorithm)
                || "SM3".equals(algorithm);
    }

    private String[] optionValues(JComboBox<String> combo) {
        if (combo == cryptoProviderCombo) return new String[]{"external", "internal"};
        if (combo == keySourceCombo) return new String[]{"static", "lookup", "cached", "none"};
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
            default:
        }
        int start = label.lastIndexOf('(');
        int end = label.lastIndexOf(')');
        if (start >= 0 && end > start) {
            return label.substring(start + 1, end).trim();
        }
        return label.trim();
    }
}
