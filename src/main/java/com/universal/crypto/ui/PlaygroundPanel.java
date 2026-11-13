package com.universal.crypto.ui;

import com.universal.crypto.ui.processor.ScriptHelp;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.engine.RuleMatchEngine;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.processor.ProcessorResult;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.util.TemplateEngine;
import com.universal.crypto.util.DebugUtil;
import com.universal.crypto.util.LanguageManager;
import com.universal.crypto.util.Logger;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Playground panel for testing processors and scripts
 */
public class PlaygroundPanel extends JPanel {

    private static final Logger logger = Logger.getInstance();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private final LanguageManager lang = LanguageManager.getInstance();

    private final MontoyaApi api;
    private final ProcessorManager processorManager;
    private final RuleManager ruleManager;
    private final RuleMatchEngine matchEngine;

    // UI Components
    private JComboBox<String> processorTypeCombo;
    private JPanel configCardPanel;
    private CardLayout configCardLayout;
    
    // Crypto Config Components
    private JComboBox<String> actionCombo;
    private JComboBox<String> algorithmCombo;
    private JComboBox<String> keySourceCombo; // [NEW] Key Source
    private JTextField keyField;
    private JTextField ivField;
    private JComboBox<String> providerCombo;
    
    // Script Config Components
    private JTextArea scriptArea;
    private JComboBox<String> scriptGuideCombo;
    private JTextArea scriptGuideArea;
    private JComboBox<String> scriptTemplateCombo;
    
    // Input/Output
    private JTextArea inputArea;
    private JTextArea outputArea;
    private JLabel statusLabel;
    private JButton runButton;
    private JSplitPane mainSplit;
    private SwingWorker<TestOutput, Void> testWorker;

    private Component[] formFields() {
        return new Component[]{processorTypeCombo, actionCombo, algorithmCombo, keySourceCombo, keyField,
                ivField, providerCombo, scriptArea, scriptGuideCombo, scriptTemplateCombo,
                inputArea, outputArea, signActionCombo, signAlgorithmCombo, signContentCombo,
                signTargetHeaderField, signKeyField, signKeySourceCombo, signProviderCombo,
                signCipherFormatCombo, signHashKeyPlacementCombo, signHexCaseCombo,
                signCustomTemplateArea, signHeaderTemplatesArea, signHttpRequestModeCheck,
                fieldOperationCombo, fieldPathField, fieldToValueField, fieldFromValueField, fieldOverwriteCheck};
    }

    public PlaygroundPanel(MontoyaApi api, ProcessorManager processorManager) {
        this(api, processorManager, null, null);
    }

    public PlaygroundPanel(MontoyaApi api, ProcessorManager processorManager,
                           RuleManager ruleManager, RuleMatchEngine matchEngine) {
        this.api = api;
        this.processorManager = processorManager;
        this.ruleManager = ruleManager;
        this.matchEngine = matchEngine;
        
        rebuildUI();
    }
    
    public void rebuildUI() {
        FormState saved = FormState.capture(formFields());
        double ratio = SplitPaneLayout.ratio(mainSplit, 0.4);
        String status = statusLabel == null ? null : statusLabel.getText();
        Color outputColor = outputArea == null ? null : outputArea.getForeground();
        this.removeAll();
        setLayout(new BorderLayout());
        setBorder(UIStyle.emptyBorder());
        setBackground(UIStyle.background());
        
        // Top Control Panel
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.setOpaque(false);
        topPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        
        topPanel.add(new JLabel(lang.getString("playground.processor_type")));
        processorTypeCombo = new JComboBox<>(new String[]{
            Constants.ProcessorType.CRYPTO,
            Constants.ProcessorType.SCRIPT,
            Constants.ProcessorType.SIGNATURE,
            Constants.ProcessorType.FIELD
        });
        processorTypeCombo.addActionListener(this::onProcessorTypeChanged);
        topPanel.add(processorTypeCombo);
        
        add(topPanel, BorderLayout.NORTH);
        
        // Main Content Split (Config vs IO)
        mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        SplitPaneLayout.initialize(mainSplit, ratio);
        mainSplit.setBorder(BorderFactory.createEmptyBorder());
        mainSplit.setDividerSize(8);
        
        // Config Panel (Top Half)
        configCardLayout = new CardLayout();
        configCardPanel = new JPanel(configCardLayout);
        configCardPanel.setBorder(UIStyle.sectionBorder(lang.getString("playground.config")));
        configCardPanel.setBackground(UIStyle.background());
        
        configCardPanel.add(UIStyle.scroll(createCryptoConfigPanel()), Constants.ProcessorType.CRYPTO);
        configCardPanel.add(UIStyle.scroll(createScriptConfigPanel()), Constants.ProcessorType.SCRIPT);
        configCardPanel.add(UIStyle.scroll(createSignatureConfigPanel()), Constants.ProcessorType.SIGNATURE);
        configCardPanel.add(UIStyle.scroll(createFieldConfigPanel()), Constants.ProcessorType.FIELD);
        
        configCardPanel.setMinimumSize(new Dimension(0, 120));
        mainSplit.setTopComponent(configCardPanel);
        
        // IO Panel (Bottom Half)
        mainSplit.setBottomComponent(createIOPanel());
        
        add(mainSplit, BorderLayout.CENTER);
        
        // Initial state - default selection
        if (processorTypeCombo.getItemCount() > 0) {
             processorTypeCombo.setSelectedIndex(0);
        }
        
        saved.restore(formFields());
        updateSignatureTemplateVisibility();
        updateSignatureKeyVisibility();
        updateScriptGuideText();
        if (status != null) statusLabel.setText(status);
        if (outputColor != null) outputArea.setForeground(outputColor);
        runButton.setEnabled(testWorker == null);
        this.revalidate();
        this.repaint();
    }

    private JPanel createCryptoConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        int row = 0;

        row = addPlaygroundNote(panel, gbc, row, lang.getString("playground.help.crypto"));
        
        // Action (Encrypt/Decrypt)
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel(lang.getString("playground.label.action")), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        actionCombo = new JComboBox<>(new String[]{
            Constants.ActionType.ENCRYPT,
            Constants.ActionType.DECRYPT
        });
        panel.add(actionCombo, gbc);
        row++;
        
        // Algorithm
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel(lang.getString("playground.label.algorithm")), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        algorithmCombo = new JComboBox<>(new String[]{
            "AES-GCM", "AES-CBC", "AES-ECB",
            "DES-CBC", "DES-ECB", "3DES-CBC", "3DES-ECB",
            "RSA-ECB", "RSA-OAEP", "SM4-CBC", "SM4-ECB", "SM2",
            "Base64", "Hex", "URL", "MD5", "SHA-1", "SHA-256", "SHA-512", "SM3"
        });
        algorithmCombo.setEditable(true);
        panel.add(algorithmCombo, gbc);
        row++;

        // Key Source
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel(lang.getString("playground.label.keysource")), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        keySourceCombo = new JComboBox<>(new String[]{
            lang.getString("playground.keysource.static"),
            lang.getString("playground.keysource.none")
        });
        keySourceCombo.addActionListener(e -> {
            boolean isStatic = lang.getString("playground.keysource.static").equals(keySourceCombo.getSelectedItem());
            keyField.setEnabled(isStatic);
            if (!isStatic) keyField.setText("");
        });
        panel.add(keySourceCombo, gbc);
        row++;
        
        // Key
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel(lang.getString("playground.label.key")), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        keyField = new JTextField();
        panel.add(keyField, gbc);
        row++;
        
        // IV
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel(lang.getString("playground.label.iv")), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        ivField = new JTextField();
        panel.add(ivField, gbc);
        row++;

        // Provider
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel(lang.getString("playground.label.provider")), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        providerCombo = new JComboBox<>(new String[]{"本地计算", "调用外部服务"});
        panel.add(providerCombo, gbc);
        
        // Spacer to push everything up
        gbc.gridy++; gbc.weighty = 1.0;
        panel.add(new JPanel(), gbc);
        
        return panel;
    }
    
    private JPanel createSignatureConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        int row = 0;

        row = addPlaygroundNote(panel, gbc, row, lang.getString("playground.help.signature"));
        
        // Action
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("要做什么:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        signActionCombo = new JComboBox<>(new String[]{
            Constants.ActionType.SIGN,
            Constants.ActionType.VERIFY
        });
        panel.add(signActionCombo, gbc);
        row++;
        
        // Algorithm
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("算法:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        signAlgorithmCombo = new JComboBox<>(new String[]{
            "SHA-256", "MD5", "SHA-1", "SHA-512", "SM3",
            "HmacSHA256", "HmacSHA1", "HmacSHA512", "HmacSM3",
            "SHA256withRSA", "SHA1withRSA", "SHA512withRSA"
        });
        signAlgorithmCombo.setEditable(true);
        panel.add(signAlgorithmCombo, gbc);
        row++;

        // Target Header
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("签名写入的 Header:"), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        signTargetHeaderField = new JTextField("Sign");
        signTargetHeaderField.setToolTipText(lang.getString("playground.help.hint.signature_header"));
        panel.add(signTargetHeaderField, gbc);
        row++;
        
        // Content Source
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("签名内容:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        signContentCombo = new JComboBox<>(new String[]{
            "body", "method+path+body", "custom"
        });
        signContentCombo.addActionListener(e -> updateSignatureTemplateVisibility());
        panel.add(signContentCombo, gbc);
        row++;
        
        // Custom Template (Hidden by default)
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        signCustomTemplateLabel = new JLabel("签名原文:");
        panel.add(signCustomTemplateLabel, gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        signCustomTemplateArea = new JTextArea(3, 20);
        signCustomTemplateArea.setText("${method} ${path}\n${body}");
        UIStyle.styleTextArea(signCustomTemplateArea, true);
        signCustomTemplateScroll = new JScrollPane(signCustomTemplateArea);
        panel.add(signCustomTemplateScroll, gbc);
        row++;

        // Header Templates
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("签名前先生成这些 Header:"), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        signHeaderTemplatesArea = new JTextArea(3, 20);
        signHeaderTemplatesArea.setText("{}");
        signHeaderTemplatesArea.setToolTipText(lang.getString("playground.help.hint.headers"));
        UIStyle.styleTextArea(signHeaderTemplatesArea, true);
        panel.add(new JScrollPane(signHeaderTemplatesArea), gbc);
        row++;
        
        // Key
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("密钥 / Secret:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        signKeyField = new JTextField();
        panel.add(signKeyField, gbc);
        row++;

        // Key Source
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("密钥从哪里来:"), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        signKeySourceCombo = new JComboBox<>(new String[]{
                "固定值",
                "从接口查询",
                "使用缓存",
                "不需要密钥"
        });
        signKeySourceCombo.addActionListener(e -> updateSignatureKeyVisibility());
        panel.add(signKeySourceCombo, gbc);
        row++;
        
        // Provider
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("在哪里计算:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        signProviderCombo = new JComboBox<>(new String[]{"本地计算", "调用外部服务"});
        panel.add(signProviderCombo, gbc);
        row++;

        // Output format row
        JPanel formatPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        formatPanel.setOpaque(false);
        signCipherFormatCombo = new JComboBox<>(new String[]{"hex", "base64", "plain"});
        signHashKeyPlacementCombo = new JComboBox<>(new String[]{
                "不拼接密钥",
                "追加密钥",
                "前置密钥",
                "前后都拼接"
        });
        signHexCaseCombo = new JComboBox<>(new String[]{"upper", "lower"});
        formatPanel.add(new JLabel("格式"));
        formatPanel.add(signCipherFormatCombo);
        formatPanel.add(new JLabel("密钥参与方式"));
        formatPanel.add(signHashKeyPlacementCombo);
        formatPanel.add(new JLabel("Hex 大小写"));
        formatPanel.add(signHexCaseCombo);

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("输出:"), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        panel.add(formatPanel, gbc);
        row++;

        // HTTP Request Dry Run
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1.0;
        signHttpRequestModeCheck = new JCheckBox("把输入当作完整 HTTP 请求，并显示最终发出的请求");
        signHttpRequestModeCheck.setOpaque(false);
        signHttpRequestModeCheck.setSelected(true);
        panel.add(signHttpRequestModeCheck, gbc);
        
        // Spacer
        gbc.gridy++; gbc.weighty = 1.0;
        panel.add(new JPanel(), gbc);
        
        updateSignatureTemplateVisibility(); // Initial State
        updateSignatureKeyVisibility();
        
        return panel;
    }
    
    private void updateSignatureTemplateVisibility() {
        boolean isCustom = "custom".equals(signContentCombo.getSelectedItem());
        signCustomTemplateLabel.setVisible(isCustom);
        signCustomTemplateScroll.setVisible(isCustom);
        this.revalidate();
        this.repaint();
    }

    private void updateSignatureKeyVisibility() {
        if (signKeyField == null || signKeySourceCombo == null) {
            return;
        }
        boolean isStatic = "static".equalsIgnoreCase(selectedValue(signKeySourceCombo));
        signKeyField.setEnabled(isStatic);
        if (!isStatic) {
            signKeyField.setText("");
        }
    }

    private JComboBox<String> fieldOperationCombo;
    private JTextField fieldPathField;
    private JTextField fieldToValueField;
    private JTextField fieldFromValueField;
    private JCheckBox fieldOverwriteCheck;

    private JPanel createFieldConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        int row = 0;

        row = addPlaygroundNote(panel, gbc, row, lang.getString("playground.help.field"));

        // Operation
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("要做什么:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        fieldOperationCombo = new JComboBox<>(new String[]{
            Constants.ActionType.ADD,
            Constants.ActionType.REPLACE,
            Constants.ActionType.REMOVE
        });
        panel.add(fieldOperationCombo, gbc);
        row++;

        // Path
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("JSON 字段:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        fieldPathField = new JTextField();
        fieldPathField.setToolTipText(lang.getString("playground.help.hint.field"));
        panel.add(fieldPathField, gbc);
        row++;

        // To Value
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("新值:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        fieldToValueField = new JTextField();
        panel.add(fieldToValueField, gbc);
        row++;

        // From Value
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("原值校验（可选）:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        fieldFromValueField = new JTextField();
        panel.add(fieldFromValueField, gbc);
        row++;

        // Overwrite
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1.0;
        fieldOverwriteCheck = new JCheckBox("字段已存在时允许覆盖（仅添加时生效）");
        panel.add(fieldOverwriteCheck, gbc);

        // Spacer
        gbc.gridy++; gbc.weighty = 1.0;
        panel.add(new JPanel(), gbc);
        
        return panel;
    }
    
    private JPanel createScriptConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setOpaque(false);

        JPanel guidePanel = new JPanel(new GridBagLayout());
        guidePanel.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        int row = 0;

        scriptGuideCombo = new JComboBox<>(ScriptHelp.topics());
        scriptGuideCombo.addActionListener(e -> updateScriptGuideText());

        gbc.gridx = 0;
        gbc.gridy = row;
        guidePanel.add(new JLabel(LanguageManager.getInstance().getString("script.help.label_colon")), gbc);
        gbc.gridx = 1;
        guidePanel.add(scriptGuideCombo, gbc);
        row++;

        scriptGuideArea = playgroundNote("");
        scriptGuideArea.setRows(8);
        scriptGuideArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        guidePanel.add(scriptGuideArea, gbc);
        gbc.gridwidth = 1;
        row++;

        scriptTemplateCombo = new JComboBox<>(ScriptHelp.templates());
        JButton applyTemplateButton = UIStyle.button(LanguageManager.getInstance().getString("script.help.apply"));
        applyTemplateButton.addActionListener(e -> applyPlaygroundScriptTemplate());

        JPanel templatePanel = new JPanel(new BorderLayout(8, 0));
        templatePanel.setOpaque(false);
        templatePanel.add(scriptTemplateCombo, BorderLayout.CENTER);
        templatePanel.add(applyTemplateButton, BorderLayout.EAST);

        gbc.gridx = 0;
        gbc.gridy = row;
        guidePanel.add(new JLabel(LanguageManager.getInstance().getString("script.help.templates_colon")), gbc);
        gbc.gridx = 1;
        guidePanel.add(templatePanel, gbc);
        row++;

        JPanel helperPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        helperPanel.setOpaque(false);
        addScriptSnippetButton(helperPanel, "content", "content");
        addScriptSnippetButton(helperPanel, "Header", "request.getHeader('Timestamp')");
        addScriptSnippetButton(helperPanel, "Path", "request.getPath()");
        addScriptSnippetButton(helperPanel, "Query", "request.getQuery()");
        addScriptSnippetButton(helperPanel, "QueryParam", "request.getQueryParam('a')");
        addScriptSnippetButton(helperPanel, "Hash", "Hash.sha256(content)");
        addScriptSnippetButton(helperPanel, "HMAC", "Hash.hmacSha256(content, 'secret')");
        addScriptSnippetButton(helperPanel, "JSON", "var obj = JSON.parse(content || '{}');\nreturn JSON.stringify(obj);");

        gbc.gridx = 0;
        gbc.gridy = row;
        guidePanel.add(new JLabel(LanguageManager.getInstance().getString("script.help.snippets_colon")), gbc);
        gbc.gridx = 1;
        guidePanel.add(helperPanel, gbc);

        panel.add(guidePanel, BorderLayout.NORTH);
        
        scriptArea = new JTextArea();
        UIStyle.styleTextArea(scriptArea, true);
        scriptArea.setText("""
                // content 是当前输入；return 的字符串会写回结果。
                // 例：return Base64.decode(content);
                return content;""");
        
        JScrollPane scroll = UIStyle.scroll(scriptArea);
        panel.add(scroll, BorderLayout.CENTER);
        updateScriptGuideText();
        
        return panel;
    }

    private void addScriptSnippetButton(JPanel panel, String label, String snippet) {
        JButton button = UIStyle.button(label);
        button.setToolTipText(snippet.replace("\n", " "));
        button.addActionListener(e -> {
            scriptArea.replaceSelection(snippet);
            scriptArea.requestFocusInWindow();
        });
        panel.add(button);
    }

    private void updateScriptGuideText() {
        if (scriptGuideArea != null && scriptGuideCombo != null) scriptGuideArea.setText(ScriptHelp.guide(scriptGuideCombo.getSelectedIndex()));
    }

    private void applyPlaygroundScriptTemplate() {
        if (scriptArea == null || scriptTemplateCombo == null) {
            return;
        }
        if (scriptTemplateCombo.getSelectedIndex() == 1) {
            scriptArea.setText("return content;");
        } else if (scriptTemplateCombo.getSelectedIndex() == 2) {
            scriptArea.setText("""
                    // 把当前输入做 Base64 解码。
                    return Base64.decode(content);""");
        } else if (scriptTemplateCombo.getSelectedIndex() == 3) {
            scriptArea.setText("""
                    // 真正规则里：基础页选择结果写回到 header，目标名称填 X-Signature。
                    var timestamp = request.getHeader('Timestamp') || '';
                    return Hash.sha256(timestamp + content);""");
        } else if (scriptTemplateCombo.getSelectedIndex() == 4) {
            scriptArea.setText("""
                    var secret = 'CHANGE_ME';
                    var raw = request.getMethod()
                            + request.getPath()
                            + request.getHeader('Timestamp')
                            + content;
                    return Hash.hmacSha256(raw, secret);""");
        } else if (scriptTemplateCombo.getSelectedIndex() == 5) {
            scriptArea.setText("""
                    var obj = JSON.parse(content || '{}');
                    obj.debug = false;
                    obj.updatedAt = String(Date.now());
                    return JSON.stringify(obj);""");
        } else if (scriptTemplateCombo.getSelectedIndex() == 6) {
            scriptArea.setText("""
                    ctx.setSharedData('lastContent', content);
                    return content;""");
        }
    }

    private int addPlaygroundNote(JPanel panel, GridBagConstraints gbc, int row, String text) {
        JTextArea note = playgroundNote(text);
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        panel.add(note, gbc);
        gbc.gridwidth = 1;
        return row + 1;
    }

    private JTextArea playgroundNote(String text) {
        JTextArea note = new JTextArea(text);
        note.setEditable(false);
        note.setLineWrap(true);
        note.setWrapStyleWord(true);
        note.setOpaque(true);
        note.setBackground(UIStyle.surface());
        note.setForeground(UIStyle.mutedText());
        note.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIStyle.border()),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)
        ));
        note.setFont(note.getFont().deriveFont(12f));
        Dimension preferred = note.getPreferredSize();
        note.setMaximumSize(new Dimension(Integer.MAX_VALUE, preferred.height));
        return note;
    }
    
    private JPanel createIOPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 2, 10, 0));
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
        
        // Input
        JPanel left = new JPanel(new BorderLayout());
        left.setBorder(UIStyle.sectionBorder(lang.getString("playground.input")));
        left.setBackground(UIStyle.background());
        inputArea = new JTextArea();
        inputArea.setLineWrap(false);
        inputArea.setWrapStyleWord(false);
        UIStyle.styleTextArea(inputArea, true);
        left.add(UIStyle.scroll(inputArea), BorderLayout.CENTER);
        
        // Output
        JPanel right = new JPanel(new BorderLayout());
        right.setBorder(UIStyle.sectionBorder(lang.getString("playground.output")));
        right.setBackground(UIStyle.background());
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setLineWrap(false);
        outputArea.setWrapStyleWord(false);
        UIStyle.styleTextArea(outputArea, true);
        right.add(UIStyle.scroll(outputArea), BorderLayout.CENTER);
        
        panel.add(left);
        panel.add(right);
        
        // Bottom Execute Button Panel
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        runButton = UIStyle.primaryButton(lang.getString("playground.btn.execute"));
        runButton.setIcon(UIStyle.icon(UIStyle.IconType.RUN));
        runButton.setFont(runButton.getFont().deriveFont(Font.BOLD, 14f));
        runButton.addActionListener(this::executeTest);
        
        statusLabel = UIStyle.mutedLabel("Ready");
        
        JPanel container = new JPanel(new BorderLayout());
        container.setOpaque(false);
        container.add(panel, BorderLayout.CENTER);
        
        JPanel btnContainer = new JPanel(new BorderLayout());
        btnContainer.setOpaque(false);
        btnContainer.add(runButton, BorderLayout.CENTER);
        btnContainer.add(statusLabel, BorderLayout.SOUTH);
        btnContainer.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
        
        container.add(btnContainer, BorderLayout.SOUTH);
        
        return container;
    }
    
    private JComboBox<String> signActionCombo;
    private JComboBox<String> signAlgorithmCombo;
    private JComboBox<String> signContentCombo;
    private JTextField signTargetHeaderField;
    private JTextField signKeyField;
    private JComboBox<String> signKeySourceCombo;
    private JComboBox<String> signProviderCombo;
    private JComboBox<String> signCipherFormatCombo;
    private JComboBox<String> signHashKeyPlacementCombo;
    private JComboBox<String> signHexCaseCombo;
    private JTextArea signCustomTemplateArea;
    private JTextArea signHeaderTemplatesArea;
    private JCheckBox signHttpRequestModeCheck;
    private JLabel signCustomTemplateLabel;
    private JScrollPane signCustomTemplateScroll;

    private void onProcessorTypeChanged(ActionEvent e) {
        String type = (String) processorTypeCombo.getSelectedItem();
        if (type != null) {
            configCardLayout.show(configCardPanel, type);
        }
    }
    
    private void executeTest(ActionEvent e) {
        if (testWorker != null) return;
        try {
            String type = (String) processorTypeCombo.getSelectedItem();
            String input = inputArea.getText();
            String content = input;
            RawHttpRequest rawRequest = null;
            if ((Constants.ProcessorType.CRYPTO.equals(type) || Constants.ProcessorType.FIELD.equals(type))
                    && looksLikeRawHttpRequest(input)) {
                rawRequest = parseRawHttpRequest(input);
                content = rawRequest.body;
            }

            ProcessingAction action = new ProcessingAction();
            action.setProcessor(type);
            action.setTargetType(Constants.TargetType.BODY); // Dummy
            action.setEnabled(true);
            
            // Build Config
            Map<String, Object> config = new HashMap<>();
            
            if (Constants.ProcessorType.CRYPTO.equals(type)) {
                action.setActionType((String) actionCombo.getSelectedItem());
                config.put(ConfigKey.ALGORITHM, algorithmCombo.getSelectedItem());
                config.put(ConfigKey.KEY_VALUE, keyField.getText());
                config.put(ConfigKey.IV_LITERAL_VALUE, ivField.getText()); 
                config.put(ConfigKey.CRYPTO_PROVIDER, selectedValue(providerCombo));
                
                // Key Source Logic
                String selectedSource = (String) keySourceCombo.getSelectedItem();
                if (lang.getString("playground.keysource.none").equals(selectedSource)) {
                    config.put(ConfigKey.KEY_SOURCE, "none");
                } else {
                    config.put(ConfigKey.KEY_SOURCE, "static");
                }
                
                // Defaults
                config.put(ConfigKey.CIPHER_FORMAT, "base64");
                config.put(ConfigKey.PLAIN_FORMAT, "plain");
                config.put(ConfigKey.CHARSET, "UTF-8");
            } else if (Constants.ProcessorType.SCRIPT.equals(type)) {
                if (looksLikeRawHttpRequest(input)) {
                    rawRequest = parseRawHttpRequest(input);
                    content = rawRequest.body;
                }
                action.setActionType("process"); // ScriptProcessor only handles process/execute/script*
                config.put(ConfigKey.SCRIPT_CODE, scriptArea.getText());
            } else if (Constants.ProcessorType.SIGNATURE.equals(type)) {
                if (signHttpRequestModeCheck != null
                        && signHttpRequestModeCheck.isSelected()
                        && looksLikeRawHttpRequest(input)) {
                    rawRequest = parseRawHttpRequest(input);
                    content = rawRequest.body;
                }

                action.setActionType((String) signActionCombo.getSelectedItem());
                action.setTargetType(Constants.TargetType.HEADER);
                action.setTargetName(emptyToDefault(signTargetHeaderField.getText(), "Sign"));
                config.put(ConfigKey.ALGORITHM, signAlgorithmCombo.getSelectedItem());
                config.put(ConfigKey.SIGN_CONTENT, signContentCombo.getSelectedItem());
                config.put(ConfigKey.CRYPTO_PROVIDER, selectedValue(signProviderCombo));
                config.put(ConfigKey.KEY_SOURCE, selectedValue(signKeySourceCombo));
                config.put(ConfigKey.KEY_VALUE, signKeyField.getText());
                config.put(ConfigKey.CIPHER_FORMAT, signCipherFormatCombo.getSelectedItem());
                config.put(ConfigKey.HASH_KEY_PLACEMENT, selectedValue(signHashKeyPlacementCombo));
                config.put(ConfigKey.SIGNATURE_HEX_CASE, signHexCaseCombo.getSelectedItem());
                config.put(ConfigKey.HEADER_TEMPLATES, parseHeaderTemplates(signHeaderTemplatesArea.getText()));
                
                if ("custom".equals(signContentCombo.getSelectedItem())) {
                    config.put(ConfigKey.CUSTOM_SIGN_TEMPLATE, signCustomTemplateArea.getText());
                }
            } else if (Constants.ProcessorType.FIELD.equals(type)) {
                action.setActionType((String) fieldOperationCombo.getSelectedItem());
                config.put(ConfigKey.OPERATION, fieldOperationCombo.getSelectedItem());
                config.put(ConfigKey.FIELD_PATH, fieldPathField.getText());
                config.put(ConfigKey.TO, fieldToValueField.getText());
                config.put(ConfigKey.FROM, fieldFromValueField.getText());
                config.put(ConfigKey.OVERWRITE, fieldOverwriteCheck.isSelected());
            }
            
            action.setConfig(config);
            
            // Context
            ProcessorContext context = rawRequest != null
                    ? ProcessorContext.forRequest(rawRequest.method, rawRequest.url, rawRequest.headers, "PLAYGROUND").build()
                    : ProcessorContext.builder()
                        .method("POST")
                        .url(new URL("http://localhost/playground"))
                        .isRequest(true)
                        .toolSource("PLAYGROUND")
                        .build();
                
            context.setBodyText(rawRequest != null ? rawRequest.body : content);
            String capturedContent = content;
            RawHttpRequest capturedRequest = rawRequest;
            runButton.setEnabled(false);
            statusLabel.setText(lang.getString("ui.task.running"));
            testWorker = UiTasks.start(() -> computeTest(action, capturedContent, context, capturedRequest),
                    result -> {
                        outputArea.setText(result.text());
                        outputArea.setCaretPosition(0);
                        outputArea.setForeground(result.success() ? UIStyle.text() : UIStyle.danger());
                        statusLabel.setText(lang.getString(result.success() ? "playground.status.success"
                                : "playground.status.failed") + " (" + result.time() + "ms)");
                    }, this::showTestError, () -> {
                        testWorker = null;
                        runButton.setEnabled(true);
                    });

        } catch (Exception ex) {
            showTestError(ex);
        }
    }

    private void showTestError(Exception ex) {
        logger.error(lang.getString("error.processing.failed"), ex);
        outputArea.setText(lang.getString("error.processing.failed") + "\n" + ex.getMessage());
        outputArea.setForeground(UIStyle.danger());
        statusLabel.setText(lang.getString("playground.status.failed"));
    }

    private TestOutput computeTest(ProcessingAction action, String content, ProcessorContext context,
                                   RawHttpRequest rawRequest) throws Exception {
        long start = System.nanoTime();
        ProcessorResult result = processorManager.process(action, content, context);
        long time = (System.nanoTime() - start) / 1_000_000;
        String text;
        if (!result.isSuccess()) text = lang.getString("error.processing.failed") + "\n" + result.getErrorMessage();
        else if (Constants.ProcessorType.SIGNATURE.equals(action.getProcessor())) {
            text = rawRequest != null ? formatSignatureHttpDryRun(action, rawRequest, result, context, content, time)
                    : formatSignatureResult(action, result, context, content, time);
        } else text = result.getProcessedContent();
        return new TestOutput(text, result.isSuccess(), time);
    }

    private record TestOutput(String text, boolean success, long time) {}

    private boolean looksLikeRawHttpRequest(String input) {
        if (input == null) {
            return false;
        }
        String firstLine = input.stripLeading().lines().findFirst().orElse("");
        return firstLine.matches("^[A-Z]+\\s+\\S+\\s+HTTP/\\d(?:\\.\\d)?$");
    }

    private RawHttpRequest parseRawHttpRequest(String input) throws Exception {
        String normalized = input.replace("\r\n", "\n").replace('\r', '\n');
        int separator = normalized.indexOf("\n\n");
        String head = separator >= 0 ? normalized.substring(0, separator) : normalized;
        String body = separator >= 0 ? normalized.substring(separator + 2) : "";

        String[] lines = head.split("\n", -1);
        if (lines.length == 0 || lines[0].trim().isEmpty()) {
            throw new IllegalArgumentException("Raw HTTP request is missing the request line");
        }

        String requestLine = lines[0].trim();
        String[] requestParts = requestLine.split("\\s+", 3);
        if (requestParts.length < 3) {
            throw new IllegalArgumentException("Invalid request line: " + requestLine);
        }

        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        String previousHeader = null;
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) {
                continue;
            }
            if ((line.startsWith(" ") || line.startsWith("\t")) && previousHeader != null) {
                headers.put(previousHeader, headers.get(previousHeader) + " " + line.trim());
                continue;
            }
            int idx = line.indexOf(':');
            if (idx <= 0) {
                continue;
            }
            String name = line.substring(0, idx).trim();
            String value = line.substring(idx + 1).trim();
            headers.put(name, value);
            previousHeader = name;
        }

        URL url = buildUrlFromRequestTarget(requestParts[1], headers);
        return new RawHttpRequest(requestParts[0], requestParts[1], requestParts[2], url, headers, body);
    }

    private URL buildUrlFromRequestTarget(String target, Map<String, String> headers) throws Exception {
        if (target.startsWith("http://") || target.startsWith("https://")) {
            return new URL(target);
        }

        String host = getHeader(headers, "Host");
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Raw HTTP request uses a relative target but has no Host header");
        }

        String path = target.startsWith("/") ? target : "/" + target;
        return new URL("https://" + host + path);
    }

    private String getHeader(Map<String, String> headers, String name) {
        if (headers == null || name == null) {
            return null;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private String emptyToDefault(String value, String defaultValue) {
        return value == null || value.trim().isEmpty() ? defaultValue : value.trim();
    }

    private Map<String, String> parseHeaderTemplates(String text) {
        if (text == null || text.trim().isEmpty()) {
            return new LinkedHashMap<>();
        }
        try {
            return objectMapper.readValue(text, new TypeReference<Map<String, String>>() {});
        } catch (Exception ex) {
            throw new IllegalArgumentException("Header Templates must be a JSON object, e.g. {\"Timestamp\":\"${timestamp}\"}", ex);
        }
    }

    private String formatHeaderTemplates(Object value) {
        if (value == null) {
            return "{}";
        }
        if (value instanceof String) {
            return (String) value;
        }
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return String.valueOf(value);
        }
    }

    private String formatSignatureResult(ProcessingAction action, ProcessorResult result,
                                         ProcessorContext context, String content, long time) {
        StringBuilder sb = new StringBuilder();
        sb.append("生成的签名: ").append(result.getProcessedContent()).append('\n');
        sb.append("耗时: ").append(time).append("ms\n\n");
        appendSignatureDebug(sb, action, result, context, content);
        return sb.toString();
    }

    private String formatSignatureHttpDryRun(ProcessingAction action, RawHttpRequest rawRequest, ProcessorResult result,
                                             ProcessorContext context, String content, long time) {
        StringBuilder sb = new StringBuilder();
        sb.append("解析到的请求\n");
        sb.append(rawRequest.method).append(' ').append(rawRequest.url).append('\n');
        sb.append("请求里的 Timestamp: ").append(emptyToDefault(getHeader(rawRequest.headers, "Timestamp"), "<missing>")).append('\n');
        sb.append("本次测试时间戳: ").append(context.getTimestamp()).append('\n');
        sb.append("内容长度: ").append(content != null ? content.length() : 0).append("\n");
        sb.append("耗时: ").append(time).append("ms\n\n");

        appendRuleMatchDiagnostics(sb, rawRequest);

        appendSignatureDebug(sb, action, result, context, content);

        sb.append("\n最终请求\n");
        sb.append(buildFinalHttpRequest(action, rawRequest, result));
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private void appendSignatureDebug(StringBuilder sb, ProcessingAction action, ProcessorResult result,
                                      ProcessorContext context, String content) {
        sb.append("生成的签名\n");
        sb.append(result.getProcessedContent()).append("\n\n");

        Object signedData = result.getMetadata("signedData");
        sb.append("签名前原文\n");
        sb.append(signedData != null ? signedData : "").append("\n\n");

        Object setHeaders = result.getMetadata("setHeaders");
        if (setHeaders instanceof Map<?, ?> && !((Map<?, ?>) setHeaders).isEmpty()) {
            sb.append("签名前生成的 Header\n");
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) setHeaders).entrySet()) {
                sb.append(entry.getKey()).append(": ").append(entry.getValue()).append('\n');
            }
            sb.append('\n');
        }

        String signContent = String.valueOf(action.getConfig(ConfigKey.SIGN_CONTENT, ""));
        String template = String.valueOf(action.getConfig(ConfigKey.CUSTOM_SIGN_TEMPLATE, ""));
        if ("custom".equalsIgnoreCase(signContent) && !template.isEmpty()) {
            sb.append("模板变量取值\n");
            Map<String, String> trace = TemplateEngine.trace(template, context, content);
            for (Map.Entry<String, String> entry : trace.entrySet()) {
                sb.append(entry.getKey()).append(" => ").append(entry.getValue()).append('\n');
            }
            sb.append('\n');
        }
    }

    private void appendRuleMatchDiagnostics(StringBuilder sb, RawHttpRequest rawRequest) {
        sb.append("规则匹配情况\n");
        if (ruleManager == null || matchEngine == null) {
            sb.append("当前测试台没有接入规则列表，无法展示匹配情况。\n\n");
            return;
        }

        RuleMatchEngine.MatchContext matchContext = RuleMatchEngine.createRequestContext(
                rawRequest.method,
                rawRequest.url,
                rawRequest.headers,
                rawRequest.body,
                "REPEATER"
        );

        List<ProcessingRule> rules = ruleManager.getRulesByPriority();
        if (rules.isEmpty()) {
            sb.append("当前还没有配置规则。\n\n");
            return;
        }

        List<RuleMatchEngine.MatchDiagnostic> diagnostics = matchEngine.diagnoseRules(rules, matchContext);
        long matchedCount = diagnostics.stream().filter(RuleMatchEngine.MatchDiagnostic::isMatched).count();
        sb.append("测试场景: Repeater 请求发送前\n");
        sb.append("匹配规则: ").append(matchedCount).append('/').append(diagnostics.size()).append("\n\n");

        for (RuleMatchEngine.MatchDiagnostic diagnostic : diagnostics) {
            sb.append(diagnostic.isMatched() ? "[匹配] " : "[跳过] ");
            sb.append(emptyToDefault(diagnostic.getRuleName(), diagnostic.getRuleId()));
            sb.append(" (").append(emptyToDefault(diagnostic.getRuleId(), "-")).append(")\n");
            sb.append("  ").append(diagnostic.getSummary()).append('\n');

            for (RuleMatchEngine.ConditionDiagnostic check : diagnostic.getChecks()) {
                sb.append("  ").append(check.isMatched() ? "[通过] " : "[未通过] ");
                sb.append(check.getName())
                        .append(" expected=").append(check.getExpected())
                        .append(" actual=").append(check.getActual())
                        .append(" - ").append(check.getMessage())
                        .append('\n');
            }

            if (diagnostic.isMatched()) {
                appendRequestActionPlan(sb, rules, diagnostic.getRuleId());
            }
            sb.append('\n');
        }
    }

    private void appendRequestActionPlan(StringBuilder sb, List<ProcessingRule> rules, String ruleId) {
        ProcessingRule rule = rules.stream()
                .filter(candidate -> ruleId != null && ruleId.equals(candidate.getId()))
                .findFirst()
                .orElse(null);
        if (rule == null || !rule.hasRequestActions()) {
            sb.append("  请求发送前没有要执行的步骤\n");
            return;
        }

        sb.append("  请求发送前会执行的步骤:\n");
        for (ProcessingAction action : rule.getRequestActions()) {
            String phase = action.getConfigString(ConfigKey.EXECUTION_PHASE, Constants.ExecutionPhase.SEND);
            boolean willRun = action.isEnabled() && actionPhaseMatches(action, Constants.ExecutionPhase.SEND);
            sb.append("    ").append(willRun ? "[执行] " : "[不执行] ")
                    .append(action.getActionType())
                    .append(" / ").append(action.getProcessor())
                    .append(" -> ").append(action.getTargetType());
            if (action.getTargetName() != null && !action.getTargetName().isBlank()) {
                sb.append(' ').append(action.getTargetName());
            }
            sb.append(" 时机=").append(phase);
            if (!action.isEnabled()) {
                sb.append(" 已禁用");
            }
            sb.append('\n');
        }
    }

    private boolean actionPhaseMatches(ProcessingAction action, String requiredPhase) {
        String configValue = action.getConfigString(ConfigKey.EXECUTION_PHASE);
        String value = (configValue == null || configValue.trim().isEmpty())
                ? Constants.ExecutionPhase.SEND
                : configValue;

        String required = requiredPhase != null
                ? requiredPhase.toLowerCase()
                : Constants.ExecutionPhase.SEND;

        return java.util.Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(token -> !token.isEmpty())
                .map(String::toLowerCase)
                .anyMatch(token -> token.equals(required) || token.equals(Constants.ExecutionPhase.ALWAYS));
    }

    @SuppressWarnings("unchecked")
    private String buildFinalHttpRequest(ProcessingAction action, RawHttpRequest rawRequest, ProcessorResult result) {
        LinkedHashMap<String, String> headers = new LinkedHashMap<>(rawRequest.headers);
        Object setHeaders = result.getMetadata("setHeaders");
        if (setHeaders instanceof Map<?, ?>) {
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) setHeaders).entrySet()) {
                putHeader(headers, String.valueOf(entry.getKey()), String.valueOf(entry.getValue()));
            }
        }

        if (Constants.TargetType.HEADER.equals(action.getTargetType())) {
            putHeader(headers, emptyToDefault(action.getTargetName(), "Sign"), result.getProcessedContent());
        }

        StringBuilder sb = new StringBuilder();
        sb.append(rawRequest.method).append(' ').append(rawRequest.target).append(' ').append(rawRequest.httpVersion).append('\n');
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            sb.append(entry.getKey()).append(": ").append(entry.getValue()).append('\n');
        }
        sb.append('\n');
        if (rawRequest.body != null && !rawRequest.body.isEmpty()) {
            sb.append(rawRequest.body);
        }
        return sb.toString();
    }

    private void putHeader(LinkedHashMap<String, String> headers, String name, String value) {
        for (String existing : headers.keySet()) {
            if (existing.equalsIgnoreCase(name)) {
                headers.put(existing, value);
                return;
            }
        }
        headers.put(name, value);
    }

    private static class RawHttpRequest {
        private final String method;
        private final String target;
        private final String httpVersion;
        private final URL url;
        private final LinkedHashMap<String, String> headers;
        private final String body;

        private RawHttpRequest(String method, String target, String httpVersion, URL url,
                               LinkedHashMap<String, String> headers, String body) {
            this.method = method;
            this.target = target;
            this.httpVersion = httpVersion;
            this.url = url;
            this.headers = headers;
            this.body = body;
        }
    }

    public void setInputText(String text) {
        if (inputArea != null) {
            inputArea.setText(text);
        }
    }

    /**
     * Import configuration from a ProcessingAction
     */
    public void importActionConfiguration(ProcessingAction action) {
        if (action == null) return;

        // 1. Set Processor Type
        String processorType = action.getProcessor();
        processorTypeCombo.setSelectedItem(processorType);

        // Switch card
        configCardLayout.show(configCardPanel, processorType);

        Map<String, Object> config = action.getConfig();
        if (config == null) return;

        // 2. Populate specific config
        if (Constants.ProcessorType.CRYPTO.equals(processorType)) {
            if (actionCombo != null) actionCombo.setSelectedItem(action.getActionType());
            if (algorithmCombo != null) algorithmCombo.setSelectedItem(config.get(Constants.ConfigKey.ALGORITHM));
            
            String keySource = (String) config.get(Constants.ConfigKey.KEY_SOURCE);
            if (keySourceCombo != null) {
                if ("none".equalsIgnoreCase(keySource)) {
                    keySourceCombo.setSelectedItem(lang.getString("playground.keysource.none"));
                    keyField.setEnabled(false);
                } else {
                    keySourceCombo.setSelectedItem(lang.getString("playground.keysource.static"));
                    keyField.setEnabled(true);
                }
            }
            
            if (keyField != null) keyField.setText((String) config.get(Constants.ConfigKey.KEY_VALUE));
            if (ivField != null) ivField.setText((String) config.get(Constants.ConfigKey.IV_LITERAL_VALUE));
            if (providerCombo != null) selectValue(providerCombo, stringValueOrDefault(config.get(Constants.ConfigKey.CRYPTO_PROVIDER), "internal"));

        } else if (Constants.ProcessorType.SCRIPT.equals(processorType)) {
            if (scriptArea != null) scriptArea.setText((String) config.get(Constants.ConfigKey.SCRIPT_CODE));

        } else if (Constants.ProcessorType.SIGNATURE.equals(processorType)) {
            if (signActionCombo != null) signActionCombo.setSelectedItem(action.getActionType());
            if (signAlgorithmCombo != null) signAlgorithmCombo.setSelectedItem(config.get(Constants.ConfigKey.ALGORITHM));
            if (signContentCombo != null) signContentCombo.setSelectedItem(config.get(Constants.ConfigKey.SIGN_CONTENT));
            if (signTargetHeaderField != null) signTargetHeaderField.setText(action.getTargetName() != null ? action.getTargetName() : "Sign");
            if (signKeySourceCombo != null) selectValue(signKeySourceCombo, stringValueOrDefault(config.get(Constants.ConfigKey.KEY_SOURCE), "static"));
            if (signKeyField != null) signKeyField.setText((String) config.get(Constants.ConfigKey.KEY_VALUE));
            if (signProviderCombo != null) selectValue(signProviderCombo, stringValueOrDefault(config.get(Constants.ConfigKey.CRYPTO_PROVIDER), "internal"));
            if (signCipherFormatCombo != null) signCipherFormatCombo.setSelectedItem(stringValueOrDefault(config.get(Constants.ConfigKey.CIPHER_FORMAT), "hex"));
            if (signHashKeyPlacementCombo != null) selectValue(signHashKeyPlacementCombo, stringValueOrDefault(config.get(Constants.ConfigKey.HASH_KEY_PLACEMENT), "suffix"));
            if (signHexCaseCombo != null) signHexCaseCombo.setSelectedItem(stringValueOrDefault(config.get(Constants.ConfigKey.SIGNATURE_HEX_CASE), "lower"));
            if (signCustomTemplateArea != null) signCustomTemplateArea.setText((String) config.get(Constants.ConfigKey.CUSTOM_SIGN_TEMPLATE));
            if (signHeaderTemplatesArea != null) signHeaderTemplatesArea.setText(formatHeaderTemplates(config.get(Constants.ConfigKey.HEADER_TEMPLATES)));
            
            updateSignatureTemplateVisibility();
            updateSignatureKeyVisibility();

        } else if (Constants.ProcessorType.FIELD.equals(processorType)) {
            if (fieldOperationCombo != null) fieldOperationCombo.setSelectedItem(action.getActionType());
            if (fieldPathField != null) fieldPathField.setText((String) config.get(Constants.ConfigKey.FIELD_PATH));
            if (fieldToValueField != null) fieldToValueField.setText((String) config.get(Constants.ConfigKey.TO));
            if (fieldFromValueField != null) fieldFromValueField.setText((String) config.get(Constants.ConfigKey.FROM));
            
            Object overwrite = config.get(Constants.ConfigKey.OVERWRITE);
            boolean isOverwrite = overwrite instanceof Boolean && (Boolean) overwrite;
            if (fieldOverwriteCheck != null) fieldOverwriteCheck.setSelected(isOverwrite);
        }
        
        statusLabel.setText(lang.getString("playground.status.imported"));
    }

    private String stringValueOrDefault(Object value, String defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        String text = value.toString();
        return text.isEmpty() ? defaultValue : text;
    }

    private String selectedValue(JComboBox<String> combo) {
        return rawOption(String.valueOf(combo.getSelectedItem()));
    }

    private void selectValue(JComboBox<String> combo, String rawValue) {
        for (int i = 0; i < combo.getItemCount(); i++) {
            if (rawValue.equalsIgnoreCase(rawOption(combo.getItemAt(i)))) {
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
            case "不拼接密钥": return "none";
            case "追加密钥": return "suffix";
            case "前置密钥": return "prefix";
            case "前后都拼接": return "both";
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
