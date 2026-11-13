package com.universal.crypto.ui;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.universal.crypto.burp.UniversalCryptoExtension;
import com.universal.crypto.util.ExtensionSettings;
import com.universal.crypto.util.LanguageManager;
import com.universal.crypto.util.Logger.LogLevel;
import com.universal.crypto.util.DebugUtil;
import com.universal.crypto.util.Logger;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Panel for extension settings and configuration
 */
public class SettingsPanel extends JPanel {

    private static final Logger logger = Logger.getInstance();
    private final LanguageManager lang = LanguageManager.getInstance();

    private final MontoyaApi api;
    private final UniversalCryptoExtension extension;
    private final Runnable textChangeCallback;

    // UI Components
    private JComboBox<String> languageComboBox;
    private JComboBox<String> logLevelComboBox;
    private JCheckBox debugModeCheckBox;
    private JCheckBox fileLoggingCheckBox;
    private JTextField logDirectoryField;
    private JButton browseLogDirectoryButton;
    private JLabel logStatusLabel;
    private JTextField apiEndpointField;
    private JSpinner apiTimeoutSpinner;
    private JLabel apiStatusLabel;
    private JButton exportConfigButton;
    private JButton importConfigButton;
    private JButton resetConfigButton;
    private JTextArea configPreviewArea;

    // Constructor with callback
    public SettingsPanel(MontoyaApi api, UniversalCryptoExtension extension, Runnable textChangeCallback) {
        this.api = api;
        this.extension = extension;
        this.textChangeCallback = textChangeCallback;

        rebuildUI();
        loadCurrentSettings(); 
        logger.debug("SettingsPanel initialized");
    }

    // Constructor for backward compatibility (if needed by other code)
    public SettingsPanel(MontoyaApi api, UniversalCryptoExtension extension) {
        this(api, extension, null);
    }

    public void rebuildUI() {
        this.removeAll();
        setLayout(new BorderLayout());
        setBorder(UIStyle.emptyBorder());
        setBackground(UIStyle.background());

        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBackground(UIStyle.background());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(0, 0, 12, 0);
        gbc.anchor = GridBagConstraints.NORTHWEST;

        // General settings (Language)
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        mainPanel.add(createGeneralSettingsPanel(), gbc);

        // Logging settings section
        gbc.gridy = 1;
        mainPanel.add(createLoggingSettingsPanel(), gbc);

        // API settings section
        gbc.gridy = 2;
        mainPanel.add(createApiSettingsPanel(), gbc);

        // Configuration management section
        gbc.gridy = 3;
        mainPanel.add(createConfigManagementPanel(), gbc);

        // Configuration preview section
        gbc.gridy = 4;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 1.0;
        mainPanel.add(createConfigPreviewPanel(), gbc);

        JScrollPane scrollPane = UIStyle.scroll(mainPanel);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        add(scrollPane, BorderLayout.CENTER);

        add(createButtonsPanel(), BorderLayout.SOUTH);

        this.revalidate();
        this.repaint();
    }
    
    // ... createGeneralSettingsPanel, createLoggingSettingsPanel, createApiSettingsPanel ...
    // reusing existing implementation via copy-paste or simple re-implementation
    // effectively full file write needed, so I will include full methods to avoid breakage

    private JPanel createGeneralSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(UIStyle.sectionBorder(lang.getString("settings.group.general")));
        panel.setBackground(UIStyle.background());
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.gridwidth = 2;
        panel.add(helpText(isZh() ? "语言会立即刷新插件 UI。规则和签名配置不会因为切换语言而改变。" :
                "Language refreshes the extension UI immediately. Rules and signing configuration are not changed."), gbc);

        gbc.gridwidth = 1;
        gbc.gridx = 0; gbc.gridy = 1;
        gbc.weightx = 0.0;
        panel.add(new JLabel(lang.getString("settings.label.language")), gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        languageComboBox = new JComboBox<>(new String[]{"English (en)", "Chinese (中文)"});
        languageComboBox.addActionListener(e -> updateConfigPreview()); 
        languageComboBox.setToolTipText(isZh() ? "只影响插件界面显示语言。" : "Only changes the extension UI language.");
        panel.add(languageComboBox, gbc);
        
        return panel;
    }

    private JPanel createLoggingSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(UIStyle.sectionBorder(lang.getString("settings.group.logging")));
        panel.setBackground(UIStyle.background());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        boolean isZh = isZh();

        gbc.gridx = 0; gbc.gridy = 0;
        gbc.gridwidth = 3;
        panel.add(helpText(isZh
                ? "日志用于排查规则匹配、签名失败、脚本异常。日常建议 INFO；排错时临时切到 DEBUG。"
                : "Logging helps diagnose rule matching, signing failures, and script errors. INFO is recommended; switch to DEBUG temporarily when debugging."), gbc);

        gbc.gridwidth = 1;
        gbc.gridx = 0; gbc.gridy = 1;
        gbc.weightx = 0.0;
        panel.add(new JLabel(lang.getString("settings.label.log_level")), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        logLevelComboBox = new JComboBox<>(new String[]{
            LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR
        });
        logLevelComboBox.setToolTipText(isZh ? "DEBUG 会产生更多日志，适合短时间排错。" : "DEBUG produces verbose logs and is best used temporarily.");
        logLevelComboBox.addActionListener(this::updateLogLevel);
        panel.add(logLevelComboBox, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        gbc.gridwidth = 2;
        debugModeCheckBox = new JCheckBox(isZh ? "开启调试模式" : "Enable Debug Mode");
        debugModeCheckBox.setText(isZh ? "开启调试模式" : "Enable Debug Mode");
        debugModeCheckBox.setOpaque(false);
        debugModeCheckBox.setToolTipText(isZh ? "打开后会输出更多运行细节，可能影响性能。" : "Outputs more runtime details and may affect performance.");
        debugModeCheckBox.addActionListener(this::toggleDebugMode);
        panel.add(debugModeCheckBox, gbc);

        gbc.gridy = 3;
        fileLoggingCheckBox = new JCheckBox(lang.getString("settings.check.enable_file_logging"));
        fileLoggingCheckBox.setOpaque(false);
        fileLoggingCheckBox.setToolTipText(isZh ? "开启后日志会写入指定目录，便于复盘问题。" : "Writes logs to the selected directory for later diagnosis.");
        fileLoggingCheckBox.addActionListener(this::toggleFileLogging);
        panel.add(fileLoggingCheckBox, gbc);

        gbc.gridwidth = 1;
        gbc.gridx = 0; gbc.gridy = 4;
        panel.add(new JLabel(lang.getString("settings.label.log_file")), gbc);

        gbc.gridx = 1;
        logDirectoryField = new JTextField(30);
        logDirectoryField.setEditable(false); 
        panel.add(logDirectoryField, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0.0;
        browseLogDirectoryButton = UIStyle.button(isZh ? "浏览..." : "Browse...");
        browseLogDirectoryButton.addActionListener(this::browseLogDirectory);
        panel.add(browseLogDirectoryButton, gbc);

        gbc.gridx = 1; gbc.gridy = 5;
        gbc.gridwidth = 2;
        logStatusLabel = UIStyle.mutedLabel("");
        panel.add(logStatusLabel, gbc);

        return panel;
    }

    private JPanel createApiSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(UIStyle.sectionBorder(lang.getString("settings.group.api")));
        panel.setBackground(UIStyle.background());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        boolean isZh = isZh();

        gbc.gridx = 0; gbc.gridy = 0;
        gbc.gridwidth = 2;
        panel.add(helpText(isZh
                ? "只有选择“调用外部服务”或“从接口查询密钥”时，才需要配置这里。本地计算不依赖这个地址。"
                : "API URL is only used by external crypto/signing services or key lookup. Local internal algorithms do not depend on this."), gbc);

        gbc.gridwidth = 1;
        gbc.gridx = 0; gbc.gridy = 1;
        gbc.weightx = 0.0;
        panel.add(new JLabel(isZh ? "外部服务地址:" : "API URL:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        apiEndpointField = new JTextField("http://localhost:8080/api", 35);
        apiEndpointField.setToolTipText(isZh ? "必须是 http:// 或 https:// 开头的完整地址。" : "Must be a full http:// or https:// URL.");
        apiEndpointField.getDocument().addDocumentListener(simpleDocumentListener(this::updateConfigPreview));
        panel.add(apiEndpointField, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        gbc.weightx = 0.0;
        panel.add(new JLabel(isZh ? "请求超时 (ms):" : "Timeout (ms):"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.NONE;
        apiTimeoutSpinner = new JSpinner(new SpinnerNumberModel(30000, 1000, 120000, 1000));
        apiTimeoutSpinner.setToolTipText(isZh ? "外部 API 请求超时时间。推荐 10000-30000ms。" : "Timeout for external API requests. 10000-30000ms is recommended.");
        apiTimeoutSpinner.addChangeListener(e -> updateConfigPreview());
        JComponent editor = apiTimeoutSpinner.getEditor();
        if (editor instanceof JSpinner.DefaultEditor) {
             ((JSpinner.DefaultEditor)editor).getTextField().setColumns(8);
        }
        panel.add(apiTimeoutSpinner, gbc);

        gbc.gridx = 1; gbc.gridy = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        apiStatusLabel = UIStyle.mutedLabel("");
        panel.add(apiStatusLabel, gbc);

        return panel;
    }

    private JPanel createConfigManagementPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(UIStyle.sectionBorder(lang.getString("settings.group.config")));
        panel.setBackground(UIStyle.background());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;

        gbc.gridx = 0; gbc.gridy = 0;
        gbc.gridwidth = 2;
        panel.add(helpText(isZh()
                ? "这里导入/导出的是全局设置，例如语言、日志和外部 API 地址；规则请在规则管理页导入/导出。"
                : "This imports/exports global settings such as language, logging, and external API URL. Use Rule Management for rules."), gbc);

        gbc.gridwidth = 1;
        gbc.gridx = 0; gbc.gridy = 1;
        exportConfigButton = UIStyle.button(lang.getString("settings.btn.export"));
        exportConfigButton.setIcon(UIStyle.icon(UIStyle.IconType.EXPORT));
        exportConfigButton.addActionListener(this::exportConfiguration);
        panel.add(exportConfigButton, gbc);

        gbc.gridx = 1;
        importConfigButton = UIStyle.button(lang.getString("settings.btn.import"));
        importConfigButton.setIcon(UIStyle.icon(UIStyle.IconType.IMPORT));
        importConfigButton.addActionListener(this::importConfiguration);
        panel.add(importConfigButton, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        gbc.gridwidth = 2;
        resetConfigButton = UIStyle.dangerButton(lang.getString("settings.btn.reset"));
        resetConfigButton.addActionListener(this::resetConfiguration);
        panel.add(resetConfigButton, gbc);

        return panel;
    }

    private JPanel createConfigPreviewPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        boolean isZh = isZh();
        panel.setBorder(UIStyle.sectionBorder(isZh ? "配置摘要 / 健康检查" : "Configuration Summary / Health Check"));
        panel.setBackground(UIStyle.background());

        configPreviewArea = new JTextArea();
        configPreviewArea.setEditable(false);
        UIStyle.styleTextArea(configPreviewArea, true);

        JScrollPane scrollPane = UIStyle.scroll(configPreviewArea);
        scrollPane.setPreferredSize(new Dimension(600, 200));

        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createButtonsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        panel.setBackground(UIStyle.surface());
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, UIStyle.border()),
            BorderFactory.createEmptyBorder(10, 10, 0, 0)
        ));

        JButton applyButton = UIStyle.primaryButton(lang.getString("settings.btn.apply"));
        applyButton.addActionListener(this::applySettings);

        JButton cancelButton = UIStyle.button(lang.getString("settings.btn.discard"));
        cancelButton.addActionListener(this::cancelSettings);

        panel.add(cancelButton);
        panel.add(applyButton);

        return panel;
    }

    private boolean isZh() {
        return "zh".equals(lang.getCurrentLocale().getLanguage());
    }

    private JTextArea helpText(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setOpaque(true);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBackground(UIStyle.surface());
        area.setForeground(UIStyle.mutedText());
        area.setFont(area.getFont().deriveFont(12f));
        area.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIStyle.border()),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)
        ));
        return area;
    }

    private DocumentListener simpleDocumentListener(Runnable runnable) {
        return new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                runnable.run();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                runnable.run();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                runnable.run();
            }
        };
    }

    private String validateApiBaseUrl(String value) {
        if (value == null || value.trim().isEmpty()) {
            return isZh() ? "API URL 不能为空" : "API URL is required";
        }
        try {
            URI uri = URI.create(value.trim());
            String scheme = uri.getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return isZh() ? "API URL 必须以 http:// 或 https:// 开头" : "API URL must start with http:// or https://";
            }
            if (uri.getHost() == null || uri.getHost().trim().isEmpty()) {
                return isZh() ? "API URL 缺少 Host" : "API URL is missing a host";
            }
            return null;
        } catch (Exception e) {
            return isZh() ? "API URL 格式不正确" : "API URL is invalid";
        }
    }

    private String validateLogDirectory(String value) {
        if (!fileLoggingCheckBox.isSelected()) {
            return null;
        }
        if (value == null || value.trim().isEmpty()) {
            return isZh() ? "日志目录不能为空" : "Log directory is required";
        }
        try {
            Path path = Paths.get(value.trim());
            if (Files.exists(path) && !Files.isDirectory(path)) {
                return isZh() ? "日志路径不是目录" : "Log path is not a directory";
            }
            Path existing = Files.exists(path) ? path : path.getParent();
            if (existing != null && Files.exists(existing) && !Files.isWritable(existing)) {
                return isZh() ? "日志目录不可写" : "Log directory is not writable";
            }
            return null;
        } catch (Exception e) {
            return isZh() ? "日志目录路径不正确" : "Log directory path is invalid";
        }
    }

    private void updateLogControlState() {
        boolean enabled = fileLoggingCheckBox != null && fileLoggingCheckBox.isSelected();
        if (logDirectoryField != null) {
            logDirectoryField.setEnabled(enabled);
        }
        if (browseLogDirectoryButton != null) {
            browseLogDirectoryButton.setEnabled(enabled);
        }
    }

    private void updateStatusLabels() {
        if (apiStatusLabel != null) {
            String apiError = validateApiBaseUrl(apiEndpointField.getText());
            apiStatusLabel.setText(apiError == null
                    ? (isZh() ? "状态：API URL 格式有效" : "Status: API URL is valid")
                    : (isZh() ? "状态：" : "Status: ") + apiError);
            apiStatusLabel.setForeground(apiError == null ? UIStyle.success() : UIStyle.danger());
        }

        if (logStatusLabel != null) {
            String logError = validateLogDirectory(logDirectoryField.getText());
            if (!fileLoggingCheckBox.isSelected()) {
                logStatusLabel.setText(isZh() ? "状态：文件日志已关闭" : "Status: file logging is disabled");
                logStatusLabel.setForeground(UIStyle.mutedText());
            } else if (logError == null) {
                logStatusLabel.setText(isZh() ? "状态：日志目录可用或可创建" : "Status: log directory is usable or can be created");
                logStatusLabel.setForeground(UIStyle.success());
            } else {
                logStatusLabel.setText((isZh() ? "状态：" : "Status: ") + logError);
                logStatusLabel.setForeground(UIStyle.danger());
            }
        }
    }

    // Load current settings into UI
    private void loadCurrentSettings() {
        try {
            showSettings(ExtensionSettings.getInstance());
        } catch (Exception e) {
            logger.error("Failed to load current settings", e);
        }
    }

    void showSettings(ExtensionSettings settings) {
            String langCode = settings.getLanguage();
             if ("zh".equalsIgnoreCase(langCode)) {
                languageComboBox.setSelectedIndex(1);
            } else {
                languageComboBox.setSelectedIndex(0);
            }
            if (settings.getLogLevel() != null) {
                logLevelComboBox.setSelectedItem(settings.getLogLevel());
            }
            debugModeCheckBox.setSelected(settings.isDebugMode());
            fileLoggingCheckBox.setSelected(settings.isFileLoggingEnabled());
            logDirectoryField.setText(settings.getLogDirectory());
            apiEndpointField.setText(settings.getApiBaseUrl());
            apiTimeoutSpinner.setValue(settings.getApiTimeoutMs());
            updateLogControlState();
            updateConfigPreview();
    }

    private void updateConfigPreview() {
        try {
            StringBuilder preview = new StringBuilder();
            boolean isZh = isZh();
            updateLogControlState();
            updateStatusLabels();

            preview.append(isZh ? "当前未保存的配置摘要:\n" : "Pending Configuration Summary:\n");
            preview.append("=========================================\n\n");
            preview.append(isZh ? "通用:\n" : "General:\n");
            preview.append("  ").append(lang.getString("settings.label.language")).append(" ").append(languageComboBox.getSelectedItem()).append("\n\n");
            preview.append(isZh ? "日志:\n" : "Logging:\n");
            preview.append(isZh ? "  级别: " : "  Level: ").append(logLevelComboBox.getSelectedItem()).append("\n");
            preview.append(isZh ? "  调试模式: " : "  Debug: ").append(debugModeCheckBox.isSelected() ? (isZh ? "开启" : "on") : (isZh ? "关闭" : "off")).append("\n");
            preview.append(isZh ? "  保存到文件: " : "  File Log: ").append(fileLoggingCheckBox.isSelected() ? (isZh ? "开启" : "on") : (isZh ? "关闭" : "off")).append("\n");
            preview.append(isZh ? "  日志目录: " : "  Dir: ").append(logDirectoryField.getText()).append("\n\n");
            preview.append(isZh ? "外部服务:\n" : "API:\n");
            preview.append(isZh ? "  地址: " : "  URL: ").append(apiEndpointField.getText()).append("\n");
            preview.append(isZh ? "  超时: " : "  Timeout: ").append(apiTimeoutSpinner.getValue()).append("ms\n\n");
            preview.append(isZh ? "格式与路径检查:\n" : "Format and Path Checks:\n");
            String apiError = validateApiBaseUrl(apiEndpointField.getText());
            String logError = validateLogDirectory(logDirectoryField.getText());
            preview.append(isZh ? "  外部服务地址: " : "  API URL: ").append(apiError == null ? (isZh ? "格式有效（未连接验证）" : "Valid format (not connected)") : apiError).append("\n");
            preview.append(isZh ? "  日志目录: " : "  Log Directory: ").append(logError == null ? (isZh ? "可用" : "OK") : logError).append("\n\n");
            preview.append(isZh ? "插件状态:\n" : "System:\n");
            preview.append(isZh ? "  版本: " : "  Version: ").append(UniversalCryptoExtension.getVersion()).append("\n");
            preview.append(isZh ? "  可用能力: " : "  Processors: ").append(extension.getProcessorManager() != null ?
                extension.getProcessorManager().getProcessorCount() : 0).append("\n");

            configPreviewArea.setText(preview.toString());
            configPreviewArea.setCaretPosition(0);

        } catch (Exception e) {
            configPreviewArea.setText((isZh() ? "更新摘要失败: " : "Error updating preview: ") + e.getMessage());
        }
    }

    private void updateLogLevel(ActionEvent e) { updateConfigPreview(); }
    private void toggleDebugMode(ActionEvent e) { updateConfigPreview(); }
    private void toggleFileLogging(ActionEvent e) {
        updateLogControlState();
        updateConfigPreview();
    }

    private void browseLogDirectory(ActionEvent e) {
        if (!fileLoggingCheckBox.isSelected()) {
            return;
        }
        JFileChooser chooser = new JFileChooser(logDirectoryField.getText());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            logDirectoryField.setText(chooser.getSelectedFile().getAbsolutePath());
            updateConfigPreview();
        }
    }

    private void exportConfiguration(ActionEvent e) {
        // ... (Export implementation same as before) ...
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Files", "json"));
        chooser.setSelectedFile(new File("universal-crypto-settings.json"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                ExtensionSettings settings = pendingSettings();
                ObjectMapper mapper = new ObjectMapper();
                mapper.writerWithDefaultPrettyPrinter().writeValue(chooser.getSelectedFile(), settings);
                JOptionPane.showMessageDialog(this, lang.getString("settings.msg.saved"), "Export", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                logger.error("Failed to export configuration", ex);
                showConfigurationError(ex);
            }
        }
    }

    private void importConfiguration(ActionEvent e) {
        // ... (Import implementation same as before) ...
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Files", "json"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                ExtensionSettings loaded = mapper.readValue(chooser.getSelectedFile(), ExtensionSettings.class);
                validateImportedSettings(loaded);
                showSettings(loaded);
                JOptionPane.showMessageDialog(this, lang.getString("settings.msg.imported"), "Import", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                logger.error("Failed to import configuration", ex);
                showConfigurationError(ex);
            }
        }
    }

    private void showConfigurationError(Exception ex) {
        JOptionPane.showMessageDialog(this, ex.getMessage(), lang.getString("error.title"), JOptionPane.ERROR_MESSAGE);
    }

    void validateImportedSettings(ExtensionSettings loaded) {
        String error = validateApiBaseUrl(loaded.getApiBaseUrl());
        if (error != null) throw new IllegalArgumentException(error);
        if (loaded.getApiTimeoutMs() < 1000 || loaded.getApiTimeoutMs() > 120000)
            throw new IllegalArgumentException(lang.getString("settings.import.invalid_timeout"));
        if (!java.util.Arrays.asList("en", "zh").contains(loaded.getLanguage())
                || !java.util.Arrays.asList(LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR).contains(loaded.getLogLevel()))
            throw new IllegalArgumentException(lang.getString("settings.import.invalid_options"));
        if (loaded.isFileLoggingEnabled() && (loaded.getLogDirectory() == null || loaded.getLogDirectory().isBlank()))
            throw new IllegalArgumentException(lang.getString("settings.import.invalid_log_directory"));
    }

    ExtensionSettings pendingSettings() throws Exception {
        apiTimeoutSpinner.commitEdit();
        // Work with a detached settings object, never the live singleton before Apply.
        ObjectMapper mapper = new ObjectMapper();
        ExtensionSettings pending = mapper.readValue("{}", ExtensionSettings.class);
        pending.setLanguage(languageComboBox.getSelectedIndex() == 1 ? "zh" : "en");
        pending.setLogLevel((String) logLevelComboBox.getSelectedItem());
        pending.setDebugMode(debugModeCheckBox.isSelected());
        pending.setFileLoggingEnabled(fileLoggingCheckBox.isSelected());
        pending.setLogDirectory(logDirectoryField.getText().trim());
        pending.setApiBaseUrl(apiEndpointField.getText().trim());
        pending.setApiTimeoutMs(((Number) apiTimeoutSpinner.getValue()).intValue());
        return pending;
    }

    private void resetConfiguration(ActionEvent e) {
        if (JOptionPane.showConfirmDialog(this, lang.getString("settings.msg.confirm_reset"), "Reset", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
            logLevelComboBox.setSelectedItem(LogLevel.INFO);
            debugModeCheckBox.setSelected(false);
            fileLoggingCheckBox.setSelected(true);
            logDirectoryField.setText(System.getProperty("user.home") + "/.burp/universal-crypto-extension/logs");
            apiEndpointField.setText("http://localhost:8080/api");
            apiTimeoutSpinner.setValue(30000);
            languageComboBox.setSelectedIndex(0); 
            updateLogControlState();
            updateConfigPreview();
        }
    }

    private void applySettings(ActionEvent e) {
        try {
            apiTimeoutSpinner.commitEdit();
            String apiError = validateApiBaseUrl(apiEndpointField.getText());
            if (apiError != null) {
                JOptionPane.showMessageDialog(this, apiError, isZh() ? "API 配置错误" : "API Configuration Error", JOptionPane.WARNING_MESSAGE);
                apiEndpointField.requestFocusInWindow();
                return;
            }

            String logError = validateLogDirectory(logDirectoryField.getText());
            if (logError != null) {
                JOptionPane.showMessageDialog(this, logError, isZh() ? "日志配置错误" : "Logging Configuration Error", JOptionPane.WARNING_MESSAGE);
                logDirectoryField.requestFocusInWindow();
                return;
            }

            ExtensionSettings settings = ExtensionSettings.getInstance();
            
            // Language Check
            String selectedItemCode = languageComboBox.getSelectedIndex() == 1 ? "zh" : "en";
            boolean langChanged = !selectedItemCode.equals(settings.getLanguage());
            
            ExtensionSettings pending = pendingSettings();
            validateImportedSettings(pending);
            if (pending.isFileLoggingEnabled()) Files.createDirectories(Paths.get(pending.getLogDirectory()));
            pending.saveOrThrow();
            // Publish runtime settings only after the complete configuration is persisted.
            settings.setLanguage(pending.getLanguage());
            settings.setLogLevel(pending.getLogLevel());
            settings.setDebugMode(pending.isDebugMode());
            settings.setFileLoggingEnabled(pending.isFileLoggingEnabled());
            settings.setLogDirectory(pending.getLogDirectory());
            settings.setApiBaseUrl(pending.getApiBaseUrl());
            settings.setApiTimeoutMs(pending.getApiTimeoutMs());

            // Apply language immediately for this panel
            if (langChanged) {
                lang.setLanguage(selectedItemCode);
                rebuildUI(); 
                loadCurrentSettings(); 
                
                // NOTIFY OTHER PANELS
                if (textChangeCallback != null) {
                    textChangeCallback.run();
                }
            }

            // Apply Runtime Changes
            Logger.getInstance().initialize(settings.getLogLevel(), true, settings.isFileLoggingEnabled(), settings.getLogDirectory());
            DebugUtil.setDebugMode(settings.isDebugMode());

            updateConfigPreview();

            String msg = lang.getString("settings.msg.saved");
            JOptionPane.showMessageDialog(this, msg, lang.getString("settings.btn.apply"), JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void cancelSettings(ActionEvent e) {
        loadCurrentSettings();
    }

    public void refresh() {
        try {
            ExtensionSettings pending = pendingSettings();
            rebuildUI();
            showSettings(pending);
        } catch (Exception ex) { logger.error("Failed to refresh settings form", ex); }
    }
}
