package com.universal.crypto.ui.processor;

import com.universal.crypto.util.LanguageManager;
import com.universal.crypto.ui.CollapsibleSection;

import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

public class ScriptConfigPanel implements ProcessorConfigUI {

    private final JPanel panel;
    private final JTextArea scriptCodeArea;
    private final JTextArea tipsArea;
    private final JComboBox<String> guideCombo;
    private final JTextArea guideArea;
    private final JComboBox<String> templateCombo;
    private final JTextArea referenceArea;



    public ScriptConfigPanel() {
        panel = new JPanel(new GridBagLayout());
        panel.setBackground(ProcessorUIStyle.background());
        panel.setBorder(ProcessorUIStyle.pageBorder());

        tipsArea = ProcessorUIStyle.note(ScriptHelp.text("tips"));

        GridBagConstraints gbc = ProcessorUIStyle.gbc();
        
        int row = 0;
        
        gbc.gridx = 0; gbc.gridy = row;
        gbc.gridwidth = 2;
        panel.add(tipsArea, gbc);
        gbc.gridwidth = 1;
        row++;

        JPanel helpContent = new JPanel();
        helpContent.setLayout(new BoxLayout(helpContent, BoxLayout.Y_AXIS));
        helpContent.setOpaque(false);
        guideCombo = new JComboBox<>(ScriptHelp.topics());
        guideCombo.addActionListener(e -> updateGuideText());

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        JLabel guideLabel = new JLabel(LanguageManager.getInstance().getString("script.help.label"));
        guideLabel.setForeground(ProcessorUIStyle.text());
        helpContent.add(guideLabel);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        helpContent.add(guideCombo);
        row++;

        guideArea = ProcessorUIStyle.note("");
        guideArea.setRows(10);
        guideArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        helpContent.add(guideArea);
        row++;
        updateGuideText();

        templateCombo = new JComboBox<>(ScriptHelp.templates());
        JButton applyTemplateButton = new JButton(LanguageManager.getInstance().getString("script.help.apply"));
        ProcessorUIStyle.styleButton(applyTemplateButton);
        applyTemplateButton.addActionListener(e -> applySelectedTemplate());

        JPanel templatePanel = new JPanel(new BorderLayout(8, 0));
        templatePanel.setOpaque(false);
        templatePanel.add(templateCombo, BorderLayout.CENTER);
        templatePanel.add(applyTemplateButton, BorderLayout.EAST);

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        JLabel templateLabel = new JLabel(LanguageManager.getInstance().getString("script.help.templates"));
        templateLabel.setForeground(ProcessorUIStyle.text());
        panel.add(templateLabel, gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        panel.add(templatePanel, gbc);
        row++;

        referenceArea = ProcessorUIStyle.note(scriptReferenceText());
        referenceArea.setRows(12);
        referenceArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        helpContent.add(referenceArea);
        row++;

        JPanel helperPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        helperPanel.setOpaque(false);
        addSnippetButton(helperPanel, "content", "content");
        addSnippetButton(helperPanel, "Header", "request.getHeader('Timestamp')");
        addSnippetButton(helperPanel, "Path", "request.getPath()");
        addSnippetButton(helperPanel, "Query", "request.getQuery()");
        addSnippetButton(helperPanel, "QueryParam", "request.getQueryParam('a')");
        addSnippetButton(helperPanel, "Hash", "Hash.sha256(content)");
        addSnippetButton(helperPanel, "Base64", "Base64.decode(content)");
        addSnippetButton(helperPanel, "JSON", "var obj = JSON.parse(content);\nreturn JSON.stringify(obj);");
        addSnippetButton(helperPanel, "Cache", "ctx.setSharedData('name', content);\nreturn content;");

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        JLabel helperLabel = new JLabel(LanguageManager.getInstance().getString("script.help.snippets"));
        helperLabel.setForeground(ProcessorUIStyle.text());
        panel.add(helperLabel, gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        panel.add(helperPanel, gbc);
        row++;

        // Fields
        scriptCodeArea = new JTextArea(14, 56);
        scriptCodeArea.setLineWrap(false);
        ProcessorUIStyle.styleTextArea(scriptCodeArea, true);
        scriptCodeArea.setText(defaultScript());
        JScrollPane scriptScroll = new JScrollPane(scriptCodeArea);
        
        gbc.gridx = 0; 
        gbc.gridy = row;
        gbc.gridwidth = 2;
        JLabel codeLabel = new JLabel(LanguageManager.getInstance().getString("script.help.code"));
        codeLabel.setForeground(ProcessorUIStyle.text());
        panel.add(codeLabel, gbc);
        row++;
        
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(scriptScroll, gbc);
        gbc.gridy = ++row;
        gbc.weighty = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(new CollapsibleSection(ScriptHelp.text("label"), helpContent), gbc);
    }

    private void addSnippetButton(JPanel helperPanel, String label, String snippet) {
        JButton button = new JButton(label);
        button.setToolTipText(snippet.replace("\n", " "));
        ProcessorUIStyle.styleButton(button);
        button.addActionListener(e -> {
            scriptCodeArea.replaceSelection(snippet);
            scriptCodeArea.requestFocusInWindow();
        });
        helperPanel.add(button);
    }

    private String scriptReferenceText() { return ScriptHelp.text("reference"); }

    private void updateGuideText() {
        if (guideArea != null && guideCombo != null) guideArea.setText(ScriptHelp.guide(guideCombo.getSelectedIndex()));
    }

    private String defaultScript() { return ScriptHelp.text("default"); }

    private void applySelectedTemplate() {
        int selected = templateCombo.getSelectedIndex();
        if (selected == 1) {
            scriptCodeArea.setText(defaultScript());
        } else if (selected == 2) {
            scriptCodeArea.setText("""
                    // 把当前输入做 Base64 解码，然后写回目标。
                    return Base64.decode(content);""");
        } else if (selected == 3) {
            scriptCodeArea.setText("""
                    // 基础页这样配：
                    //   要做什么 = sign
                    //   结果写回到 = header
                    //   目标名称 = X-Signature
                    //
                    // 这里返回的字符串会成为 X-Signature 的值。
                    var timestamp = request.getHeader('Timestamp') || '';
                    return Hash.sha256(timestamp + content);""");
        } else if (selected == 4) {
            scriptCodeArea.setText("""
                    // 基础页这样配：
                    //   要做什么 = sign
                    //   结果写回到 = header
                    //   目标名称 = X-Signature
                    //
                    // 目标：X-Signature = HMAC-SHA256(secret, method + path + timestamp + body)
                    var secret = 'CHANGE_ME';
                    var raw = request.getMethod()
                            + request.getPath()
                            + request.getHeader('Timestamp')
                            + content;
                    return Hash.hmacSha256(raw, secret);""");
        } else if (selected == 5) {
            scriptCodeArea.setText("""
                    // 修改 JSON body。基础页通常选择：结果写回到 = body。
                    var obj = JSON.parse(content || '{}');
                    obj.debug = false;
                    obj.updatedAt = String(Date.now());
                    return JSON.stringify(obj);""");
        } else if (selected == 6) {
            scriptCodeArea.setText("""
                    // 把当前步骤结果保存给后续步骤，同时原样写回。
                    ctx.setSharedData('lastContent', content);
                    return content;""");
        }
    }

    @Override
    public JPanel getPanel() {
        return panel;
    }

    @Override
    public void loadConfig(ProcessingAction action) {
        Map<String, Object> config = action.getConfig();
        if (config == null) config = new HashMap<>();

        scriptCodeArea.setText(stringValue(config.get(ConfigKey.SCRIPT_CODE)));
    }

    @Override
    public void saveConfig(ProcessingAction action) {
        Map<String, Object> config = action.getConfig();
        if (config == null) {
            config = new HashMap<>();
            action.setConfig(config);
        }
        
        config.put(ConfigKey.SCRIPT_CODE, scriptCodeArea.getText());
    }

    @Override
    public boolean validateConfig() {
        if (scriptCodeArea.getText() == null || scriptCodeArea.getText().trim().isEmpty()) {
            JOptionPane.showMessageDialog(panel,
                    ScriptHelp.text("empty.hint"),
                    ScriptHelp.text("empty.title"),
                    JOptionPane.WARNING_MESSAGE);
            scriptCodeArea.requestFocusInWindow();
            return false;
        }
        return true;
    }

    private String stringValue(Object obj) {
        return obj == null ? "" : obj.toString();
    }
}
