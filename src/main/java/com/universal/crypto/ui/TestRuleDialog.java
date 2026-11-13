package com.universal.crypto.ui;

import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.util.TemplateEngine;

import com.universal.crypto.util.LanguageManager;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Dialog for testing processing actions (Dry Run).
 */
public class TestRuleDialog extends JDialog {

    private final LanguageManager lang = LanguageManager.getInstance();
    private final ProcessingAction action;
    private JTextArea inputBodyArea;
    private JTextArea inputHeadersArea;
    private JTextArea resultArea;

    public TestRuleDialog(Dialog owner, ProcessingAction action) {
        super(owner, LanguageManager.getInstance().getString("test.dialog.title"), true);
        this.action = action;
        setSize(860, 620);
        setMinimumSize(new Dimension(760, 540));
        setLocationRelativeTo(owner);
        setLayout(new BorderLayout());
        getContentPane().setBackground(UIStyle.background());

        add(createHeader(), BorderLayout.NORTH);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                createInputPanel(), createResultPanel());
        SplitPaneLayout.initialize(splitPane, 0.46);
        splitPane.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 12));
        add(splitPane, BorderLayout.CENTER);

        add(createButtonPanel(), BorderLayout.SOUTH);
    }

    private JPanel createHeader() {
        JPanel panel = new JPanel(new BorderLayout(8, 4));
        panel.setBackground(UIStyle.background());
        panel.setBorder(BorderFactory.createEmptyBorder(14, 16, 10, 16));

        JLabel title = UIStyle.sectionTitle(lang.getString("test.dialog.title"));
        panel.add(title, BorderLayout.NORTH);
        panel.add(UIStyle.mutedLabel(lang.getString("test.help")), BorderLayout.CENTER);
        return panel;
    }

    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        panel.setBackground(UIStyle.surface());
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UIStyle.border()),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
        ));

        JButton runButton = UIStyle.primaryButton(lang.getString("test.btn.run"));
        runButton.setIcon(UIStyle.icon(UIStyle.IconType.RUN));
        runButton.addActionListener(e -> runTest());
        JButton closeButton = UIStyle.button(lang.getString("btn.close"));
        closeButton.addActionListener(e -> dispose());

        panel.add(runButton);
        panel.add(closeButton);
        return panel;
    }

    private JPanel createInputPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 10));
        panel.setBackground(UIStyle.background());
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 12, 8));
        
        inputBodyArea = new JTextArea("{\"id\": 123, \"data\": \"test\"}");
        inputBodyArea.setLineWrap(true);
        inputBodyArea.setWrapStyleWord(true);
        UIStyle.styleTextArea(inputBodyArea, true);
        
        inputHeadersArea = new JTextArea("Content-Type: application/json\nX-Req-Id: abc-123");
        inputHeadersArea.setLineWrap(true);
        inputHeadersArea.setWrapStyleWord(true);
        UIStyle.styleTextArea(inputHeadersArea, true);
        
        JSplitPane vertical = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                wrapWithTitle(lang.getString("test.section.input_body"), UIStyle.scroll(inputBodyArea)),
                wrapWithTitle(lang.getString("test.section.input_headers"), UIStyle.scroll(inputHeadersArea)));
        SplitPaneLayout.initialize(vertical, 0.6);
        vertical.setBorder(null);
        
        panel.add(vertical, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createResultPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 10));
        panel.setBackground(UIStyle.background());
        panel.setBorder(BorderFactory.createEmptyBorder(0, 8, 12, 0));

        resultArea = new JTextArea();
        resultArea.setLineWrap(true);
        resultArea.setWrapStyleWord(true);
        resultArea.setEditable(false);
        UIStyle.styleTextArea(resultArea, true);
        resultArea.setText(lang.getString("test.empty"));
        
        panel.add(wrapWithTitle(lang.getString("test.section.trace"), UIStyle.scroll(resultArea)), BorderLayout.CENTER);
        return panel;
    }

    private JPanel wrapWithTitle(String title, JComponent comp) {
        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setBackground(UIStyle.background());
        JLabel l = UIStyle.sectionTitle(title);
        p.add(l, BorderLayout.NORTH);
        p.add(comp, BorderLayout.CENTER);
        return p;
    }

    private void runTest() {
        resultArea.setText("");
        StringBuilder log = new StringBuilder();
        
        String body = inputBodyArea.getText();
        Map<String, String> headers = parseHeaders(inputHeadersArea.getText());
        
        // Build mock context
        ProcessorContext context;
        try {
            context = ProcessorContext.builder()
                    .method("POST")
                    .url(new java.net.URL("http://example.com/api/test"))
                    .headers(headers)
                    .toolSource("TEST_TOOL")
                    .isRequest(true)
                    .build();
        } catch (java.net.MalformedURLException e) {
             resultArea.setText(lang.getString("test.error.context").replace("{0}", e.getMessage()));
             return;
        }

        log.append("=== 当前步骤 ===\n");
        log.append("要做什么: ").append(action.getActionType()).append("\n");
        log.append("算法: ").append(action.getConfig(ConfigKey.ALGORITHM)).append("\n\n");

        if ("sign".equalsIgnoreCase(action.getActionType())) {
            String template = (String) action.getConfig(ConfigKey.CUSTOM_SIGN_TEMPLATE);
            if (template != null) {
                log.append("=== 签名原文 ===\n");
                log.append("模板: ").append(template).append("\n\n");
                
                Map<String, String> trace = TemplateEngine.trace(template, context, body);
                
                log.append("--- 变量取值 ---\n");
                trace.forEach((k, v) -> log.append(String.format("%-30s => %s\n", k, v)));
                
                log.append("\n--- 最终参与签名的字符串 ---\n");
                String finalString = TemplateEngine.process(template, context, body);
                log.append(finalString).append("\n");
                
                if ("true".equalsIgnoreCase((String)action.getConfig(ConfigKey.SORT_KEYS))) {
                    log.append("\n--- 参数整理 ---\n");
                    // Assuming SignatureProcessor canonical Logic... 
                    // Ideally we should invoke SignatureProcessor logic here, but for dry run 
                    // let's trust the engine or just show what we have.
                    // Since Canonicalization logic is inside SignatureProcessor, we can't easily call it 
                    // without instantiation. 
                    // Future improvement: Move canonicalization to Utility.
                    log.append("这里仅展示模板取值；完整签名结果请使用“步骤流预览”或主测试台。");
                }
            } else {
                log.append("当前没有配置签名原文模板，将使用动作里的默认签名内容。\n");
            }
        } else {
             log.append("这个窗口主要用于查看签名模板变量。加解密链路请使用“步骤流预览”。\n");
        }
        
        resultArea.setText(log.toString());
    }

    private Map<String, String> parseHeaders(String text) {
        Map<String, String> map = new HashMap<>();
        for (String line : text.split("\n")) {
            int idx = line.indexOf(":");
            if (idx > 0) {
                map.put(line.substring(0, idx).trim(), line.substring(idx + 1).trim());
            }
        }
        return map;
    }
}
