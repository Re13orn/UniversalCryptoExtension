package com.universal.crypto.ui;

import com.universal.crypto.engine.StepFlowPreviewService;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorFactory;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.util.LanguageManager;

import javax.swing.*;
import java.awt.*;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/**
 * Interactive dry-run dialog for a complete request/response step flow.
 */
public class StepFlowPreviewDialog extends JDialog {

    private static final int PREVIEW_LIMIT = 2400;

    private final LanguageManager lang = LanguageManager.getInstance();
    private final List<ProcessingAction> actions;
    private final boolean requestFlow;
    private final StepFlowPreviewService previewService;
    private final InitialData initialData;

    private JTextField methodField;
    private JTextField urlField;
    private JComboBox<String> phaseBox;
    private JTextArea headersArea;
    private JTextArea requestHeadersArea;
    private JTextArea bodyArea;
    private JTextArea traceArea;
    private JButton runButton;
    private SwingWorker<StepFlowPreviewService.PreviewResult, Void> previewWorker;

    public StepFlowPreviewDialog(Window owner, List<ProcessingAction> actions, boolean requestFlow) {
        this(owner, actions, requestFlow, null);
    }

    public StepFlowPreviewDialog(Window owner, List<ProcessingAction> actions, boolean requestFlow, InitialData initialData) {
        super(owner, LanguageManager.getInstance().getString("flow.preview.title"), ModalityType.APPLICATION_MODAL);
        this.actions = actions != null ? List.copyOf(actions) : List.of();
        this.requestFlow = requestFlow;
        this.initialData = initialData;

        ProcessorManager processorManager = ProcessorFactory.createDefaultProcessorManager(null);
        this.previewService = new StepFlowPreviewService(processorManager);

        setSize(960, 680);
        setMinimumSize(new Dimension(760, 560));
        setLocationRelativeTo(owner);
        setLayout(new BorderLayout());
        getContentPane().setBackground(UIStyle.background());

        add(createHeader(), BorderLayout.NORTH);
        add(createMainPanel(), BorderLayout.CENTER);
        add(createButtonPanel(), BorderLayout.SOUTH);
    }

    private JPanel createHeader() {
        JPanel panel = new JPanel(new BorderLayout(8, 4));
        panel.setBackground(UIStyle.background());
        panel.setBorder(BorderFactory.createEmptyBorder(14, 16, 10, 16));
        panel.add(UIStyle.sectionTitle(lang.getString("flow.preview.title")), BorderLayout.NORTH);
        panel.add(UIStyle.mutedLabel(lang.getString("flow.preview.help")), BorderLayout.CENTER);
        return panel;
    }

    private JPanel createMainPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(UIStyle.background());
        panel.setBorder(BorderFactory.createEmptyBorder(0, 14, 12, 14));

        panel.add(createRequestMetaPanel(), BorderLayout.NORTH);

        bodyArea = new JTextArea(initialData != null && initialData.body() != null ? initialData.body() : defaultBody());
        bodyArea.setLineWrap(true);
        bodyArea.setWrapStyleWord(true);
        UIStyle.styleTextArea(bodyArea, true);

        headersArea = new JTextArea(initialData != null && initialData.headers() != null
                ? headersText(initialData.headers())
                : "Content-Type: application/json\nX-Req-Id: preview-1");
        headersArea.setLineWrap(true);
        headersArea.setWrapStyleWord(true);
        UIStyle.styleTextArea(headersArea, true);

        traceArea = new JTextArea(lang.getString("flow.preview.empty"));
        traceArea.setEditable(false);
        traceArea.setLineWrap(true);
        traceArea.setWrapStyleWord(true);
        UIStyle.styleTextArea(traceArea, true);

        JComponent headerInputs = UIStyle.scroll(headersArea);
        if (!requestFlow) {
            requestHeadersArea = new JTextArea(initialData != null && initialData.requestHeaders() != null
                    ? headersText(initialData.requestHeaders()) : "");
            UIStyle.styleTextArea(requestHeadersArea, true);
            JTabbedPane tabs = new JTabbedPane();
            tabs.addTab(lang.getString("flow.preview.response_headers"), headerInputs);
            tabs.addTab(lang.getString("flow.preview.request_headers"), UIStyle.scroll(requestHeadersArea));
            headerInputs = tabs;
        }
        JSplitPane left = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                wrap(lang.getString("flow.preview.body"), UIStyle.scroll(bodyArea)),
                wrap(lang.getString("flow.preview.headers"), headerInputs));
        SplitPaneLayout.initialize(left, 0.66);
        left.setBorder(null);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                left,
                wrap(lang.getString("flow.preview.trace"), UIStyle.scroll(traceArea)));
        SplitPaneLayout.initialize(split, 0.46);
        split.setBorder(null);

        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createRequestMetaPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(UIStyle.background());
        panel.setBorder(UIStyle.sectionBorder(lang.getString("flow.preview.context")));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 6, 5, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        methodField = new JTextField(initialData != null && initialData.method() != null
                ? initialData.method()
                : requestFlow ? "POST" : "GET", 8);
        urlField = new JTextField(initialData != null && initialData.url() != null
                ? initialData.url().toString()
                : "https://example.com/api/test", 36);
        phaseBox = new JComboBox<>(phaseOptions());
        phaseBox.setSelectedItem(initialPhase());

        addRow(panel, gbc, 0, lang.getString("flow.preview.method"), methodField);
        addRow(panel, gbc, 1, lang.getString("flow.preview.url"), urlField);
        addRow(panel, gbc, 2, lang.getString("flow.preview.phase"), phaseBox);
        return panel;
    }

    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        panel.setBackground(UIStyle.surface());
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UIStyle.border()),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
        ));

        runButton = UIStyle.primaryButton(lang.getString("flow.preview.run"));
        runButton.setIcon(UIStyle.icon(UIStyle.IconType.RUN));
        runButton.addActionListener(e -> runPreview());
        JButton closeButton = UIStyle.button(lang.getString("btn.close"));
        closeButton.addActionListener(e -> dispose());

        panel.add(runButton);
        panel.add(closeButton);
        return panel;
    }

    private void runPreview() {
        if (previewWorker != null) return;
        if (actions.isEmpty()) {
            traceArea.setText(lang.getString("flow.preview.no_steps"));
            return;
        }

        try {
            String body = bodyArea.getText();
            String method = methodField.getText().trim();
            URL url = new URL(urlField.getText().trim());
            Map<String, String> headers = parseHeaders(headersArea.getText());
            Map<String, String> requestHeaders = requestHeadersArea == null ? null : parseHeaders(requestHeadersArea.getText());
            String phase = String.valueOf(phaseBox.getSelectedItem());
            String source = initialData != null && initialData.toolSource() != null
                    ? initialData.toolSource() : Constants.ToolSource.REPEATER;
            runButton.setEnabled(false);
            traceArea.setText(lang.getString("ui.task.running"));
            previewWorker = UiTasks.start(() -> previewService.preview(actions, body, method, url,
                            headers, source, requestFlow, phase, requestHeaders),
                    result -> { traceArea.setText(format(result)); traceArea.setCaretPosition(0); },
                    ex -> traceArea.setText(lang.getString("flow.preview.context_error").replace("{0}", String.valueOf(ex.getMessage()))),
                    () -> { previewWorker = null; runButton.setEnabled(true); });

        } catch (Exception ex) {
            traceArea.setText(lang.getString("flow.preview.context_error").replace("{0}", ex.getMessage()));
        }
    }

    @Override public void dispose() {
        if (previewWorker != null) previewWorker.cancel(true);
        super.dispose();
    }

    private String format(StepFlowPreviewService.PreviewResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("预览结果: ").append(result.isSuccess() ? "成功" : "有步骤失败").append('\n');
        sb.append("最终内容:\n").append(clip(result.getFinalBody())).append("\n\n");

        for (StepFlowPreviewService.PreviewStep step : result.getSteps()) {
            ProcessingAction action = step.getAction();
            sb.append("第 ").append(step.getIndex()).append(" 步 [").append(statusLabel(step.getStatus())).append("]");
            if (action != null) {
                sb.append(" ").append(safe(action.getActionType()))
                        .append(" / ").append(safe(action.getProcessor()));
            }
            sb.append('\n');
            sb.append("执行时机: ").append(safe(step.getPhase())).append('\n');
            if (!step.getMessage().isBlank()) {
                sb.append("说明: ").append(step.getMessage()).append('\n');
            }
            if (!step.getTarget().isBlank()) {
                sb.append("写回位置: ").append(step.getTarget()).append('\n');
            }
            if (!step.getInput().isEmpty()) {
                sb.append("读取内容:\n").append(clip(step.getInput())).append('\n');
            }
            if (!step.getOutput().isEmpty()) {
                sb.append("生成内容:\n").append(clip(step.getOutput())).append('\n');
            }
            if (!step.getMetadata().isEmpty()) {
                sb.append("附加信息: ").append(step.getMetadata()).append('\n');
            }
            sb.append('\n');
        }

        if (!result.getModifiedHeaders().isEmpty()) {
            sb.append("已修改的 Header:\n");
            result.getModifiedHeaders().forEach((k, v) -> sb.append(k).append(": ").append(v).append('\n'));
            sb.append('\n');
        }
        if (!result.getVariables().isEmpty()) {
            StringJoiner joiner = new StringJoiner("\n");
            result.getVariables().forEach((k, v) -> joiner.add(k + " = " + v));
            sb.append("临时变量:\n").append(joiner).append('\n');
        }

        return sb.toString();
    }

    private String statusLabel(String status) {
        if ("executed".equalsIgnoreCase(status)) {
            return "已执行";
        }
        if ("skipped".equalsIgnoreCase(status)) {
            return "已跳过";
        }
        if ("failed".equalsIgnoreCase(status)) {
            return "失败";
        }
        return safe(status);
    }

    private JPanel wrap(String title, JComponent component) {
        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.setBackground(UIStyle.background());
        panel.add(UIStyle.sectionTitle(title), BorderLayout.NORTH);
        panel.add(component, BorderLayout.CENTER);
        return panel;
    }

    private void addRow(JPanel panel, GridBagConstraints gbc, int row, String label, JComponent field) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        panel.add(new JLabel(label), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(field, gbc);
    }

    private Map<String, String> parseHeaders(String text) {
        return HeaderText.parse(text);
    }

    private String[] phaseOptions() {
        if (requestFlow) {
            return new String[]{
                    Constants.ExecutionPhase.DISPLAY,
                    Constants.ExecutionPhase.EDITOR_SEND,
                    Constants.ExecutionPhase.SEND
            };
        }
        return new String[]{
                Constants.ExecutionPhase.RESPONSE_DISPLAY,
                Constants.ExecutionPhase.RESPONSE_EDITOR_SEND,
                Constants.ExecutionPhase.RESPONSE_SEND
        };
    }

    private String initialPhase() {
        if (initialData != null && initialData.phase() != null) {
            for (String option : phaseOptions()) {
                if (option.equalsIgnoreCase(initialData.phase())) {
                    return option;
                }
            }
        }
        return defaultPhase();
    }

    private String defaultPhase() {
        if (actions.stream().anyMatch(action -> action != null && phaseContains(action, Constants.ExecutionPhase.DISPLAY))) {
            return Constants.ExecutionPhase.DISPLAY;
        }
        if (actions.stream().anyMatch(action -> action != null && phaseContains(action, Constants.ExecutionPhase.EDITOR_SEND))) {
            return Constants.ExecutionPhase.EDITOR_SEND;
        }
        if (actions.stream().anyMatch(action -> action != null && phaseContains(action, Constants.ExecutionPhase.RESPONSE_DISPLAY))) {
            return Constants.ExecutionPhase.RESPONSE_DISPLAY;
        }
        if (!requestFlow && actions.stream().anyMatch(action -> action != null && phaseContains(action, Constants.ExecutionPhase.RESPONSE_EDITOR_SEND)))
            return Constants.ExecutionPhase.RESPONSE_EDITOR_SEND;
        return requestFlow ? Constants.ExecutionPhase.SEND : Constants.ExecutionPhase.RESPONSE_DISPLAY;
    }

    private boolean phaseContains(ProcessingAction action, String phase) {
        return Constants.ExecutionPhase.matches(action.getConfigString(Constants.ConfigKey.EXECUTION_PHASE), phase,
                requestFlow ? Constants.ExecutionPhase.SEND : Constants.ExecutionPhase.RESPONSE_DISPLAY);
    }

    private String defaultBody() {
        return requestFlow ? "{\"id\":123,\"data\":\"aGVsbG8=\"}" : "{\"code\":0,\"data\":\"aGVsbG8=\"}";
    }

    private String headersText(Map<String, String> headers) {
        StringBuilder sb = new StringBuilder();
        headers.forEach((name, value) -> sb.append(name).append(": ").append(value != null ? value : "").append('\n'));
        return sb.toString().trim();
    }

    private String clip(String value) {
        if (value == null) {
            return "";
        }
        if (value.length() <= PREVIEW_LIMIT) {
            return value;
        }
        return value.substring(0, PREVIEW_LIMIT) + "\n... clipped " + (value.length() - PREVIEW_LIMIT) + " chars";
    }

    private String safe(String value) {
        return value == null || value.isBlank() ? "(empty)" : value;
    }

    public record InitialData(String method, URL url, Map<String, String> headers, String body, String phase,
                              Map<String,String> requestHeaders, String toolSource) {
        public InitialData(String method, URL url, Map<String,String> headers, String body, String phase) {
            this(method, url, headers, body, phase, null, Constants.ToolSource.REPEATER);
        }
    }
}
