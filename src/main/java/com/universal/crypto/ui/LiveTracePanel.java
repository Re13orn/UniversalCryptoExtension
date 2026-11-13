package com.universal.crypto.ui;

import burp.api.montoya.MontoyaApi;
import com.universal.crypto.burp.UniversalCryptoExtension;
import com.universal.crypto.engine.RuleMatchEngine;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.engine.StepFlowPreviewService;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.handler.HttpContextBase;
import com.universal.crypto.handler.HttpResponseContext;
import com.universal.crypto.util.LanguageManager;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.CancellationException;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Panel for real-time tracing of processed requests.
 */
public class LiveTracePanel extends JPanel {

    private final RuleManager ruleManager;
    private final RuleMatchEngine matchEngine;
    private final ProcessorManager processorManager;
    private final LanguageManager lang = LanguageManager.getInstance();
    private DefaultTableModel tableModel;
    private JTable logTable;
    private final List<TraceEntry> traceEntries = new ArrayList<>(); // Store full details
    private volatile boolean isRecording = true;
    private volatile long recordingEpoch;
    private long nextId = 1;
    private JSplitPane mainSplit;
    private JSplitPane detailsSplit;
    private double dividerRatio = 0.50;
    private JTabbedPane outputTabs;
    private JTextArea plaintextArea;
    private SwingWorker<String, Void> previewWorker;
    private long previewGeneration;
    private Long detailId;
    private boolean rebuilding;
    private JButton previewButton;
    private JButton rerunButton;
    private JTextField searchField;
    private JComboBox<String> directionFilter;
    private JComboBox<String> resultFilter;
    private JComboBox<String> kindFilter;
    private JLabel filterCount;

    // Detail UI Components
    private JTextArea summaryArea;
    private JTextArea originalArea;
    private JTextArea modifiedArea;
    private JPanel originalPanel;
    
    // Split Panes for UI refresh
    private JScrollPane tableScroll;

    public LiveTracePanel(MontoyaApi api, UniversalCryptoExtension extension) {
        this(extension.getRuleManager(), extension.getMatchEngine(), extension.getProcessorManager());
        extension.addTrafficListener(this::addLogEntry);
    }

    LiveTracePanel(RuleManager ruleManager, RuleMatchEngine matchEngine, ProcessorManager processorManager) {
        this.ruleManager = ruleManager;
        this.matchEngine = matchEngine;
        this.processorManager = processorManager;

        // Initialize Table Model (Empty first, columns set in rebuildUI)
        tableModel = new DefaultTableModel(0, 0) {
            @Override public Class<?> getColumnClass(int column) { return column == 0 ? Long.class : String.class; }
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        rebuildUI();
        if (ruleManager != null) ruleManager.addRuleChangeListener(() -> SwingUtilities.invokeLater(() -> {
            cancelPreview();
            traceEntries.forEach(entry -> entry.previewText = null);
            if (selectedEntry() != null && !selectedEntry().isAction() && outputTabs.getSelectedIndex() == 1)
                plaintextArea.setText(lang.getString("trace.preview.rules_changed"));
        }));
    }
    
    public void rebuildUI() {
        TraceEntry selected = selectedEntry();
        Long selectedId = selected == null ? null : selected.id;
        String query = searchField == null ? "" : searchField.getText();
        int direction = directionFilter == null ? 0 : directionFilter.getSelectedIndex();
        int result = resultFilter == null ? 0 : resultFilter.getSelectedIndex();
        int kind = kindFilter == null ? 0 : kindFilter.getSelectedIndex();
        List<? extends RowSorter.SortKey> sortKeys = logTable == null || logTable.getRowSorter() == null
                ? List.of() : List.copyOf(logTable.getRowSorter().getSortKeys());
        int selectedOutput = outputTabs == null ? 0 : outputTabs.getSelectedIndex();
        double horizontalRatio = SplitPaneLayout.ratio(detailsSplit, 0.5);
        rebuilding = true;
        if (mainSplit != null && mainSplit.getHeight() > 0) {
            dividerRatio = Math.max(0.2, Math.min(0.8, (double) mainSplit.getDividerLocation() / mainSplit.getHeight()));
        }
        cancelPreview();
        detailId = null;
        this.removeAll();
        setLayout(new BorderLayout());
        setBorder(UIStyle.emptyBorder());
        setBackground(UIStyle.background());

        // Update table model identifier (headers)
        updateTableHeaders();

        // Toolbar
        JToolBar toolBar = new JToolBar();
        UIStyle.styleToolBar(toolBar);
        
        // Buttons with I18n can be tricky for toggle button state, refactoring
        String recordingText = lang.getString(isRecording ? "trace.recording" : "trace.paused");
        // Simple toggle text
        JToggleButton recordBtn = new JToggleButton(recordingText, isRecording);
        UIStyle.styleButton(recordBtn, false, false);
        recordBtn.setIcon(UIStyle.dot(isRecording ? UIStyle.danger() : UIStyle.mutedText()));
        recordBtn.addActionListener(e -> {
            isRecording = recordBtn.isSelected();
            recordingEpoch++;
            recordBtn.setText(lang.getString(isRecording ? "trace.recording" : "trace.paused"));
            recordBtn.setIcon(UIStyle.dot(isRecording ? UIStyle.danger() : UIStyle.mutedText()));
        });
        
        JButton clearBtn = UIStyle.button(lang.getString("trace.btn.clear"));
        clearBtn.setIcon(UIStyle.icon(UIStyle.IconType.CLEAR));
        clearBtn.addActionListener(e -> {
            recordingEpoch++;
            traceEntries.clear();
            tableModel.setRowCount(0);
            clearDetails();
            updateFilterCount();
        });

        previewButton = UIStyle.button(lang.getString("trace.btn.preview_flow"));
        previewButton.setIcon(UIStyle.icon(UIStyle.IconType.RUN));
        previewButton.addActionListener(e -> previewSelectedTraffic());
        
        toolBar.add(recordBtn);
        toolBar.add(clearBtn);
        toolBar.add(previewButton);
        JPanel controls = new JPanel(new BorderLayout(0, 6));
        controls.setOpaque(false);
        controls.add(toolBar, BorderLayout.NORTH);
        controls.add(createFilters(query, direction, result, kind), BorderLayout.CENTER);
        add(controls, BorderLayout.NORTH);
        
        if (logTable == null) {
            logTable = new JTable(tableModel);
            logTable.setAutoCreateRowSorter(true);
            logTable.setFillsViewportHeight(true);
            UIStyle.styleTable(logTable);
            
             // Selection listener
            logTable.getSelectionModel().addListSelectionListener(e -> {
                if (!rebuilding && !e.getValueIsAdjusting()) {
                    TraceEntry entry = selectedEntry();
                    if (entry != null) showDetails(entry.id);
                    else clearDetails();
                }
            });
        } else {
            // Preserve stored rows; restore selection after changing the column structure.
            logTable.setModel(tableModel); 
            UIStyle.styleTable(logTable);
        }

        previewButton.setEnabled(selected != null && !selected.isAction());
        configureTable();
        applyFilters();
        logTable.getRowSorter().setSortKeys(sortKeys);
        
        // Scroll pane for table
        tableScroll = UIStyle.scroll(logTable);
        tableScroll.setColumnHeaderView(logTable.getTableHeader());

        summaryArea = createDetailArea(false);
        summaryArea.setRows(4);
        
        // Detail View (Split Pane: Left=Original, Right=Modified)
        originalArea = createDetailArea(true);
        modifiedArea = createDetailArea(true);
        
        plaintextArea = createDetailArea(true);
        outputTabs = new JTabbedPane();
        outputTabs.addTab(lang.getString("trace.tab.forwarded"), UIStyle.scroll(modifiedArea));
        JPanel plaintextPanel = new JPanel(new BorderLayout(0, 6));
        plaintextPanel.setOpaque(false);
        JLabel previewHint = new JLabel(lang.getString("trace.preview.hint"));
        previewHint.setForeground(UIStyle.mutedText());
        rerunButton = UIStyle.button(lang.getString("trace.preview.refresh"));
        rerunButton.addActionListener(e -> { TraceEntry entry = selectedEntry(); if (entry != null) { entry.previewText = null; generatePlaintextPreview(entry); } });
        JPanel previewBar = new JPanel(new BorderLayout(6, 0));
        previewBar.setOpaque(false);
        previewBar.add(previewHint, BorderLayout.CENTER);
        previewBar.add(rerunButton, BorderLayout.EAST);
        plaintextPanel.add(previewBar, BorderLayout.NORTH);
        plaintextPanel.add(UIStyle.scroll(plaintextArea), BorderLayout.CENTER);
        outputTabs.addTab(lang.getString("trace.tab.plaintext"), plaintextPanel);
        outputTabs.setSelectedIndex(selectedOutput);
        rerunButton.setEnabled(selected != null && !selected.isAction());
        outputTabs.addChangeListener(e -> { if (!rebuilding && outputTabs.getSelectedIndex() == 1) { TraceEntry entry = selectedEntry(); if (entry != null) generatePlaintextPreview(entry); } });

        originalPanel = wrapWithTitle(lang.getString("trace.tab.original"), originalArea);
        detailsSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, originalPanel, outputTabs);
        detailsSplit.getLeftComponent().setMinimumSize(new Dimension(0, 0));
        outputTabs.setMinimumSize(new Dimension(0, 0));
        SplitPaneLayout.initialize(detailsSplit, horizontalRatio);
        detailsSplit.setBorder(BorderFactory.createEmptyBorder());
        detailsSplit.setDividerSize(8);

        JPanel detailPanel = new JPanel(new BorderLayout(0, 8));
        detailPanel.setOpaque(false);
        detailPanel.add(wrapWithTitle(lang.getString("trace.details.summary"), summaryArea), BorderLayout.NORTH);
        detailPanel.add(detailsSplit, BorderLayout.CENTER);

        // Main Split Pane (Top: List, Bottom: Details)
        tableScroll.setMinimumSize(new Dimension(0, 120));
        detailPanel.setMinimumSize(new Dimension(0, 240));
        mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailPanel);
        SplitPaneLayout.initialize(mainSplit, dividerRatio);
        mainSplit.setBorder(BorderFactory.createEmptyBorder());
        mainSplit.setDividerSize(8);

        add(mainSplit, BorderLayout.CENTER);
        
        this.revalidate();
        this.repaint();
        rebuilding = false;
        if (selectedId != null) restoreSelection(selectedId);
        else clearDetails();
    }

    private void restoreSelection(long id) {
        for (int row = 0; row < tableModel.getRowCount(); row++) {
            if (Long.parseLong(tableModel.getValueAt(row, 0).toString()) == id) {
                int view = logTable.convertRowIndexToView(row);
                if (view >= 0) {
                    logTable.setRowSelectionInterval(view, view);
                    showDetails(id);
                } else { logTable.clearSelection(); clearDetails(); }
                break;
            }
        }
    }

    private JPanel createFilters(String query, int direction, int result, int kind) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setOpaque(false);
        searchField = new JTextField(query, 22);
        searchField.setToolTipText(lang.getString("trace.search.hint"));
        searchField.getAccessibleContext().setAccessibleName(lang.getString("trace.search.label"));
        JPanel search = new JPanel(new BorderLayout(6, 0));
        search.setOpaque(false);
        search.add(new JLabel(lang.getString("trace.search.label")), BorderLayout.WEST);
        search.add(searchField, BorderLayout.CENTER);
        JButton reset = UIStyle.button(lang.getString("trace.filter.reset"));
        reset.addActionListener(e -> {
            boolean wasRebuilding = rebuilding;
            rebuilding = true;
            try { searchField.setText(""); directionFilter.setSelectedIndex(0); resultFilter.setSelectedIndex(0); kindFilter.setSelectedIndex(0); }
            finally { rebuilding = wasRebuilding; }
            applyFilters();
        });
        search.add(reset, BorderLayout.EAST);
        panel.add(search, BorderLayout.NORTH);
        // Equal-width cells remain usable in narrow Burp panels; no fixed toolbar width.
        JPanel filters = new JPanel(new GridLayout(1, 3, 6, 0));
        filters.setOpaque(false);
        directionFilter = filterCombo("trace.filter.direction", new String[]{"all", "request", "response"}, direction);
        resultFilter = filterCombo("trace.filter.result", new String[]{"all", "changed", "unchanged", "failed"}, result);
        kindFilter = filterCombo("trace.filter.kind", new String[]{"all", "message", "action"}, kind);
        filters.add(directionFilter); filters.add(resultFilter); filters.add(kindFilter);
        panel.add(filters, BorderLayout.CENTER);
        filterCount = new JLabel();
        filterCount.setForeground(UIStyle.mutedText());
        panel.add(filterCount, BorderLayout.SOUTH);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { changed(); }
            public void removeUpdate(DocumentEvent e) { changed(); }
            public void changedUpdate(DocumentEvent e) { changed(); }
            private void changed() { if (!rebuilding) applyFilters(); }
        });
        return panel;
    }

    private JComboBox<String> filterCombo(String prefix, String[] options, int selected) {
        JComboBox<String> combo = new JComboBox<>(Arrays.stream(options).map(key -> lang.getString(prefix + "." + key)).toArray(String[]::new));
        combo.setSelectedIndex(selected);
        combo.addActionListener(e -> { if (!rebuilding) applyFilters(); });
        return combo;
    }

    private void applyFilters() {
        if (logTable == null || !(logTable.getRowSorter() instanceof TableRowSorter<?> sorter)) return;
        TraceEntry selected = selectedEntry();
        String query = searchField.getText().strip().toLowerCase(Locale.ROOT);
        int direction = directionFilter.getSelectedIndex(), result = resultFilter.getSelectedIndex(), kind = kindFilter.getSelectedIndex();
        // Capture semantic values: translated labels never decide filtering behavior.
        sorter.setRowFilter(new RowFilter() {
            @Override public boolean include(Entry entry) {
                long id = ((Number) entry.getValue(0)).longValue();
                int modelRow = ((Number) entry.getIdentifier()).intValue();
                TraceEntry trace = modelRow < traceEntries.size() ? traceEntries.get(modelRow) : null;
                if (trace == null || trace.id != id) return false;
                boolean response = trace.original instanceof HttpResponseContext || trace.modified instanceof HttpResponseContext;
                if ((direction == 1 && response) || (direction == 2 && !response)) return false;
                if ((kind == 1 && trace.isAction()) || (kind == 2 && !trace.isAction())) return false;
                boolean failed = trace.resultKey().equals("trace.result.failed");
                if ((result == 1 && (failed || !trace.wireChanged())) || (result == 2 && (failed || trace.wireChanged())) || (result == 3 && !failed)) return false;
                String tool = trace.original != null ? trace.original.getToolSource() : trace.modified != null ? trace.modified.getToolSource() : "";
                String haystack = trace.id + " " + trace.method + " " + trace.url + " " + trace.ruleInfo + " " + tool;
                return query.isEmpty() || haystack.toLowerCase(Locale.ROOT).contains(query);
            }
        });
        if (selected != null) restoreSelection(selected.id);
        else if (!rebuilding) { logTable.clearSelection(); clearDetails(); }
        updateFilterCount();
    }

    private void updateFilterCount() {
        if (filterCount != null && logTable != null)
            filterCount.setText(lang.format("trace.filter.count", logTable.getRowCount(), traceEntries.size()));
    }

    private void updateTableHeaders() {
        String[] columns = {
            lang.getString("trace.col.id"),
            lang.getString("trace.col.time"),
            lang.getString("trace.col.flow"),
            lang.getString("trace.col.method"),
            lang.getString("trace.col.url"),
            lang.getString("trace.col.result"),
            lang.getString("trace.col.rule")
        };
        
        java.util.Vector<String> columnIdentifiers = new java.util.Vector<>();
        for (String col : columns) columnIdentifiers.add(col);

        if (tableModel.getColumnCount() == columns.length) {
            tableModel.setDataVector(tableModel.getDataVector(), columnIdentifiers);
            for (int row = 0; row < tableModel.getRowCount(); row++) {
                long id = ((Number) tableModel.getValueAt(row, 0)).longValue();
                TraceEntry entry = traceEntries.stream().filter(item -> item.id == id).findFirst().orElse(null);
                if (entry != null) {
                    tableModel.setValueAt(entry.flowLabel(), row, 2);
                    tableModel.setValueAt(entry.resultLabel(), row, 5);
                }
            }
        } else {
            tableModel.setDataVector(new java.util.Vector<>(), columnIdentifiers);
            traceEntries.clear();
        }
    }

    private void configureTable() {
        if (logTable.getColumnCount() < 7) {
            return;
        }

        logTable.getColumnModel().getColumn(0).setPreferredWidth(55);
        logTable.getColumnModel().getColumn(1).setPreferredWidth(82);
        logTable.getColumnModel().getColumn(2).setPreferredWidth(88);
        logTable.getColumnModel().getColumn(3).setPreferredWidth(70);
        logTable.getColumnModel().getColumn(4).setPreferredWidth(360);
        logTable.getColumnModel().getColumn(5).setPreferredWidth(190);
        logTable.getColumnModel().getColumn(6).setPreferredWidth(260);

        DefaultTableCellRenderer padded = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                String text = value != null ? value.toString() : "";
                label.setText(text);
                label.setToolTipText(text);
                label.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
                return label;
            }
        };

        DefaultTableCellRenderer resultRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                String text = value != null ? value.toString() : "";
                label.setText(text);
                label.setToolTipText(text);
                int modelRow = table.convertRowIndexToModel(row);
                long id = Long.parseLong(tableModel.getValueAt(modelRow, 0).toString());
                TraceEntry entry = traceEntries.stream().filter(item -> item.id == id).findFirst().orElse(null);
                String key = entry == null ? "" : entry.resultKey();
                label.setIcon(UIStyle.dot(key.endsWith("failed") ? UIStyle.danger() : key.endsWith("changed") && !key.endsWith("unchanged") ? UIStyle.success() : UIStyle.mutedText()));
                label.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
                return label;
            }
        };

        for (int i = 0; i < logTable.getColumnCount(); i++) {
            logTable.getColumnModel().getColumn(i).setCellRenderer(i == 5 ? resultRenderer : padded);
        }
    }
    
    /**
     * Refresh the panel
     */
    public void refresh() {
        rebuildUI();
    }
    
    private void showDetails(long id) {
        TraceEntry entry = traceEntries.stream().filter(e -> e.id == id).findFirst().orElse(null);
        if (entry != null) {
            if (Long.valueOf(entry.id).equals(detailId)) return;
            detailId = entry.id;
            boolean action = entry.isAction();
            previewButton.setEnabled(!action);
            rerunButton.setEnabled(!action);
            originalPanel.setBorder(UIStyle.sectionBorder(lang.getString(action ? "trace.tab.before_action" : "trace.tab.original")));
            outputTabs.setTitleAt(0, lang.getString(action ? "trace.tab.after_action" : "trace.tab.forwarded"));
            cancelPreview();
            summaryArea.setText(formatSummary(entry));
            summaryArea.setCaretPosition(0);

            originalArea.setText(formatContext(entry.original));
            originalArea.setCaretPosition(0);
            
            modifiedArea.setText(formatContext(entry.modified));
            modifiedArea.setCaretPosition(0);
            plaintextArea.setText(action ? lang.getString("trace.preview.action_snapshot") : lang.getString("trace.preview.idle"));
            plaintextArea.setCaretPosition(0);
            if (outputTabs.getSelectedIndex() == 1) generatePlaintextPreview(entry);
        }
    }

    private void cancelPreview() {
        previewGeneration++;
        if (previewWorker != null) previewWorker.cancel(true);
        previewWorker = null;
    }

    private void generatePlaintextPreview(TraceEntry entry) {
        cancelPreview();
        if (entry.isAction()) {
            plaintextArea.setText(lang.getString("trace.preview.action_snapshot"));
            return;
        }
        long revision = ruleManager == null ? 0 : ruleManager.getRevision();
        String locale = lang.getCurrentLocale().toLanguageTag();
        if (entry.previewRevision != revision || !locale.equals(entry.previewLocale)) entry.previewText = null;
        if (entry.previewText != null) {
            plaintextArea.setText(entry.previewText);
            plaintextArea.setCaretPosition(0);
            return;
        }
        HttpContextBase context = entry.original != null ? entry.original : entry.modified;
        boolean response = context instanceof HttpResponseContext;
        List<ProcessingAction> actions = context == null ? List.of() : matchingActions(context, response);
        long generation = previewGeneration;
        plaintextArea.setText(lang.getString("trace.preview.running"));
        // Explicit preview only: no extra script execution during traffic recording or row selection.
        previewWorker = new SwingWorker<>() {
            @Override protected String doInBackground() {
                return plaintextPreview(context, actions, processorManager, lang);
            }
            @Override protected void done() {
                if (isCancelled() || generation != previewGeneration) return;
                try {
                    if ((ruleManager != null && revision != ruleManager.getRevision()) || !locale.equals(lang.getCurrentLocale().toLanguageTag())) {
                        plaintextArea.setText(lang.getString("trace.preview.rules_changed"));
                        return;
                    }
                    entry.previewText = get();
                    entry.previewRevision = revision;
                    entry.previewLocale = locale;
                    if (selectedEntry() == entry) {
                        plaintextArea.setText(entry.previewText);
                        plaintextArea.setCaretPosition(0);
                    }
                } catch (CancellationException ignored) {
                } catch (Exception ex) {
                    plaintextArea.setText(lang.getString("trace.preview.failed") + "\n" + ex.getMessage());
                }
            }
        };
        previewWorker.execute();
    }

    static String plaintextPreview(HttpContextBase context, List<ProcessingAction> actions,
                                   ProcessorManager processors, LanguageManager lang) {
        if (context == null || processors == null) return lang.getString("trace.preview.unavailable");
        boolean response = context instanceof HttpResponseContext;
        String phase = response ? Constants.ExecutionPhase.RESPONSE_DISPLAY : Constants.ExecutionPhase.DISPLAY;
        var result = new StepFlowPreviewService(processors).preview(actions, context.getBody(), context.getMethod(),
                context.getUrl(), context.getHeaders(), context.getToolSource(), !response, phase, context.getRequestHeaders());
        if (!result.isSuccess()) {
            String errors = result.getSteps().stream().filter(step -> "failed".equals(step.getStatus()))
                    .map(step -> step.getIndex() + ": " + step.getMessage()).collect(java.util.stream.Collectors.joining("\n"));
            return lang.getString("trace.preview.failed") + "\n" + errors;
        }
        if (result.getSteps().stream().noneMatch(step -> "executed".equals(step.getStatus()))) {
            return lang.getString("trace.preview.no_actions") + " (" + phase + ")";
        }
        String body = result.getFinalBody();
        try {
            var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            var value = mapper.readTree(body);
            if (value != null && (value.isObject() || value.isArray())) body = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(value);
        } catch (Exception ignored) { /* Non-JSON plaintext remains unchanged. */ }
        String headerChanges = result.getModifiedHeaders().isEmpty() ? "" : "\n" + result.getModifiedHeaders();
        return lang.getString("trace.preview.hint") + "\n" + phase + headerChanges + "\n\n" + body;
    }

    private void previewSelectedTraffic() {
        TraceEntry entry = selectedEntry();
        if (entry != null && entry.isAction()) return;
        if (entry == null) {
            JOptionPane.showMessageDialog(this, "请先选择一条实时流量。", "步骤流预览", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        HttpContextBase context = entry.original != null ? entry.original : entry.modified;
        if (context == null || context.getUrl() == null) {
            JOptionPane.showMessageDialog(this, "这条流量没有可用于预览的请求上下文。", "步骤流预览", JOptionPane.WARNING_MESSAGE);
            return;
        }

        boolean responseFlow = context instanceof HttpResponseContext;
        List<ProcessingAction> actions = matchingActions(context, responseFlow);
        if (actions.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    responseFlow ? "当前规则里没有匹配这条响应的步骤。" : "当前规则里没有匹配这条请求的步骤。",
                    "步骤流预览",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String phase = responseFlow ? Constants.ExecutionPhase.RESPONSE_DISPLAY : Constants.ExecutionPhase.SEND;
        StepFlowPreviewDialog.InitialData initialData = new StepFlowPreviewDialog.InitialData(
                context.getMethod(),
                context.getUrl(),
                headersForPreview(context, responseFlow),
                context.getBody(),
                phase,
                context.getRequestHeaders(),
                context.getToolSource()
        );

        StepFlowPreviewDialog dialog = new StepFlowPreviewDialog(
                SwingUtilities.getWindowAncestor(this),
                actions,
                !responseFlow,
                initialData
        );
        dialog.setVisible(true);
    }

    private TraceEntry selectedEntry() {
        if (logTable == null || logTable.getSelectedRow() < 0) {
            return null;
        }
        int viewRow = logTable.getSelectedRow();
        if (viewRow >= logTable.getRowCount()) return null;
        int modelRow = logTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= tableModel.getRowCount()) return null;
        Object value = tableModel.getValueAt(modelRow, 0);
        if (!(value instanceof Number number)) return null;
        return traceEntries.stream().filter(entry -> entry.id == number.longValue()).findFirst().orElse(null);
    }

    private List<ProcessingAction> matchingActions(HttpContextBase context, boolean responseFlow) {
        if (ruleManager == null || matchEngine == null) {
            return List.of();
        }

        RuleMatchEngine.MatchContext matchContext = responseFlow
                ? RuleMatchEngine.createResponseContext(context.getMethod(), context.getUrl(), context.getHeaders(), context.getBody(), context.getToolSource())
                : RuleMatchEngine.createRequestContext(context.getMethod(), context.getUrl(), context.getHeaders(), context.getBody(), context.getToolSource());

        List<ProcessingRule> matches = matchEngine.findMatchingRules(
                ruleManager.getEnabledRulesByPriority(),
                matchContext
        );

        List<ProcessingAction> actions = new ArrayList<>();
        for (ProcessingRule rule : matches) {
            List<ProcessingAction> source = responseFlow ? rule.getResponseActions() : rule.getRequestActions();
            if (source == null) {
                continue;
            }
            for (ProcessingAction action : source) {
                if (action != null) {
                    actions.add(action.clone());
                }
            }
        }
        return actions;
    }

    private Map<String, String> headersForPreview(HttpContextBase context, boolean responseFlow) {
        Map<String, String> headers = new LinkedHashMap<>();
        if (!responseFlow && context.getHost() != null && !containsHeader(context.getHeaders(), "Host")) {
            headers.put("Host", context.getHost());
        }
        headers.putAll(context.getHeaders());
        return headers;
    }
    
    private void clearDetails() {
        previewButton.setEnabled(false);
        rerunButton.setEnabled(false);
        detailId = null;
        cancelPreview();
        plaintextArea.setText(lang.getString("trace.preview.idle"));
        summaryArea.setText("");
        originalArea.setText("");
        modifiedArea.setText("");
    }
    
    private String formatContext(HttpContextBase context) {
        if (context == null) return "";
        StringBuilder sb = new StringBuilder();

        if (context instanceof HttpResponseContext responseContext) {
            sb.append("HTTP ").append(responseContext.getStatusCode()).append(" (").append(lang.getString("trace.protocol.unknown")).append(")\n");
        } else {
            String method = context.getMethod() != null ? context.getMethod() : "GET";
            sb.append(method).append(' ').append(pathAndQuery(context.getUrl())).append(" HTTP (").append(lang.getString("trace.protocol.unknown")).append(")\n");
        }

        Map<String, String> headers = context.getHeaders();
        if (headers != null) {
            if (!(context instanceof HttpResponseContext) && !containsHeader(headers, "Host") && context.getHost() != null) {
                sb.append("Host: ").append(context.getHost()).append("\n");
            }
            headers.forEach((k, v) -> sb.append(k).append(": ").append(v).append("\n"));
        }
        sb.append("\n");
        if (context.getBody() != null) {
            sb.append(context.getBody());
        }
        return sb.toString();
    }

    private String pathAndQuery(URL url) {
        if (url == null) {
            return "/";
        }
        String path = url.getPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        return url.getQuery() == null || url.getQuery().isEmpty() ? path : path + "?" + url.getQuery();
    }

    private boolean containsHeader(Map<String, String> headers, String name) {
        if (headers == null || name == null) {
            return false;
        }
        return headers.keySet().stream().anyMatch(name::equalsIgnoreCase);
    }
    
    private JTextArea createDetailArea(boolean code) {
        JTextArea area = new JTextArea();
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setEditable(false);
        UIStyle.styleTextArea(area, code);
        return area;
    }
    
    private JPanel wrapWithTitle(String title, JComponent comp) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(UIStyle.sectionBorder(title));
        p.setBackground(UIStyle.background());
        p.add(UIStyle.scroll(comp), BorderLayout.CENTER);
        return p;
    }

    public void addLogEntry(String method, String url, String status, String ruleId,
                            HttpContextBase original, HttpContextBase modified) {
        if (!isRecording) return;
        long epoch = recordingEpoch;
        String time = new SimpleDateFormat("HH:mm:ss").format(new Date());
        SwingUtilities.invokeLater(() -> {
            if (!isRecording || epoch != recordingEpoch) return;
            TraceEntry selected = selectedEntry();
            TraceEntry entry = new TraceEntry(nextId++, time, method, url, status, ruleId, original, modified);
            // Do not publish transient selections while the sorter updates inserted/evicted rows.
            boolean wasRebuilding = rebuilding;
            rebuilding = true;
            try {
                traceEntries.add(0, entry);
                tableModel.insertRow(0, new Object[]{ entry.id, time, entry.flowLabel(), method, url, entry.resultLabel(), entry.ruleInfo });
                if (tableModel.getRowCount() > 1000) {
                    tableModel.setRowCount(1000);
                    traceEntries.subList(1000, traceEntries.size()).clear();
                }
            } finally { rebuilding = wasRebuilding; }
            if (selected != null && traceEntries.contains(selected)) restoreSelection(selected.id);
            else if (selected != null) { logTable.clearSelection(); clearDetails(); }
            updateFilterCount();
        });
    }

    static class TraceEntry {
        long id;
        String time;
        String method;
        String url;
        String status;
        String ruleInfo;
        String previewText;
        long previewRevision = -1;
        String previewLocale;
        HttpContextBase original;
        HttpContextBase modified;
        
        public TraceEntry(long id, String time, String method, String url, String status, String ruleInfo,
                          HttpContextBase original, HttpContextBase modified) {
            this.id = id;
            this.time = time;
            this.method = method;
            this.url = url;
            this.status = status;
            this.ruleInfo = ruleInfo != null ? ruleInfo : "";
            this.original = original;
            this.modified = modified;
        }

        String flowLabel() {
            return LanguageManager.getInstance().getString(original instanceof HttpResponseContext || modified instanceof HttpResponseContext
                    ? "trace.flow.response" : "trace.flow.request");
        }

        boolean isAction() { return status != null && status.toLowerCase(Locale.ROOT).contains("action"); }

        String resultKey() {
            String lower = status == null ? "" : status.toLowerCase(Locale.ROOT);
            if (lower.contains("error") || lower.contains("fail") || (modified != null && modified.hasError())) return "trace.result.failed";
            if (lower.contains("action")) return wireChanged() ? "trace.result.action_changed" : "trace.result.action_unchanged";
            return wireChanged() ? "trace.result.changed" : "trace.result.unchanged";
        }

        String resultLabel() { return LanguageManager.getInstance().getString(resultKey()); }

        boolean wireChanged() {
            return original != null && modified != null
                    && (!Arrays.equals(original.getBodyBytes(), modified.getBodyBytes()) || !original.getHeaders().equals(modified.getHeaders()));
        }
    }

    private String formatSummary(TraceEntry entry) {
        StringBuilder sb = new StringBuilder();
        sb.append(entry.time).append("  |  #").append(entry.id).append("  |  ")
                .append(entry.flowLabel()).append("  |  ").append(entry.resultLabel())
                .append("  |  ").append(entry.original != null ? entry.original.getToolSource() : "-")
                .append("  |  ").append(lang.getString("trace.summary.message_id")).append(": ").append(messageId(entry)).append('\n');
        sb.append(entry.method).append(' ').append(entry.url).append('\n');
        sb.append(lang.getString(entry.status != null && entry.status.toLowerCase(Locale.ROOT).contains("action")
                ? "trace.summary.action" : "trace.summary.matches")).append(": ")
                .append(entry.ruleInfo == null || entry.ruleInfo.isBlank() ? "-" : entry.ruleInfo).append('\n');
        sb.append(lang.getString(entry.isAction() ? "trace.summary.action_hint" : "trace.summary.wire_hint"));
        String headerChanges = formatHeaderChanges(entry.original, entry.modified);
        if (!headerChanges.isBlank()) {
            sb.append('\n').append(lang.getString("trace.summary.header_changes")).append(":\n").append(headerChanges);
        }
        return sb.toString();
    }

    private String messageId(TraceEntry entry) {
        Integer id = null;
        if (entry.modified != null) {
            id = entry.modified.getMessageId();
        }
        if (id == null && entry.original != null) {
            id = entry.original.getMessageId();
        }
        return id != null ? id.toString() : "-";
    }

    private String formatHeaderChanges(HttpContextBase original, HttpContextBase modified) {
        if (original == null || modified == null) {
            return "";
        }
        Map<String, String> originalHeaders = original.getHeaders();
        Map<String, String> modifiedHeaders = modified.getHeaders();
        if (originalHeaders == null || modifiedHeaders == null) {
            return "";
        }

        Set<String> names = new LinkedHashSet<>();
        modifiedHeaders.keySet().forEach(names::add);
        originalHeaders.keySet().forEach(name -> {
            if (findHeaderNameIgnoreCase(modifiedHeaders, name) == null) {
                names.add(name);
            }
        });

        StringBuilder sb = new StringBuilder();
        for (String name : names) {
            String originalName = findHeaderNameIgnoreCase(originalHeaders, name);
            String modifiedName = findHeaderNameIgnoreCase(modifiedHeaders, name);
            String before = originalName != null ? originalHeaders.get(originalName) : null;
            String after = modifiedName != null ? modifiedHeaders.get(modifiedName) : null;
            if (!java.util.Objects.equals(before, after)) {
                String displayName = modifiedName != null ? modifiedName : name;
                sb.append("  ").append(displayName).append(": ")
                        .append(before == null ? "<missing>" : before)
                        .append("  ->  ")
                        .append(after == null ? "<removed>" : after)
                        .append('\n');
            }
        }
        return sb.toString();
    }

    private String findHeaderNameIgnoreCase(Map<String, String> headers, String name) {
        if (headers == null || name == null) {
            return null;
        }
        for (String headerName : headers.keySet()) {
            if (name.equalsIgnoreCase(headerName)) {
                return headerName;
            }
        }
        return null;
    }

}
