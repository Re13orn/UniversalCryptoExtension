package com.universal.crypto.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;
import com.universal.crypto.burp.UniversalCryptoExtension;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.handler.HttpInterceptor;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.util.DebugUtil;
import com.universal.crypto.util.LanguageManager;
import com.universal.crypto.util.Logger;

import javax.swing.*;
import java.awt.*;

/**
 * Main UI tab for Universal Crypto Extension
 */
public class UniversalCryptoTab extends JPanel {

    private static final Logger logger = Logger.getInstance();
    private final LanguageManager lang = LanguageManager.getInstance();

    private final MontoyaApi api;
    private final UniversalCryptoExtension extension;
    private final RuleManager ruleManager;
    private final ProcessorManager processorManager;
    private final HttpInterceptor interceptor;

    // UI Components
    private JTabbedPane mainTabbedPane;
    private RuleManagementPanel rulePanel;
    private SettingsPanel settingsPanel;
    private LiveTracePanel liveTracePanel;
    private PlaygroundPanel playgroundPanel;
    private JLabel rulesStatus;

    public UniversalCryptoTab(MontoyaApi api, UniversalCryptoExtension extension) {
        this.api = api;
        this.extension = extension;
        this.ruleManager = extension.getRuleManager();
        this.processorManager = extension.getProcessorManager();
        this.interceptor = null; // Will be set later if needed

        initializeUI();
        ruleManager.addRuleChangeListener(() -> SwingUtilities.invokeLater(this::updateRuleStatus));
        logger.info("Universal Crypto UI Tab initialized");
    }

    /**
     * Initialize the main UI components
     */
    private void initializeUI() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder());
        setBackground(UIStyle.background());

        // Create header panel
        JPanel headerPanel = createHeaderPanel();
        add(headerPanel, BorderLayout.NORTH);

        // Create main tabbed pane
        mainTabbedPane = new JTabbedPane();
        mainTabbedPane.setBorder(BorderFactory.createEmptyBorder(0, UIStyle.GAP_LG, UIStyle.GAP_LG, UIStyle.GAP_LG));

        // Initialize all panels
        try {
            initializePanels();
            addTabs();
        } catch (Exception e) {
            logger.error("Failed to initialize UI panels", e);
            JPanel errorPanel = new JPanel(new BorderLayout());
            JTextArea error = new JTextArea(lang.getString("ui.initialization_failed") + "\n" + e.getMessage());
            error.setEditable(false);
            errorPanel.add(new JScrollPane(error), BorderLayout.CENTER);
            mainTabbedPane.addTab(lang.getString("error.title"), errorPanel);
        }

        // Add tab change listener for status synchronization
        mainTabbedPane.addChangeListener(e -> {
            // Tab change logic if needed
        });

        add(mainTabbedPane, BorderLayout.CENTER);

        // Create status bar
        JPanel statusBar = createStatusBar();
        add(statusBar, BorderLayout.SOUTH);
    }

    /**
     * Initialize all UI panels
     */
    private void initializePanels() {
        rulePanel = new RuleManagementPanel(api, ruleManager, (ActionTestNavigator) this::openActionTest);
        settingsPanel = new SettingsPanel(api, extension, this::refreshUI);
        liveTracePanel = new LiveTracePanel(api, extension);
        playgroundPanel = new PlaygroundPanel(api, processorManager, ruleManager, extension.getMatchEngine());
    }

    private void addTabs() {
        Component selected = mainTabbedPane.getSelectedComponent();
        mainTabbedPane.removeAll();
        mainTabbedPane.addTab(lang.getString("tab.live_trace"), UIStyle.icon(UIStyle.IconType.TRACE), liveTracePanel, "Real-time monitoring");
        mainTabbedPane.addTab(lang.getString("tab.rules"), UIStyle.icon(UIStyle.IconType.RULES), rulePanel, "Manage rules");
        mainTabbedPane.addTab(lang.getString("tab.global_settings"), UIStyle.icon(UIStyle.IconType.SETTINGS), settingsPanel, "Extension settings");
        mainTabbedPane.addTab(lang.getString("tab.playground"), UIStyle.icon(UIStyle.IconType.PLAYGROUND), playgroundPanel, "Test configuration");
        if (selected != null && mainTabbedPane.indexOfComponent(selected) >= 0)
            mainTabbedPane.setSelectedComponent(selected);
    }

    /**
     * Create header panel with extension info
     */
    private JPanel createHeaderPanel() {
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setOpaque(true);
        headerPanel.setBackground(UIStyle.surface());
        headerPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, UIStyle.border()),
            BorderFactory.createEmptyBorder(14, 18, 12, 18)
        ));

        // Title and version
        JLabel titleLabel = new JLabel("Universal Crypto");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 18f));

        // Description
        JLabel descLabel = UIStyle.mutedLabel(UniversalCryptoExtension.getDescription()
            + "  ·  Author: " + UniversalCryptoExtension.getAuthor()
            + "  ·  v" + UniversalCryptoExtension.getVersion());

        // Status indicator
        JPanel statusPanel = createHeaderStatusPanel();

        // Layout
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setOpaque(false);
        leftPanel.add(titleLabel, BorderLayout.NORTH);
        leftPanel.add(descLabel, BorderLayout.CENTER);

        headerPanel.add(leftPanel, BorderLayout.CENTER);
        headerPanel.add(statusPanel, BorderLayout.EAST);

        return headerPanel;
    }

    /**
     * Create status indicators in header
     */
    private JPanel createHeaderStatusPanel() {
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        statusPanel.setOpaque(false);

        // Rules status
        int ruleCount = ruleManager != null ? ruleManager.getRuleCount() : 0;
        int enabledRules = ruleManager != null ? ruleManager.getEnabledRulesByPriority().size() : 0;
        rulesStatus = UIStyle.badge(String.format("Rules %d/%d", enabledRules, ruleCount), UIStyle.surfaceAlt());
        rulesStatus.setForeground(UIStyle.text());

        // Processors status
        int processorCount = processorManager != null ? processorManager.getProcessorCount() : 0;
        JLabel processorsStatus = UIStyle.badge(String.format("Processors %d", processorCount), UIStyle.surfaceAlt());
        processorsStatus.setForeground(UIStyle.text());

        // Extension status
        JLabel extensionStatus = new JLabel(lang.getString("ui.status.running"), UIStyle.dot(UIStyle.success()), SwingConstants.LEFT);
        extensionStatus.setFont(extensionStatus.getFont().deriveFont(Font.BOLD, 11f));
        extensionStatus.setForeground(UIStyle.success());

        statusPanel.add(rulesStatus);
        statusPanel.add(Box.createHorizontalStrut(8));
        statusPanel.add(processorsStatus);
        statusPanel.add(Box.createHorizontalStrut(10));
        statusPanel.add(extensionStatus);

        return statusPanel;
    }

    /**
     * Create status bar at bottom
     */
    private JPanel createStatusBar() {
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setOpaque(true);
        statusBar.setBackground(UIStyle.surface());
        statusBar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, UIStyle.border()),
            BorderFactory.createEmptyBorder(6, 18, 6, 18)
        ));

        JLabel statusLabel = new JLabel(lang.getString("ui.status.ready"));
        statusLabel.setFont(statusLabel.getFont().deriveFont(11f));
        statusLabel.setForeground(UIStyle.mutedText());

        // Performance info
        String memoryInfo = getMemoryInfo();
        JLabel memoryLabel = new JLabel(memoryInfo);
        memoryLabel.setFont(memoryLabel.getFont().deriveFont(11f));
        memoryLabel.setForeground(UIStyle.mutedText());

        statusBar.add(statusLabel, BorderLayout.WEST);
        statusBar.add(memoryLabel, BorderLayout.EAST);

        return statusBar;
    }

    /**
     * Get memory usage information
     */
    private String getMemoryInfo() {
        try {
            Runtime runtime = Runtime.getRuntime();
            long totalMemory = runtime.totalMemory();
            long freeMemory = runtime.freeMemory();
            long usedMemory = totalMemory - freeMemory;

            return String.format("Mem: %dMB used", usedMemory / (1024 * 1024));
        } catch (Exception e) {
            return "Mem: N/A";
        }
    }

    /**
     * Refresh all UI components
     */
    public void refreshUI() {
        SwingUtilities.invokeLater(() -> {
            try {
                // Determine if we need to update tab titles
                addTabs();
                
                if (rulePanel != null) {
                    rulePanel.refresh();
                }
                if (settingsPanel != null) {
                    settingsPanel.refresh();
                }
                if (liveTracePanel != null) {
                    liveTracePanel.refresh();
                }
                if (playgroundPanel != null) {
                    // We need a refresh method in PlaygroundPanel ideally, or rebuildUI
                    playgroundPanel.rebuildUI(); 
                }

                remove(((BorderLayout) getLayout()).getLayoutComponent(BorderLayout.NORTH));
                add(createHeaderPanel(), BorderLayout.NORTH);
                revalidate();
                repaint();
                logger.debug("UI refreshed successfully");
            } catch (Exception e) {
                logger.error("Failed to refresh UI", e);
            }
        });
    }

    private void updateRuleStatus() {
        if (rulesStatus != null) rulesStatus.setText(String.format("Rules %d/%d",
                ruleManager.getEnabledRulesByPriority().size(), ruleManager.getRuleCount()));
    }

    /**
     * Update status bar message
     */
    public void updateStatus(String message) {
        SwingUtilities.invokeLater(() -> {
            try {
                Component statusBar = ((BorderLayout) getLayout()).getLayoutComponent(BorderLayout.SOUTH);
                if (statusBar instanceof JPanel) {
                    JLabel statusLabel = (JLabel) ((JPanel) statusBar).getComponent(0);
                    if (statusLabel != null) {
                        statusLabel.setText(message);
                    }
                }
            } catch (Exception e) {
                logger.debug("Failed to update status: " + e.getMessage());
            }
        });
    }

    /**
     * Get the main tabbed pane for external access
     */
    public JTabbedPane getMainTabbedPane() {
        return mainTabbedPane;
    }

    /**
     * Switch to specific tab
     */
    public void switchToTab(int tabIndex) {
        if (mainTabbedPane != null && tabIndex >= 0 && tabIndex < mainTabbedPane.getTabCount()) {
            mainTabbedPane.setSelectedIndex(tabIndex);
        }
    }

    /**
     * Switch to tab by name
     */
    public void switchToTab(String tabName) {
        if (mainTabbedPane != null) {
            for (int i = 0; i < mainTabbedPane.getTabCount(); i++) {
                if (tabName.equals(mainTabbedPane.getTitleAt(i))) {
                    mainTabbedPane.setSelectedIndex(i);
                    break;
                }
            }
        }
    }

    public PlaygroundPanel getPlaygroundPanel() {
        return playgroundPanel;
    }

    private void openActionTest(Window owner, com.universal.crypto.model.ProcessingAction action, boolean responseAction) {
        createActionTestDialog(owner, action, responseAction).setVisible(true);
    }

    static StepFlowPreviewDialog createActionTestDialog(Window owner, com.universal.crypto.model.ProcessingAction action, boolean responseAction) {
        String configured = action.getConfigString("executionPhase", "");
        String fallback = responseAction ? "response-display"
                : Boolean.parseBoolean(action.getConfigString("editorOnly", "false")) ? "editor-send" : "send";
        String phase = java.util.Arrays.stream(configured.split(","))
                .map(String::trim).filter(value -> !value.isEmpty() && !value.equals("always"))
                .filter(value -> responseAction == value.startsWith("response-"))
                .findFirst().orElse(fallback);
        try {
            var initial = new StepFlowPreviewDialog.InitialData("POST", new java.net.URL("https://example.test/api"),
                    java.util.Map.of("Content-Type", "application/json"), "{\"data\":\"sample\"}", phase,
                    java.util.Map.of(), "REPEATER");
            return new StepFlowPreviewDialog(owner, java.util.List.of(action.clone()), !responseAction, initial);
        } catch (java.net.MalformedURLException error) { throw new IllegalStateException(error); }
    }

}
