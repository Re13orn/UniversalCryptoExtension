package com.universal.crypto.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.universal.crypto.engine.DefaultRuleFactory;
import com.universal.crypto.engine.RuleConfigStorage;
import com.universal.crypto.engine.RuleMatchEngine;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.engine.RuleProcessingService;
import com.universal.crypto.handler.HttpInterceptor;
import com.universal.crypto.util.Logger.LogLevel;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.processor.ProcessorFactory;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.processor.impl.CryptoProcessor;
import com.universal.crypto.ui.UniversalCryptoTab;
import com.universal.crypto.ui.editor.PlaintextHttpRequestEditorProvider;
import com.universal.crypto.util.DebugUtil;
import com.universal.crypto.util.Logger;
import com.universal.crypto.util.BouncyCastleSupport;


/**
 * Main BurpSuite extension class
 * Universal Crypto Extension for handling encryption/decryption via API
 */
public class UniversalCryptoExtension implements BurpExtension {

    private static final Logger logger = Logger.getInstance();

    private MontoyaApi api;
    private HttpInterceptor interceptor;
    private RuleManager ruleManager;
    private RuleMatchEngine matchEngine;
    private ProcessorManager processorManager;
    private RuleProcessingService ruleProcessingService;
    private UniversalCryptoTab uiTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        try {
            // Initialize logging system first
            initializeLogging();

            // Initialize Language from settings
            com.universal.crypto.util.LanguageManager.getInstance().setLanguage(
                com.universal.crypto.util.ExtensionSettings.getInstance().getLanguage()
            );

            // Initialize UI Theme
            com.universal.crypto.ui.ThemeManager.initialize();

            // Set extension info
            api.extension().setName("Universal Crypto Extension");
            logger.info("Starting Universal Crypto Extension v" + getVersion() + " (revision " + com.universal.crypto.util.BuildInfo.revision() + ") - Universal API Processing Platform");

            api.extension().registerUnloadingHandler(BouncyCastleSupport::close);
            java.security.Provider cryptoProvider = BouncyCastleSupport.getProvider();
            logger.info("Signed BC provider loaded: " + cryptoProvider.getName() + " " + cryptoProvider.getVersionStr());

            // Initialize components
            initializeComponents();

            // Register HTTP handler (simplified version)
            api.http().registerHttpHandler(new SimpleMontoyaHttpHandler(interceptor));

            // Register plaintext message editor tabs
            registerMessageEditors();

            // Initialize and register UI
            initializeUI();

            // Log successful initialization
            String successMsg = "Universal Crypto Extension initialized successfully";
            api.logging().logToOutput(successMsg);
            logger.info(successMsg);

            String statsMsg = "Statistics: " + interceptor.getStats();
            api.logging().logToOutput(statsMsg);
            logger.info(statsMsg);

        } catch (Exception e) {
            String errorMsg = "Failed to initialize Universal Crypto Extension: " + e.getMessage();
            api.logging().logToError(errorMsg);
            logger.error(errorMsg, e);
            DebugUtil.logException("UniversalCryptoExtension.initialize", e);
        }
    }

    /**
     * Initialize logging system with default configuration
     */
    private void initializeLogging() {
        try {
            // Load persistent settings first
            com.universal.crypto.util.ExtensionSettings settings = com.universal.crypto.util.ExtensionSettings.getInstance();
            settings.load();

            // Initialize logger with loaded settings
            logger.initialize(
                settings.getLogLevel(),
                true, // Console always on
                settings.isFileLoggingEnabled(),
                settings.getLogDirectory()
            );

            // Enable debug mode if configured
            DebugUtil.setDebugMode(settings.isDebugMode());

            logger.info("Logging system initialized - Log directory: " + settings.getLogDirectory());

        } catch (Exception e) {
            // Fallback to basic logging if initialization fails
            System.err.println("Failed to initialize logging system: " + e.getMessage());
        }
    }

    /**
     * Initialize and register UI components
     */
    private void initializeUI() {
        try {
            logger.info("Initializing UI components...");

            // Create main UI tab
            uiTab = new UniversalCryptoTab(api, this);

            // Register UI tab with BurpSuite
            api.userInterface().registerSuiteTab("Universal Crypto", uiTab);

            // Register Context Menu Provider
            api.userInterface().registerContextMenuItemsProvider(
                new UniversalContextMenuProvider(api, this)
            );

            logger.info("UI components initialized and registered successfully");

        } catch (Exception e) {
            logger.error("Failed to initialize UI components", e);
            DebugUtil.logException("UniversalCryptoExtension.initializeUI", e);
            // Don't throw - UI failure shouldn't prevent core functionality
        }
    }

    /**
     * Register custom message editor tabs for plaintext handling.
     */
    private void registerMessageEditors() {
        try {
            if (ruleProcessingService == null) {
                logger.warn("Rule processing service is not initialized; skipping message editor registration");
                return;
            }

            api.userInterface().registerHttpRequestEditorProvider(
                    new PlaintextHttpRequestEditorProvider(api, ruleProcessingService));
            api.userInterface().registerHttpResponseEditorProvider(new com.universal.crypto.ui.editor.PlaintextHttpResponseEditorProvider(api, ruleProcessingService));
            logger.info("Plaintext HTTP request and response editors registered");
            com.universal.crypto.processor.impl.ScriptProcessor.runSelfTest();
        } catch (Exception e) {
            logger.warn("Failed to register plaintext message editor: " + e.getMessage());
            DebugUtil.logException("UniversalCryptoExtension.registerMessageEditors", e);
        }
    }

    /**
     * Initialize all components of the extension
     */
    private void initializeComponents() {
        try {
            logger.info("Initializing extension components...");
            DebugUtil.startTiming("component_initialization");

            // Initialize storage
            logger.debug("Initializing rule config storage");
            RuleConfigStorage storage = new RuleConfigStorage();

            // Initialize rule manager
            logger.debug("Initializing rule manager");
            ruleManager = new RuleManager(storage);

            ruleManager.initializeWithDefaults(DefaultRuleFactory.getEssentialDefaultRules());
            logger.info("Loaded " + ruleManager.getRuleCount() + " configured rules ("
                    + ruleManager.getEnabledRuleCount() + " enabled)");

            // Initialize rule matching engine
            logger.debug("Initializing rule matching engine");
            matchEngine = new RuleMatchEngine();
            // Invalidate match-engine caches whenever rules change (add/update/remove/replace)
            ruleManager.addRuleChangeListener(matchEngine::clearCaches);

            // Initialize API client (placeholder - should be configured with real endpoint)
            logger.debug("Creating API client");
            CryptoProcessor.ApiClient apiClient = createApiClient();

            // Initialize processor manager
            logger.debug("Initializing processor manager");
            processorManager = ProcessorFactory.createDefaultProcessorManager(apiClient);

            // Initialize reusable rule processing service
            ruleProcessingService = new RuleProcessingService(ruleManager, matchEngine, processorManager);

            // Initialize HTTP interceptor
            logger.debug("Initializing HTTP interceptor");
            interceptor = new HttpInterceptor(ruleManager, matchEngine, processorManager);

            long initTime = DebugUtil.endTiming("component_initialization");

            String componentsMsg = "Components initialized: " +
                    ruleManager.getRuleCount() + " rules, " +
                    processorManager.getProcessorCount() + " processors" +
                    " (took " + initTime + "ms)";

            api.logging().logToOutput(componentsMsg);
            logger.info(componentsMsg);

        } catch (Exception e) {
            logger.error("Component initialization failed", e);
            DebugUtil.logException("UniversalCryptoExtension.initializeComponents", e);
            throw new RuntimeException("Component initialization failed", e);
        }
    }

    /**
     * Create API client for crypto operations
     * Delegates to HttpApiClient which uses ExtensionSettings for configuration
     */
    private CryptoProcessor.ApiClient createApiClient() {
        return createApiClient(com.universal.crypto.processor.impl.HttpApiClient::new);
    }

    static CryptoProcessor.ApiClient createApiClient(java.util.function.Supplier<CryptoProcessor.ApiClient> factory) {
        try {
            return factory.get();
        } catch (Exception e) {
            logger.error("External crypto client unavailable; internal processors remain enabled: " + e.getMessage());
            return null;
        }
    }

    /**
     * Get rule manager for external access (e.g., UI)
     */
    public RuleManager getRuleManager() {
        return ruleManager;
    }

    /**
     * Get processor manager for external access
     */
    public ProcessorManager getProcessorManager() {
        return processorManager;
    }

    public RuleProcessingService getRuleProcessingService() {
        return ruleProcessingService;
    }

    public RuleMatchEngine getMatchEngine() {
        return matchEngine;
    }

    /**
     * Get interceptor statistics
     */
    public HttpInterceptor.ProcessingStats getStats() {
        return interceptor != null ? interceptor.getStats() : null;
    }
    
    public void addTrafficListener(com.universal.crypto.handler.TrafficListener listener) {
        if (interceptor != null) {
            interceptor.addTrafficListener(listener);
        }
    }

    /**
     * Get UI tab for external access
     */
    public UniversalCryptoTab getUITab() {
        return uiTab;
    }

    /**
     * Refresh UI components
     */
    public void refreshUI() {
        try {
            if (uiTab != null) {
                uiTab.refreshUI();
                logger.debug("UI refreshed successfully");
            }
        } catch (Exception e) {
            logger.error("Failed to refresh UI", e);
            DebugUtil.logException("UniversalCryptoExtension.refreshUI", e);
        }
    }

    /**
     * Update UI status message
     */
    public void updateUIStatus(String message) {
        try {
            if (uiTab != null) {
                uiTab.updateStatus(message);
            }
        } catch (Exception e) {
            logger.debug("Failed to update UI status: " + e.getMessage());
        }
    }

    /**
     * Reload configuration from storage
     */
    public void reloadConfiguration() {
        try {
            logger.info("Reloading configuration...");
            if (ruleManager != null) {
                ruleManager.loadRules();
                String reloadMsg = "Configuration reloaded successfully. Rules: " + ruleManager.getRuleCount();
                api.logging().logToOutput(reloadMsg);
                logger.info(reloadMsg);
                DebugUtil.incrementCounter("config_reloads");

                // Refresh UI after reload
                refreshUI();
                updateUIStatus("Configuration reloaded");
            } else {
                logger.warn("Cannot reload configuration: rule manager not initialized");
            }
        } catch (Exception e) {
            String errorMsg = "Failed to reload configuration: " + e.getMessage();
            api.logging().logToError(errorMsg);
            logger.error(errorMsg, e);
            DebugUtil.logException("UniversalCryptoExtension.reloadConfiguration", e);
            updateUIStatus("Failed to reload configuration");
        }
    }

    /**
     * Save current configuration to storage
     */
    public void saveConfiguration() {
        try {
            logger.info("Saving configuration...");
            if (ruleManager != null) {
                ruleManager.saveRules();
                String saveMsg = "Configuration saved successfully";
                api.logging().logToOutput(saveMsg);
                logger.info(saveMsg);
                DebugUtil.incrementCounter("config_saves");

                // Update UI status after save
                updateUIStatus("Configuration saved");
            } else {
                logger.warn("Cannot save configuration: rule manager not initialized");
            }
        } catch (Exception e) {
            String errorMsg = "Failed to save configuration: " + e.getMessage();
            api.logging().logToError(errorMsg);
            logger.error(errorMsg, e);
            DebugUtil.logException("UniversalCryptoExtension.saveConfiguration", e);
            updateUIStatus("Failed to save configuration");
        }
    }

    /**
     * Add a new rule
     */
    public boolean addRule(ProcessingRule rule) {
        try {
            if (ruleManager != null) {
                ruleManager.addRule(rule);
                api.logging().logToOutput("Rule added: " + rule.getId());

                // Refresh UI after adding rule
                refreshUI();
                updateUIStatus("Rule added: " + rule.getName());
                return true;
            }
            return false;
        } catch (Exception e) {
            api.logging().logToError("Failed to add rule: " + e.getMessage());
            updateUIStatus("Failed to add rule");
            return false;
        }
    }

    /**
     * Enable/disable a rule
     */
    public boolean setRuleEnabled(String ruleId, boolean enabled) {
        try {
            if (ruleManager != null) {
                boolean result = ruleManager.setRuleEnabled(ruleId, enabled);
                if (result) {
                    api.logging().logToOutput("Rule " + ruleId + " " + (enabled ? "enabled" : "disabled"));

                    // Refresh UI after changing rule state
                    refreshUI();
                    updateUIStatus("Rule " + ruleId + " " + (enabled ? "enabled" : "disabled"));
                }
                return result;
            }
            return false;
        } catch (Exception e) {
            api.logging().logToError("Failed to update rule: " + e.getMessage());
            updateUIStatus("Failed to update rule");
            return false;
        }
    }

    /**
     * Get extension version info
     */
    public static String getVersion() {
        return "1.0.0";
    }

    /**
     * Get extension description
     */
    public static String getDescription() {
        return "通用 API 加解密、签名、编码和自定义处理平台。适用于请求重签、明文编辑、响应解密和协议调试。";
    }

    /**
     * Get extension author
     */
    public static String getAuthor() {
        return "Yao";
    }
}
