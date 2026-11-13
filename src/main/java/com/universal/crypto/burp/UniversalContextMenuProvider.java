package com.universal.crypto.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.ui.QuickRuleWizardDialog;
import com.universal.crypto.ui.UniversalCryptoTab;
import com.universal.crypto.util.LanguageManager;
import com.universal.crypto.util.Logger;

import javax.swing.*;
import java.awt.*;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Provides context menu items for BurpSuite integration
 */
public class UniversalContextMenuProvider implements ContextMenuItemsProvider {

    private static final Logger logger = Logger.getInstance();
    private final LanguageManager lang = LanguageManager.getInstance();
    private final MontoyaApi api;
    private final UniversalCryptoExtension extension;

    public UniversalContextMenuProvider(MontoyaApi api, UniversalCryptoExtension extension) {
        this.api = api;
        this.extension = extension;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        // Only show if we have a selected request/response
        if (event.selectedRequestResponses().isEmpty() && event.messageEditorRequestResponse().isEmpty()) {
            return Collections.emptyList();
        }

        // Get the relevant request info
        HttpRequestResponse reqResp = null;
        if (!event.selectedRequestResponses().isEmpty()) {
            reqResp = event.selectedRequestResponses().get(0);
        } else if (event.messageEditorRequestResponse().isPresent()) {
            reqResp = event.messageEditorRequestResponse().get().requestResponse();
        }

        if (reqResp == null || reqResp.request() == null) {
            return Collections.emptyList();
        }

        final HttpRequestResponse finalReqResp = reqResp;
        final QuickRuleWizardDialog.SourceRequest sourceRequest = sourceRequestFrom(reqResp.request());

        List<Component> menuList = new ArrayList<>();

        // Main Menu Item
        JMenu universalMenu = new JMenu("Universal Crypto");
        
        // 1. Create rule from the current request
        String wizardTitle = MessageFormat.format(lang.getString("menu.wizard"), sourceRequest.host());
        JMenuItem wizardItem = new JMenuItem(wizardTitle);
        wizardItem.addActionListener(e -> openWizard(sourceRequest));
        universalMenu.add(wizardItem);
        
        // 2. Send to Playground
        JMenuItem playgroundItem = new JMenuItem(lang.getString("menu.playground"));
        playgroundItem.addActionListener(e -> sendToPlayground(finalReqResp));
        universalMenu.add(playgroundItem);

        menuList.add(universalMenu);

        return menuList;
    }

    private QuickRuleWizardDialog.SourceRequest sourceRequestFrom(HttpRequest request) {
        Map<String, String> headers = new LinkedHashMap<>();
        if (request != null) {
            for (HttpHeader header : request.headers()) {
                if (header != null && header.name() != null && !header.name().isBlank()) {
                    headers.put(header.name(), header.value() != null ? header.value() : "");
                }
            }
        }
        return QuickRuleWizardDialog.sourceRequest(
                request != null ? request.method() : "",
                request != null ? request.url() : "",
                headers,
                false
        );
    }

    private void openWizard(QuickRuleWizardDialog.SourceRequest sourceRequest) {
        SwingUtilities.invokeLater(() -> {
            try {
                // Find parent frame
                Frame parent = Frame.getFrames().length > 0 ? Frame.getFrames()[0] : null;
                
                QuickRuleWizardDialog dialog = new QuickRuleWizardDialog(parent, sourceRequest);
                dialog.setVisible(true);

                if (dialog.isConfirmed()) {
                    ProcessingRule rule = dialog.getRule();
                    if (rule != null) {
                        RuleManager ruleManager = extension.getRuleManager();
                        ruleManager.addRuleAndSave(rule);
                        
                        // Force UI refresh
                        extension.refreshUI();
                        
                        String msg = MessageFormat.format(lang.getString("menu.success.msg"), rule.getName());
                        JOptionPane.showMessageDialog(parent, msg, lang.getString("menu.success.title"), JOptionPane.INFORMATION_MESSAGE);
                    }
                }
            } catch (Exception e) {
                logger.error("Error in Quick Wizard", e);
                JOptionPane.showMessageDialog(null, MessageFormat.format(lang.getString("error.generic"), e.getMessage()));
            }
        });
    }
    
    static String playgroundInput(HttpRequest request) {
        // Preserve method, URL and headers used by signing templates and script context.
        return request.toString();
    }

    private void sendToPlayground(HttpRequestResponse reqResp) {
        SwingUtilities.invokeLater(() -> {
            try {
                // Grab body default, or selection if available? 
                // ContextMenuEvent doesn't easily give selection in basic usage without more logic, 
                // assuming full body for now or specific selection if possible.
                // For simplicity, taking request body.
                String content = playgroundInput(reqResp.request());
                
                UniversalCryptoTab tab = extension.getUITab();
                if (tab != null) {
                    // Switch to Playground tab
                    // We need a robust way to select by index or title logic.
                    // Playground is usually index 3 (last one).
                    // Or via method we added: switchToTab(String name) but name is localized.
                    // Let's iterate tabs to find PlaygroundPanel instance.
                    JTabbedPane tabs = tab.getMainTabbedPane();
                    if (tabs != null) {
                        for(int i=0; i<tabs.getTabCount(); i++) {
                             // This relies on the component being the PlaygroundPanel
                             // But tabs might wrap components. 
                             // Easier: extension.getUITab().getPlaygroundPanel() check
                             if (tabs.getComponentAt(i) == tab.getPlaygroundPanel()) {
                                 tabs.setSelectedIndex(i);
                                 break;
                             }
                        }
                    }
                    
                    // Set Input
                    if (tab.getPlaygroundPanel() != null) {
                        tab.getPlaygroundPanel().setInputText(content);
                    }
                    
                    // Bring Burp to front? (Not easily possible via API, but tab switch helps)
                }
            } catch(Exception e) {
                 logger.error("Error sending to playground", e);
            }
        });
    }
}
