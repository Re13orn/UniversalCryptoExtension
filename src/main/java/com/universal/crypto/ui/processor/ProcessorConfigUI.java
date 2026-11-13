package com.universal.crypto.ui.processor;

import com.universal.crypto.model.ProcessingAction;

import javax.swing.JPanel;

/**
 * Interface for processor-specific configuration panels.
 */
public interface ProcessorConfigUI {
    
    /**
     * Returns the main panel for this configuration UI.
     */
    JPanel getPanel();

    /**
     * Loads the configuration from the given action into the UI.
     * @param action The action to load configuration from.
     */
    void loadConfig(ProcessingAction action);

    /**
     * Saves the configuration from the UI into the given action.
     * @param action The action to save configuration to.
     */
    void saveConfig(ProcessingAction action);

    /**
     * Validates the current UI configuration.
     * @return true if valid, false otherwise.
     */
    boolean validateConfig();

    /**
     * Called when the action type changes so panels can hide fields that are
     * not relevant to the selected operation.
     */
    default void onActionTypeChanged(String actionType, boolean responseAction) {
        // Optional hook.
    }
}
