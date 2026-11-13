package com.universal.crypto.ui;

import com.universal.crypto.model.ProcessingAction;
import java.awt.KeyboardFocusManager;
import java.awt.Window;
import java.util.function.Consumer;

/** Keeps the test window inside the editing dialog's modal ownership chain. */
@FunctionalInterface
interface ActionTestNavigator extends Consumer<ProcessingAction> {
    void open(Window owner, ProcessingAction action, boolean responseAction);

    @Override default void accept(ProcessingAction action) {
        String phase = action.getConfigString("executionPhase", "");
        open(KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow(), action,
                phase.startsWith("response-"));
    }
}
