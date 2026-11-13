package com.universal.crypto.ui.editor;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextAreaDefaultInputMap;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextAreaUI;
import org.fife.ui.rtextarea.RTextAreaUI;

import javax.swing.*;
import javax.swing.text.DefaultEditorKit;
import javax.swing.text.JTextComponent;
import javax.swing.text.Keymap;

/** Prevent Swing's process-wide caches from retaining actions from an unloaded extension. */
final class IsolatedSyntaxTextArea extends RSyntaxTextArea {
    @Override protected RTextAreaUI createRTextAreaUI() {
        return new RSyntaxTextAreaUI(this) {
            @Override protected void installKeyboardActions() {
                // RTextAreaUI normally caches actions in UIManager and a named keymap.
                // Those actions instanceof-check RTextArea from their own class loader,
                // so they silently ignore editors created after a Burp extension reload.
                var area = getRTextArea();
                Keymap keys = JTextComponent.addKeymap(null, JTextComponent.getKeymap("default"));
                keys.setDefaultAction(new DefaultEditorKit.DefaultKeyTypedAction());
                area.setKeymap(keys);
                SwingUtilities.replaceUIInputMap(area, JComponent.WHEN_FOCUSED, new RSyntaxTextAreaDefaultInputMap());
                ActionMap actions = createRTextAreaActionMap();
                actions.put("requestFocus", new AbstractAction() {
                    @Override public void actionPerformed(java.awt.event.ActionEvent e) { area.requestFocusInWindow(); }
                });
                SwingUtilities.replaceUIActionMap(area, actions);
            }
        };
    }
}
