package com.universal.crypto.ui.editor;

import org.junit.jupiter.api.Test;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.net.URL;
import java.net.URLClassLoader;
import static org.junit.jupiter.api.Assertions.*;

class EditorReloadTest {
    @Test void reloadUsesLocalKeyboardActionsEvenWhenOldExtensionActionsAreCached() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            Object oldActions = UIManager.get("RSyntaxTextAreaUI.actionMap");
            Object oldInputs = UIManager.get("RSyntaxTextAreaUI.inputMap");
            var oldKeys = JTextComponent.getKeymap("RTextAreaKeymap");
            try {
                UIManager.put("RSyntaxTextAreaUI.actionMap", null);
                JTextComponent.removeKeymap("RTextAreaKeymap");
                URL library = RSyntaxTextArea.class.getProtectionDomain().getCodeSource().getLocation();
                URL project = IsolatedSyntaxTextArea.class.getProtectionDomain().getCodeSource().getLocation();
                // Load the old, unpatched editor to reproduce caches left by earlier releases.
                try (var previous = new URLClassLoader(new URL[]{library}, ClassLoader.getPlatformClassLoader())) {
                    var first = (JTextArea) previous.loadClass("org.fife.ui.rsyntaxtextarea.RSyntaxTextArea").getConstructor().newInstance();
                    first.setText("a"); first.setCaretPosition(1);
                    first.getKeymap().getDefaultAction().actionPerformed(new ActionEvent(first, 0, "x"));
                    assertEquals("ax", first.getText());
                    Object cachedActions = UIManager.get("RSyntaxTextAreaUI.actionMap");
                    try (var unpatched = new URLClassLoader(new URL[]{library}, ClassLoader.getPlatformClassLoader())) {
                        var broken = (JTextArea) unpatched.loadClass("org.fife.ui.rsyntaxtextarea.RSyntaxTextArea").getConstructor().newInstance();
                        broken.setText("a"); broken.setCaretPosition(1);
                        broken.getKeymap().getDefaultAction().actionPerformed(new ActionEvent(broken, 0, "x"));
                        assertEquals("a", broken.getText(), "Old cached action ignores a new class loader's editor");
                    }
                    for (int reload = 0; reload < 3; reload++) {
                        try (var current = new URLClassLoader(new URL[]{project, library}, ClassLoader.getPlatformClassLoader())) {
                            var constructor = current.loadClass(IsolatedSyntaxTextArea.class.getName()).getDeclaredConstructor();
                            constructor.setAccessible(true);
                            var area = (JTextArea) constructor.newInstance();
                            area.setEditable(true); area.setText("{}"); area.setCaretPosition(1);
                            area.getKeymap().getDefaultAction().actionPerformed(new ActionEvent(area, 0, "x"));
                            assertEquals("{x}", area.getText());
                            Object key = area.getInputMap().get(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0));
                            area.getActionMap().get(key).actionPerformed(new ActionEvent(area, 0, ""));
                            assertEquals("{}", area.getText());
                            area.select(0, 2); area.replaceSelection("{\"value\":2}");
                            assertEquals("{\"value\":2}", area.getText());
                            area.updateUI(); area.setCaretPosition(area.getDocument().getLength());
                            area.getKeymap().getDefaultAction().actionPerformed(new ActionEvent(area, 0, " "));
                            assertEquals("{\"value\":2} ", area.getText());
                            area.setEditable(false);
                            area.getKeymap().getDefaultAction().actionPerformed(new ActionEvent(area, 0, "x"));
                            assertEquals("{\"value\":2} ", area.getText());
                            assertSame(cachedActions, UIManager.get("RSyntaxTextAreaUI.actionMap"), "Do not overwrite host or other extension caches");
                        }
                    }
                }
            } catch (Exception e) { throw new RuntimeException(e); }
            finally {
                UIManager.put("RSyntaxTextAreaUI.actionMap", oldActions);
                UIManager.put("RSyntaxTextAreaUI.inputMap", oldInputs);
                JTextComponent.removeKeymap("RTextAreaKeymap");
                if (oldKeys != null) {
                    var restored = JTextComponent.addKeymap("RTextAreaKeymap", oldKeys.getResolveParent());
                    restored.setDefaultAction(oldKeys.getDefaultAction());
                    for (var key : oldKeys.getBoundKeyStrokes()) restored.addActionForKeyStroke(key, oldKeys.getAction(key));
                }
            }
        });
    }
}
