package com.universal.crypto.ui.processor;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import java.awt.*;

final class ProcessorUIStyle {

    private ProcessorUIStyle() {
    }

    static Color background() {
        Color color = UIManager.getColor("Panel.background");
        return color != null ? color : new Color(245, 245, 245);
    }

    static Color surface() {
        Color base = background();
        return isDark(base) ? shift(base, 12) : shift(base, -4);
    }

    static Color text() {
        Color color = UIManager.getColor("Label.foreground");
        return color != null ? color : Color.DARK_GRAY;
    }

    static Color mutedText() {
        return blend(text(), background(), 0.46f);
    }

    static Color border() {
        return blend(text(), background(), 0.78f);
    }

    static Border pageBorder() {
        return BorderFactory.createEmptyBorder(14, 14, 14, 14);
    }

    static JPanel formPanel() { return new FormPanel(); }

    private static final class FormPanel extends JPanel implements Scrollable {
        FormPanel() { setLayout(new BoxLayout(this, BoxLayout.Y_AXIS)); }
        public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        public int getScrollableUnitIncrement(Rectangle visible, int orientation, int direction) { return 20; }
        public int getScrollableBlockIncrement(Rectangle visible, int orientation, int direction) { return Math.max(20, visible.height - 20); }
        public boolean getScrollableTracksViewportWidth() { return true; }
        public boolean getScrollableTracksViewportHeight() { return false; }
    }

    static JPanel section(String title) {
        JPanel panel = new JPanel(new GridBagLayout()) {
            @Override public Dimension getMaximumSize() {
                return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
            }
        };
        panel.setBackground(background());
        Border outer = BorderFactory.createLineBorder(border());
        Border inner = BorderFactory.createEmptyBorder(10, 12, 12, 12);
        TitledBorder titled = BorderFactory.createTitledBorder(
                BorderFactory.createCompoundBorder(outer, inner),
                title,
                TitledBorder.LEFT,
                TitledBorder.TOP
        );
        titled.setTitleFont(new JLabel().getFont().deriveFont(Font.BOLD, 12f));
        titled.setTitleColor(text());
        panel.setBorder(titled);
        return panel;
    }

    static JTextArea note(String text) {
        JTextArea note = new JTextArea(text);
        note.setEditable(false);
        note.setOpaque(true);
        note.setBackground(surface());
        note.setForeground(mutedText());
        note.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(border()),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)
        ));
        note.setLineWrap(true);
        note.setWrapStyleWord(true);
        note.setFont(note.getFont().deriveFont(12f));
        return note;
    }

    static void keepPreferredHeight(JComponent component) {
        Dimension preferred = component.getPreferredSize();
        component.setMaximumSize(new Dimension(Integer.MAX_VALUE, preferred.height));
    }

    static void styleTextArea(JTextArea textArea, boolean code) {
        textArea.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        textArea.setFont(code ? new Font(Font.MONOSPACED, Font.PLAIN, 12) : textArea.getFont().deriveFont(12f));
        textArea.setBackground(surface());
        textArea.setForeground(text());
        textArea.setCaretColor(text());
        textArea.setSelectionColor(blend(new Color(205, 88, 58), background(), 0.65f));
    }

    static void styleButton(AbstractButton button) {
        button.setFocusPainted(false);
        button.setOpaque(true);
        button.setBackground(surface());
        button.setForeground(text());
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(border()),
                BorderFactory.createEmptyBorder(5, 9, 5, 9)
        ));
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    }

    static GridBagConstraints gbc() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 6, 5, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        return gbc;
    }

    private static boolean isDark(Color color) {
        double luminance = (0.2126 * color.getRed() + 0.7152 * color.getGreen() + 0.0722 * color.getBlue()) / 255d;
        return luminance < 0.45d;
    }

    private static Color shift(Color color, int amount) {
        return new Color(clamp(color.getRed() + amount), clamp(color.getGreen() + amount), clamp(color.getBlue() + amount));
    }

    private static Color blend(Color foreground, Color background, float backgroundWeight) {
        float foregroundWeight = 1f - backgroundWeight;
        return new Color(
                clamp(Math.round(foreground.getRed() * foregroundWeight + background.getRed() * backgroundWeight)),
                clamp(Math.round(foreground.getGreen() * foregroundWeight + background.getGreen() * backgroundWeight)),
                clamp(Math.round(foreground.getBlue() * foregroundWeight + background.getBlue() * backgroundWeight))
        );
    }

    private static int clamp(int value) {
        return Math.max(0, Math.min(255, value));
    }
}
