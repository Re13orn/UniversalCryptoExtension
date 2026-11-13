package com.universal.crypto.ui;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;

/**
 * Local UI helpers that keep the extension polished without changing Burp's
 * global look and feel.
 */
final class UIStyle {

    static final int GAP = 10;
    static final int GAP_LG = 16;

    private UIStyle() {
    }

    static Color background() {
        Color color = UIManager.getColor("Panel.background");
        return color != null ? color : new Color(245, 245, 245);
    }

    static Color surface() {
        Color base = background();
        return isDark(base) ? shift(base, 10) : shift(base, -3);
    }

    static Color surfaceAlt() {
        Color base = background();
        return isDark(base) ? shift(base, 18) : shift(base, -8);
    }

    static Color text() {
        Color color = UIManager.getColor("Label.foreground");
        return color != null ? color : Color.DARK_GRAY;
    }

    static Color mutedText() {
        return blend(text(), background(), 0.42f);
    }

    static Color border() {
        return blend(text(), background(), 0.78f);
    }

    static Color accent() {
        Color selection = UIManager.getColor("Table.selectionBackground");
        if (selection != null) {
            return isDark(selection) ? shift(selection, 22) : selection.darker();
        }
        return new Color(205, 88, 58);
    }

    static Color success() {
        return new Color(63, 150, 94);
    }

    static Color danger() {
        return new Color(190, 72, 64);
    }

    static Border emptyBorder() {
        return BorderFactory.createEmptyBorder(GAP_LG, GAP_LG, GAP_LG, GAP_LG);
    }

    static Border compactBorder() {
        return BorderFactory.createEmptyBorder(8, 10, 8, 10);
    }

    static Border sectionBorder(String title) {
        Border outer = BorderFactory.createLineBorder(border());
        Border inner = BorderFactory.createEmptyBorder(10, 12, 12, 12);
        Border compound = BorderFactory.createCompoundBorder(outer, inner);
        return title == null || title.isEmpty()
                ? compound
                : BorderFactory.createTitledBorder(compound, title);
    }

    static JLabel sectionTitle(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 13f));
        label.setForeground(text());
        return label;
    }

    static JLabel mutedLabel(String text) {
        JLabel label = new JLabel(text);
        label.setForeground(mutedText());
        label.setFont(label.getFont().deriveFont(11f));
        return label;
    }

    static JLabel badge(String text, Color color) {
        JLabel label = new JLabel(text);
        label.setOpaque(true);
        label.setForeground(contrastText(color));
        label.setBackground(color);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 11f));
        label.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        return label;
    }

    static JButton button(String text) {
        JButton button = new JButton(text);
        styleButton(button, false, false);
        return button;
    }

    static JButton primaryButton(String text) {
        JButton button = new JButton(text);
        styleButton(button, true, false);
        return button;
    }

    static JButton dangerButton(String text) {
        JButton button = new JButton(text);
        styleButton(button, false, true);
        return button;
    }

    static void styleButton(AbstractButton button, boolean primary, boolean danger) {
        button.setFocusPainted(false);
        button.setOpaque(true);
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(primary ? accent() : danger ? danger() : border()),
                BorderFactory.createEmptyBorder(6, 10, 6, 10)
        ));
        button.setFont(button.getFont().deriveFont(primary ? Font.BOLD : Font.PLAIN));
        if (primary) {
            button.setBackground(accent());
            button.setForeground(contrastText(accent()));
        } else if (danger) {
            button.setBackground(blend(danger(), background(), 0.78f));
            button.setForeground(isDark(background()) ? new Color(255, 188, 180) : danger());
        } else {
            button.setBackground(surface());
            button.setForeground(text());
        }
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    }

    static void styleToolBar(JToolBar toolBar) {
        toolBar.setFloatable(false);
        toolBar.setOpaque(true);
        toolBar.setBackground(surface());
        toolBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, border()),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)
        ));
    }

    static void styleTable(JTable table) {
        sizeTableRows(table);
        if (table.getClientProperty("uce.fontSizing") == null) {
            table.putClientProperty("uce.fontSizing", Boolean.TRUE);
            table.addPropertyChangeListener("font", event -> sizeTableRows(table));
        }
        table.setShowVerticalLines(false);
        table.setShowHorizontalLines(true);
        table.setGridColor(border());
        table.setIntercellSpacing(new Dimension(0, 1));
        table.setFillsViewportHeight(true);
        table.setSelectionBackground(blend(accent(), background(), isDark(background()) ? 0.45f : 0.72f));
        table.setSelectionForeground(text());

        JTableHeader header = table.getTableHeader();
        if (header != null) {
            header.setReorderingAllowed(false);
            header.setFont(header.getFont().deriveFont(Font.BOLD));
            header.setBackground(surfaceAlt());
            header.setForeground(mutedText());
            header.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, border()));
        }
    }

    private static void sizeTableRows(JTable table) {
        Font font = table.getFont();
        if (font == null) font = UIManager.getFont("Table.font");
        if (font == null) font = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        table.setRowHeight(Math.max(30, table.getFontMetrics(font).getHeight() + 10));
    }

    static JScrollPane scroll(JComponent component) {
        JScrollPane scrollPane = new JScrollPane(component);
        scrollPane.setBorder(BorderFactory.createLineBorder(border()));
        scrollPane.getViewport().setBackground(component.getBackground());
        return scrollPane;
    }

    static void styleTextArea(JTextArea textArea, boolean code) {
        textArea.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        textArea.setFont(code
                ? new Font(Font.MONOSPACED, Font.PLAIN, 12)
                : textArea.getFont().deriveFont(12f));
        textArea.setBackground(surface());
        textArea.setForeground(text());
        textArea.setCaretColor(text());
        textArea.setSelectionColor(blend(accent(), background(), 0.65f));
    }

    static Icon icon(IconType type) {
        return new LineIcon(type, 16);
    }

    static Icon dot(Color color) {
        return new DotIcon(color, 9);
    }

    static boolean isDark(Color color) {
        if (color == null) {
            return false;
        }
        double luminance = (0.2126 * color.getRed() + 0.7152 * color.getGreen() + 0.0722 * color.getBlue()) / 255d;
        return luminance < 0.45d;
    }

    private static Color contrastText(Color background) {
        return isDark(background) ? Color.WHITE : new Color(32, 32, 32);
    }

    private static Color shift(Color color, int amount) {
        return new Color(clamp(color.getRed() + amount), clamp(color.getGreen() + amount), clamp(color.getBlue() + amount));
    }

    private static Color blend(Color foreground, Color background, float backgroundWeight) {
        float fg = 1f - backgroundWeight;
        return new Color(
                clamp(Math.round(foreground.getRed() * fg + background.getRed() * backgroundWeight)),
                clamp(Math.round(foreground.getGreen() * fg + background.getGreen() * backgroundWeight)),
                clamp(Math.round(foreground.getBlue() * fg + background.getBlue() * backgroundWeight))
        );
    }

    private static int clamp(int value) {
        return Math.max(0, Math.min(255, value));
    }

    enum IconType {
        TRACE, RULES, SETTINGS, PLAYGROUND, REFRESH, ADD, EDIT, COPY, DELETE, IMPORT, EXPORT, UP, DOWN, WIZARD, LIBRARY, RUN, CLEAR, RECORD
    }

    private static final class DotIcon implements Icon {
        private final Color color;
        private final int size;

        private DotIcon(Color color, int size) {
            this.color = color;
            this.size = size;
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(color);
            g2.fill(new Ellipse2D.Float(x, y + 3, size, size));
            g2.dispose();
        }

        @Override
        public int getIconWidth() {
            return size;
        }

        @Override
        public int getIconHeight() {
            return size + 6;
        }
    }

    private static final class LineIcon implements Icon {
        private final IconType type;
        private final int size;

        private LineIcon(IconType type, int size) {
            this.type = type;
            this.size = size;
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setStroke(new BasicStroke(1.7f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.setColor(c != null && c.isEnabled() ? mutedText() : border());

            int cx = x + size / 2;
            int cy = y + size / 2;
            switch (type) {
                case TRACE:
                    g2.drawOval(x + 2, y + 2, 9, 9);
                    g2.drawLine(x + 10, y + 10, x + 14, y + 14);
                    break;
                case RULES:
                    g2.drawRoundRect(x + 3, y + 2, 10, 12, 3, 3);
                    g2.drawLine(x + 5, y + 6, x + 11, y + 6);
                    g2.drawLine(x + 5, y + 10, x + 10, y + 10);
                    break;
                case SETTINGS:
                    g2.drawOval(x + 5, y + 5, 6, 6);
                    g2.drawLine(cx, y + 1, cx, y + 4);
                    g2.drawLine(cx, y + 12, cx, y + 15);
                    g2.drawLine(x + 1, cy, x + 4, cy);
                    g2.drawLine(x + 12, cy, x + 15, cy);
                    break;
                case PLAYGROUND:
                    g2.drawLine(x + 5, y + 3, x + 11, cy);
                    g2.drawLine(x + 11, cy, x + 5, y + 13);
                    break;
                case REFRESH:
                    g2.drawArc(x + 3, y + 3, 10, 10, 35, 280);
                    g2.drawLine(x + 12, y + 3, x + 13, y + 7);
                    break;
                case ADD:
                    g2.drawLine(cx, y + 3, cx, y + 13);
                    g2.drawLine(x + 3, cy, x + 13, cy);
                    break;
                case EDIT:
                    g2.drawLine(x + 4, y + 12, x + 12, y + 4);
                    g2.drawLine(x + 10, y + 3, x + 13, y + 6);
                    g2.drawLine(x + 3, y + 13, x + 6, y + 12);
                    break;
                case COPY:
                    g2.drawRect(x + 5, y + 3, 8, 9);
                    g2.drawRect(x + 2, y + 6, 8, 8);
                    break;
                case DELETE:
                    g2.drawLine(x + 4, y + 5, x + 12, y + 13);
                    g2.drawLine(x + 12, y + 5, x + 4, y + 13);
                    break;
                case IMPORT:
                    g2.drawLine(cx, y + 3, cx, y + 11);
                    g2.drawLine(x + 5, y + 8, cx, y + 12);
                    g2.drawLine(x + 11, y + 8, cx, y + 12);
                    break;
                case EXPORT:
                    g2.drawLine(cx, y + 12, cx, y + 4);
                    g2.drawLine(x + 5, y + 7, cx, y + 3);
                    g2.drawLine(x + 11, y + 7, cx, y + 3);
                    break;
                case UP:
                    g2.drawLine(cx, y + 4, x + 4, y + 10);
                    g2.drawLine(cx, y + 4, x + 12, y + 10);
                    break;
                case DOWN:
                    g2.drawLine(cx, y + 12, x + 4, y + 6);
                    g2.drawLine(cx, y + 12, x + 12, y + 6);
                    break;
                case WIZARD:
                    Path2D bolt = new Path2D.Float();
                    bolt.moveTo(x + 9, y + 1);
                    bolt.lineTo(x + 4, y + 9);
                    bolt.lineTo(x + 8, y + 9);
                    bolt.lineTo(x + 6, y + 15);
                    bolt.lineTo(x + 12, y + 6);
                    bolt.lineTo(x + 8, y + 6);
                    bolt.closePath();
                    g2.draw(bolt);
                    break;
                case LIBRARY:
                    g2.draw(new RoundRectangle2D.Float(x + 3, y + 3, 10, 11, 2, 2));
                    g2.drawLine(x + 6, y + 3, x + 6, y + 14);
                    break;
                case RUN:
                    Path2D play = new Path2D.Float();
                    play.moveTo(x + 5, y + 3);
                    play.lineTo(x + 12, cy);
                    play.lineTo(x + 5, y + 13);
                    play.closePath();
                    g2.draw(play);
                    break;
                case CLEAR:
                    g2.drawLine(x + 4, y + 4, x + 12, y + 12);
                    g2.drawLine(x + 12, y + 4, x + 4, y + 12);
                    g2.drawOval(x + 2, y + 2, 12, 12);
                    break;
                case RECORD:
                    g2.fillOval(x + 4, y + 4, 8, 8);
                    break;
                default:
                    g2.drawOval(x + 3, y + 3, 10, 10);
            }
            g2.dispose();
        }

        @Override
        public int getIconWidth() {
            return size;
        }

        @Override
        public int getIconHeight() {
            return size;
        }
    }
}
