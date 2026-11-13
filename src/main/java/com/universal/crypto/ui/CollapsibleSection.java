package com.universal.crypto.ui;

import javax.swing.*;
import java.awt.*;

/** A keyboard-accessible disclosure. Its fields stay mounted and retain their values. */
public final class CollapsibleSection extends JPanel {
    private final JToggleButton toggle;
    private final JComponent content;
    private final String title;
    private boolean configured;

    public CollapsibleSection(String title, JComponent content) {
        super(new BorderLayout(0, 6));
        this.title = title;
        this.content = content;
        setOpaque(false);
        setAlignmentX(Component.LEFT_ALIGNMENT);
        toggle = new JToggleButton();
        toggle.setHorizontalAlignment(SwingConstants.LEFT);
        toggle.setContentAreaFilled(false);
        toggle.setBorder(BorderFactory.createEmptyBorder(6, 4, 6, 4));
        toggle.addActionListener(e -> update());
        add(toggle, BorderLayout.NORTH);
        add(content, BorderLayout.CENTER);
        update();
    }

    public void setConfigured(boolean configured) {
        this.configured = configured;
        // Existing non-default values are visible when a form is loaded.
        setExpanded(configured);
    }

    public void setExpanded(boolean expanded) {
        toggle.setSelected(expanded);
        update();
    }

    public boolean isExpanded() { return toggle.isSelected(); }

    private void update() {
        boolean expanded = toggle.isSelected();
        String suffix = configured ? " · " + com.universal.crypto.util.LanguageManager.getInstance().getString("form.advanced.configured") : "";
        toggle.setText((expanded ? "▾ " : "▸ ") + title + suffix);
        toggle.getAccessibleContext().setAccessibleName(title + suffix);
        content.setVisible(expanded);
        revalidate();
        repaint();
    }

    @Override public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
    }
}
