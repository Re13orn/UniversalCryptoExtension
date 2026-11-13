package com.universal.crypto.ui;

import javax.swing.JSplitPane;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;

final class SplitPaneLayout {
    private SplitPaneLayout() {}

    static void initialize(JSplitPane pane, double ratio) {
        pane.setResizeWeight(ratio);
        pane.addComponentListener(new ComponentAdapter() {
            @Override public void componentResized(ComponentEvent event) {
                int size = pane.getOrientation() == JSplitPane.VERTICAL_SPLIT ? pane.getHeight() : pane.getWidth();
                if (size > 0) {
                    pane.setDividerLocation(ratio);
                    pane.removeComponentListener(this);
                }
            }
        });
    }

    static double ratio(JSplitPane pane, double fallback) {
        if (pane == null) return fallback;
        int size = pane.getOrientation() == JSplitPane.VERTICAL_SPLIT ? pane.getHeight() : pane.getWidth();
        return size > 0 && pane.getDividerLocation() >= 0
                ? Math.max(0.1, Math.min(0.9, (double) pane.getDividerLocation() / size)) : fallback;
    }
}
