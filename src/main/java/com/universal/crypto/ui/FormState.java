package com.universal.crypto.ui;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Explicitly ordered form fields; combo indexes also survive translated option labels. */
final class FormState {
    private final List<Object> values = new ArrayList<>();

    private record ComboValue(int index, Object item) {
        static ComboValue capture(JComboBox<?> combo) {
            Object item = combo.isEditable() ? combo.getEditor().getItem() : combo.getSelectedItem();
            // A typed value may not have been committed to the combo model yet.
            int index = combo.isEditable() && !Objects.equals(item, combo.getSelectedItem())
                    ? -1 : combo.getSelectedIndex();
            return new ComboValue(index, item);
        }
    }

    static FormState capture(Component... fields) {
        FormState state = new FormState();
        for (Component field : fields) {
            state.values.add(field instanceof JComboBox<?> combo ? ComboValue.capture(combo)
                    : field instanceof JTextComponent text ? text.getText()
                    : field instanceof AbstractButton button ? button.isSelected() : null);
        }
        return state;
    }

    void restore(Component... fields) {
        // Restore controls first: their listeners can change dependent text fields.
        for (int i = 0; i < fields.length; i++) {
            Object value = values.get(i);
            if (fields[i] instanceof JComboBox<?> combo && value instanceof ComboValue selected) {
                if (selected.index() >= 0 && selected.index() < combo.getItemCount())
                    combo.setSelectedIndex(selected.index());
                else if (combo.isEditable()) combo.setSelectedItem(selected.item());
            }
            else if (fields[i] instanceof AbstractButton button && value instanceof Boolean selected)
                button.setSelected(selected);
        }
        for (int i = 0; i < fields.length; i++) {
            if (fields[i] instanceof JTextComponent text && values.get(i) instanceof String value)
                text.setText(value);
        }
    }
}
