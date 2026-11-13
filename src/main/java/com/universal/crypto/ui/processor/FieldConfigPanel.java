package com.universal.crypto.ui.processor;

import com.universal.crypto.util.LanguageManager;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

public class FieldConfigPanel implements ProcessorConfigUI {

    private final JPanel panel;
    private final JTextField replacementValueField;
    private final JCheckBox overwriteCheck;
    private final JCheckBox ignoreNotFoundCheck;
    private final JTextArea tipsArea;
    private JLabel valueLabel;

    public FieldConfigPanel() {
        panel = new JPanel(new GridBagLayout());
        panel.setBackground(ProcessorUIStyle.background());
        panel.setBorder(ProcessorUIStyle.pageBorder());

        tipsArea = ProcessorUIStyle.note(LanguageManager.getInstance().getString("script.help.field.intro")
                + LanguageManager.getInstance().getString("script.help.field.1")
                + LanguageManager.getInstance().getString("script.help.field.2")
                + LanguageManager.getInstance().getString("script.help.field.3"));

        JPanel section = ProcessorUIStyle.section(LanguageManager.getInstance().getString("script.help.field.group"));
        GridBagConstraints gbc = ProcessorUIStyle.gbc();
        
        int row = 0;
        
        gbc.gridx = 0; gbc.gridy = row;
        gbc.gridwidth = 2;
        panel.add(tipsArea, gbc);
        gbc.gridwidth = 1;
        row++;

        // Fields
        replacementValueField = new JTextField();
        replacementValueField.setToolTipText(LanguageManager.getInstance().getString("script.help.field.hint"));
        addLabelAndField(section, LanguageManager.getInstance().getString("script.help.field.value"), replacementValueField, gbc, 0);
        
        overwriteCheck = new JCheckBox(LanguageManager.getInstance().getString("script.help.field.overwrite"));
        addLabelAndField(section, "", overwriteCheck, gbc, 1);

        ignoreNotFoundCheck = new JCheckBox(LanguageManager.getInstance().getString("script.help.field.ignore"));
        addLabelAndField(section, "", ignoreNotFoundCheck, gbc, 2);

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        panel.add(section, gbc);
    }

    private void addLabelAndField(JPanel p, String labelText, JComponent field, GridBagConstraints gbc, int row) {
        gbc.gridx = 0; 
        gbc.gridy = row;
        gbc.weightx = 0.0;
        JLabel label = new JLabel(labelText);
        label.setForeground(ProcessorUIStyle.text());
        p.add(label, gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        if (field instanceof JCheckBox) {
            field.setOpaque(false);
        }
        p.add(field, gbc);

        field.putClientProperty("label", label);
        if (field == replacementValueField) {
            valueLabel = label;
        }
    }

    @Override
    public JPanel getPanel() {
        return panel;
    }

    @Override
    public void loadConfig(ProcessingAction action) {
        Map<String, Object> config = action.getConfig();
        if (config == null) config = new HashMap<>();

        replacementValueField.setText(stringValue(config.get(ConfigKey.TO)));
        overwriteCheck.setSelected(booleanValue(config.get(ConfigKey.OVERWRITE)));
        ignoreNotFoundCheck.setSelected(booleanValue(config.get(ConfigKey.IGNORE_NOT_FOUND)));
        
        String actionType = action.getActionType();
        updateVisibility(actionType);
    }
    
    public void updateVisibility(String actionType) {
        overwriteCheck.setVisible(Constants.ActionType.ADD.equals(actionType));
        ignoreNotFoundCheck.setVisible(Constants.ActionType.REMOVE.equals(actionType));
        replacementValueField.setVisible(!Constants.ActionType.REMOVE.equals(actionType));
        if (valueLabel != null) {
            valueLabel.setVisible(!Constants.ActionType.REMOVE.equals(actionType));
        }
        panel.revalidate();
        panel.repaint();
    }

    @Override
    public void saveConfig(ProcessingAction action) {
        Map<String, Object> config = action.getConfig();
        if (config == null) {
            config = new HashMap<>();
            action.setConfig(config);
        }
        
        config.put(ConfigKey.TO, replacementValueField.getText());
        config.put(ConfigKey.OVERWRITE, overwriteCheck.isSelected());
        config.put(ConfigKey.IGNORE_NOT_FOUND, ignoreNotFoundCheck.isSelected());
    }

    @Override
    public boolean validateConfig() {
        return true; // Simple field config usually valid
    }

    private String stringValue(Object obj) {
        return obj == null ? "" : obj.toString();
    }

    private boolean booleanValue(Object obj) {
        if (obj instanceof Boolean) return (Boolean) obj;
        return "true".equalsIgnoreCase(stringValue(obj));
    }
}
