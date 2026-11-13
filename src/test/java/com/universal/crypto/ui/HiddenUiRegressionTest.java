package com.universal.crypto.ui;

import com.universal.crypto.engine.*;
import com.universal.crypto.model.*;
import com.universal.crypto.processor.*;
import com.universal.crypto.ui.processor.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.lang.reflect.*;
import java.net.URL;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

class HiddenUiRegressionTest {
    @TempDir Path temp;

    @Test void untouchedScopeListsRetainLiteralCommasAndTheirMatchingBehavior() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        var original = new ProcessingRule("literal-comma"); original.setName("Comma path");
        var condition = new RuleCondition(); condition.setHosts(List.of("example.test"));
        condition.setPaths(List.of("/api/items/a,b")); condition.setMethods(List.of("post")); original.setCondition(condition);
        original.addRequestAction(new ProcessingAction("execute", "body", "script"));
        var dialog = new RuleEditDialog(null, original, null);
        try {
            get(dialog, "nameField", JTextField.class).setText("Rename only");
            var saved = dialog.buildDraft();
            assertEquals(condition.getHosts(), saved.getCondition().getHosts());
            assertEquals(condition.getPaths(), saved.getCondition().getPaths());
            assertEquals(condition.getMethods(), saved.getCondition().getMethods());
            var context = RuleMatchEngine.createRequestContext("POST", new URL("https://example.test/api/items/a,b"), Map.of(), "", "REPEATER");
            var match = new RuleMatchEngine();
            assertEquals(1, match.findMatchingRules(List.of(original), context).size());
            assertEquals(1, match.findMatchingRules(List.of(saved), context).size());
            get(dialog, "pathsField", JTextField.class).setText("/api/next, /api/other");
            assertEquals(List.of("/api/next", "/api/other"), dialog.buildDraft().getCondition().getPaths());
        } finally { dialog.dispose(); }
    }

    private ProcessingRule responseRule() {
        var rule=DefaultRuleFactory.verifiedExampleRules().get(9);
        rule.setEnabled(true);rule.setPriority(-7);rule.getCondition().setToolSource("REPEATER");
        rule.getCondition().setHeaders(Map.of("X-Required",""));
        rule.getCondition().setContentPattern(" hello ");return rule;
    }

    @Test void savingResponseOnlyRuleKeepsScopeEmptyHeaderConditionAndOriginalObject() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        var original=responseRule();String before=RuleSerializer.exportRules(List.of(original));
        RuleEditDialog dialog=new RuleEditDialog(null,original,null);
        try {
            get(dialog,"nameField",JTextField.class).setText("Edited rule");
            invoke(dialog,"saveRule",java.awt.event.ActionEvent.class,null);
            assertTrue(dialog.isConfirmed());var saved=dialog.getRule();
            assertEquals("REPEATER",saved.getCondition().getToolSource());
            assertEquals("",saved.getCondition().getHeaders().get("X-Required"));
            assertEquals(" hello ",saved.getCondition().getContentPattern());assertEquals(-7,saved.getPriority());
            assertEquals(before,RuleSerializer.exportRules(List.of(original)));
            RuleMatchEngine match=new RuleMatchEngine();URL url=new URL("https://api.example.test/api/demo");
            assertEquals(1,match.findMatchingRules(List.of(saved),RuleMatchEngine.createResponseContext("POST",url,Map.of("X-Required","")," hello ","REPEATER")).size());
            assertEquals(0,match.findMatchingRules(List.of(saved),RuleMatchEngine.createResponseContext("POST",url,Map.of("X-Required","")," hello ","PROXY")).size());
            assertEquals(0,match.findMatchingRules(List.of(saved),RuleMatchEngine.createResponseContext("POST",url,Map.of()," hello ","REPEATER")).size());
        }finally{dialog.dispose();}
    }

    @Test void invalidDraftDoesNotMutateTheOriginalRuleAndBlankDraftCannotBeSaved() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        var original=responseRule();String before=RuleSerializer.exportRules(List.of(original));
        RuleEditDialog dialog=new RuleEditDialog(null,original,null);
        try {
            get(dialog,"nameField",JTextField.class).setText("unsaved");
            get(dialog,"headerConditionsArea",JTextArea.class).setText("malformed header");
            assertThrows(IllegalArgumentException.class,dialog::buildDraft);
            get(dialog,"headerConditionsArea",JTextArea.class).setText("X-*: *");
            get(dialog,"contentPatternArea",JTextArea.class).setText("[");
            assertThrows(java.util.regex.PatternSyntaxException.class,dialog::buildDraft);
            assertEquals(before,RuleSerializer.exportRules(List.of(original)));
        }finally{dialog.dispose();}
        RuleEditDialog empty=new RuleEditDialog(null,null,null);
        try{get(empty,"nameField",JTextField.class).setText("empty");assertThrows(IllegalArgumentException.class,empty::buildDraft);}
        finally{empty.dispose();}
    }

    @Test void customToolScopeAndTypedPrioritySurviveRuleEditing() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        var rule=responseRule();rule.getCondition().setToolSource("CUSTOM_CAPTURE");rule.setPriority(5001);
        RuleEditDialog dialog=new RuleEditDialog(null,rule,null);
        try {
            assertEquals("CUSTOM_CAPTURE",get(dialog,"toolSourceCombo",JComboBox.class).getSelectedItem());
            JSpinner spinner=get(dialog,"prioritySpinner",JSpinner.class);
            ((JSpinner.DefaultEditor)spinner.getEditor()).getTextField().setText("-2147483648");
            var result=dialog.buildDraft();assertEquals(Integer.MIN_VALUE,result.getPriority());
            assertEquals("CUSTOM_CAPTURE",result.getCondition().getToolSource());
        }finally{dialog.dispose();}
    }

    @Test void nestedDialogOwnersDoNotRequireAFrame() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        JDialog library=new JDialog();RuleEditDialog ruleEditor=new RuleEditDialog(library,responseRule(),null);
        ActionEditDialog step=new ActionEditDialog(ruleEditor,responseRule().getResponseActions().get(0),true,null);
        QuickRuleWizardDialog wizard=new QuickRuleWizardDialog(library,"api.example.test","/api/demo");
        try{assertSame(library,ruleEditor.getOwner());assertSame(ruleEditor,step.getOwner());assertSame(library,wizard.getOwner());}
        finally{wizard.dispose();step.dispose();ruleEditor.dispose();library.dispose();}
    }

    @Test void scriptTypeBodyInputAliasOpaqueConfigAndCancellationArePreserved() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        ProcessingAction original=new ProcessingAction("execute","header","X-Value","script");
        original.setConfig("scriptCode","return content;");original.setConfig("executionPhase","send");
        original.setConfig("inputSource","body");original.setConfig("algorithm","opaque-metadata");original.setEnabled(false);
        ActionEditDialog dialog=new ActionEditDialog(null,original,false,null);
        try {
            var saved=dialog.buildAction();assertEquals("execute",saved.getActionType());assertEquals("script",saved.getProcessor());
            assertEquals("body",saved.getConfigString("inputSource"));assertEquals("opaque-metadata",saved.getConfigString("algorithm"));assertFalse(saved.isEnabled());
            get(dialog,"actionTypeCombo",JComboBox.class).setSelectedItem("encrypt");assertEquals("script",get(dialog,"processorCombo",JComboBox.class).getSelectedItem());
            assertEquals("execute",original.getActionType());assertEquals("send",original.getConfigString("executionPhase"));
        }finally{dialog.dispose();}
    }

    @Test void renamingVariableChangesActualPipelineOutput() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        ProcessingAction original=new ProcessingAction("execute","variable","script");
        original.setConfig("variableName","oldNonce");original.setConfig("scriptCode","return 'token';");original.setConfig("executionPhase","send");
        ActionEditDialog dialog=new ActionEditDialog(null,original,false,null);
        try {
            assertEquals("oldNonce",get(dialog,"targetNameField",JTextField.class).getText());
            get(dialog,"targetNameField",JTextField.class).setText("newNonce");var saved=dialog.buildAction();
            assertEquals("newNonce",saved.getConfigString("variableName"));
            var context=ProcessorContext.forRequest("POST",new URL("https://example.test/"),Map.of(),"REPEATER").build();
            var pipeline=new ActionPipeline(context,"body",null);assertTrue(pipeline.execute(ProcessorFactory.createDefaultProcessorManager(null),saved).isSuccess());
            assertEquals("token",context.getSharedData("newNonce"));assertNull(context.getSharedData("oldNonce"));
            assertEquals("oldNonce",original.getConfigString("variableName"));
        }finally{dialog.dispose();}
    }

    @Test void fieldPathRenameIsUsedByTheRealProcessor() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        ProcessingAction original=new ProcessingAction("replace","field","$.ignored","field");
        original.setConfig("operation","replace");original.setConfig("fieldPath","$.old");original.setConfig("to","new");original.setConfig("executionPhase","send");
        ActionEditDialog dialog=new ActionEditDialog(null,original,false,null);
        try {
            assertEquals("$.old",get(dialog,"targetNameField",JTextField.class).getText());
            get(dialog,"targetNameField",JTextField.class).setText("$.next");var saved=dialog.buildAction();assertEquals("$.next",saved.getConfigString("fieldPath"));
            var context=ProcessorContext.forRequest("POST",new URL("https://example.test/"),Map.of(),"REPEATER").build();
            var result=ProcessorFactory.createDefaultProcessorManager(null).process(saved,"{\"old\":\"before\",\"next\":\"before\"}",context);
            assertTrue(result.isSuccess(),result.getErrorMessage());
            var json=new com.fasterxml.jackson.databind.ObjectMapper().readTree(result.getProcessedContent());
            assertEquals("before",json.get("old").asText());assertEquals("new",json.get("next").asText());
        }finally{dialog.dispose();}
    }

    @Test void extraParametersCannotSilentlyOverrideGeneralFieldsAndCanBeDeleted() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        ProcessingAction original=new ProcessingAction("execute","body","script");original.setConfig("scriptCode","return content;");original.setConfig("customFlag",true);
        ActionEditDialog dialog=new ActionEditDialog(null,original,false,null);
        try {
            var model=get(dialog,"extraConfigModel",DefaultTableModel.class);model.setRowCount(0);assertFalse(dialog.buildAction().hasConfig("customFlag"));
            model.addRow(new Object[]{"executionPhase","response-send"});assertThrows(IllegalArgumentException.class,dialog::buildAction);
            model.setRowCount(0);model.addRow(new Object[]{"same",1});model.addRow(new Object[]{"same",2});assertThrows(IllegalArgumentException.class,dialog::buildAction);
            assertEquals(Boolean.TRUE,original.getConfig("customFlag"));
        }finally{dialog.dispose();}
    }

    @Test void noOpSignatureSaveKeepsLegacyModeAndEditingTemplateExplicitlyChangesIt() throws Exception {
        for(String mode:List.of("body","method+path+body","timestamp+method+path+body")) {
            SignatureConfigPanel panel=new SignatureConfigPanel();ProcessingAction action=new ProcessingAction("sign","header","signature");
            action.setConfig("algorithm","HMAC-SHA256");action.setConfig("keySource","static");action.setConfig("keyValue","secret");action.setConfig("signContent",mode);
            panel.loadConfig(action);ProcessingAction saved=action.clone();panel.saveConfig(saved);
            assertEquals(mode,saved.getConfigString("signContent"));assertFalse(saved.hasConfig("customSignTemplate"));
            get(panel,"customSignTemplateArea",JTextArea.class).setText("${body}changed");panel.saveConfig(saved);
            assertEquals("custom",saved.getConfigString("signContent"));assertEquals("${body}changed",saved.getConfigString("customSignTemplate"));
        }
    }

    @Test void algorithmTransitionsRestoreKeySourcesAndDoNotForceExternalNone() throws Exception {
        CryptoConfigPanel crypto=new CryptoConfigPanel();ProcessingAction action=new ProcessingAction("encrypt","body","crypto");
        action.setConfig("algorithm","AES-CBC");action.setConfig("cryptoProvider","internal");action.setConfig("keySource","lookup");
        crypto.loadConfig(action);get(crypto,"algorithmCombo",JComboBox.class).setSelectedItem("Base64");
        ProcessingAction saved=new ProcessingAction();crypto.saveConfig(saved);assertEquals("none",saved.getConfigString("keySource"));
        get(crypto,"algorithmCombo",JComboBox.class).setSelectedItem("AES-CBC");crypto.saveConfig(saved);assertEquals("lookup",saved.getConfigString("keySource"));
        get(crypto,"algorithmCombo",JComboBox.class).setSelectedItem("Base64");select(get(crypto,"cryptoProviderCombo",JComboBox.class),"external");
        crypto.saveConfig(saved);assertEquals("lookup",saved.getConfigString("keySource"));
        SignatureConfigPanel sign=new SignatureConfigPanel();action.setActionType("sign");action.setConfig("algorithm","HMAC-SHA256");action.setConfig("signContent","body");
        sign.loadConfig(action);get(sign,"algorithmCombo",JComboBox.class).setSelectedItem("SHA-256");select(get(sign,"hashKeyPlacementCombo",JComboBox.class),"none");
        sign.saveConfig(saved);assertEquals("none",saved.getConfigString("keySource"));
        get(sign,"algorithmCombo",JComboBox.class).setSelectedItem("HMAC-SHA256");sign.saveConfig(saved);assertEquals("lookup",saved.getConfigString("keySource"));
    }

    @Test void tableRowsFollowFontSizeWithoutAccumulatingListeners() throws Exception {
        SwingUtilities.invokeAndWait(()->{
            JTable table=new JTable(1,1);UIStyle.styleTable(table);int listeners=table.getPropertyChangeListeners("font").length;
            UIStyle.styleTable(table);assertEquals(listeners,table.getPropertyChangeListeners("font").length);
            table.setFont(table.getFont().deriveFont(32f));assertTrue(table.getRowHeight()>=table.getFontMetrics(table.getFont()).getHeight()+10);
            table.setFont(null);assertTrue(table.getRowHeight()>=30);
        });
    }

    @Test void sortedMultiselectionSurvivesRefreshAndDetailsExplainBatchScope() throws Exception {
        RuleManager manager=new RuleManager(new RuleConfigStorage(temp.toString()));
        for(String name:List.of("Zulu","Alpha","Beta")){var rule=new ProcessingRule(name);rule.setName(name);rule.setCategory("test");manager.addRule(rule);}
        SwingUtilities.invokeAndWait(()->{
            RuleManagementPanel panel=new RuleManagementPanel(null,manager,null);JTable table=get(panel,"rulesTable",JTable.class);
            table.getRowSorter().toggleSortOrder(1);table.getRowSorter().toggleSortOrder(1);table.setRowSelectionInterval(0,1);
            var keys=List.copyOf(table.getRowSorter().getSortKeys());panel.refresh();table=get(panel,"rulesTable",JTable.class);
            assertEquals(keys,table.getRowSorter().getSortKeys());assertEquals("Zulu",table.getValueAt(0,1));assertEquals(2,table.getSelectedRowCount());
            String text=get(panel,"ruleDetailsArea",JTextArea.class).getText();assertTrue(text.contains("2"));assertTrue(text.contains("batch")||text.contains("批量"));
        });
    }

    private static void select(JComboBox<?> combo,String value){for(int i=0;i<combo.getItemCount();i++){String item=String.valueOf(combo.getItemAt(i));if(item.equals(value)||item.endsWith("("+value+")")||("external".equals(value)&&("调用外部服务".equals(item)||"External service".equals(item)))||("internal".equals(value)&&("本地计算".equals(item)||"Local computation".equals(item)))||("none".equals(value)&&("不拼接密钥".equals(item)||"不需要密钥".equals(item)||"No key".equals(item)||"Do not concatenate key".equals(item)))){combo.setSelectedIndex(i);return;}}throw new AssertionError(value);}
    private static <T> T get(Object object,String name,Class<T> type){try{Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return type.cast(f.get(object));}catch(Exception ex){throw new RuntimeException(ex);}}
    private static void invoke(Object o,String name,Class<?> type,Object value){try{Method m=o.getClass().getDeclaredMethod(name,type);m.setAccessible(true);m.invoke(o,value);}catch(Exception ex){throw new RuntimeException(ex);}}
}
