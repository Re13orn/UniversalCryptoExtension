package com.universal.crypto.ui;

import com.universal.crypto.engine.*;
import com.universal.crypto.model.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import javax.swing.*;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class PresetCatalogTest {
    @TempDir Path temp;

    @Test void packagedCatalogMatchesMaintainedRuleAndFixtureFiles() throws Exception {
        Path assets=Path.of("skills/universal-crypto-rules/assets/examples");
        try(var files=Files.list(assets)) {
            for(Path file:files.filter(p->p.getFileName().toString().endsWith(".json")).toList()) {
                try(var input=getClass().getResourceAsStream("/com/universal/crypto/presets/"+file.getFileName())) {
                    assertNotNull(input,file.toString());assertArrayEquals(Files.readAllBytes(file),input.readAllBytes(),file.toString());
                }
            }
        }
        var rules=DefaultRuleFactory.getAllDefaultRules();
        assertEquals(10,rules.size());assertEquals(10,rules.stream().map(ProcessingRule::getId).distinct().count());
        assertTrue(rules.stream().noneMatch(ProcessingRule::isEnabled));
        assertEquals(10,rules.stream().filter(r->"可验证示例".equals(r.getCategory())).count());
        for(var rule:rules)for(var action:rule.getRequestActions()) {
            assertTrue(action.hasConfig("executionPhase"));
            if("signature".equals(action.getProcessor())) {
                assertEquals("request-body",action.getConfigString("inputSource"));assertTrue(action.hasConfig("cryptoProvider"));
            }
        }
    }

    @Test void librarySearchShowsFullCurrentResponseEditFlow() throws Exception {
        RuleManager manager=new RuleManager(new RuleConfigStorage(temp.toString()));
        SwingUtilities.invokeAndWait(()->{
            PresetRuleLibraryPanel panel=new PresetRuleLibraryPanel(null,manager,null);
            get(panel,"searchField",JTextField.class).setText("response-editor-send");
            JList<?> list=get(panel,"presetRuleList",JList.class);
            assertEquals(1,list.getModel().getSize());list.setSelectedIndex(0);
            String details=get(panel,"ruleDescriptionArea",JTextArea.class).getText();
            assertTrue(details.contains("AAD"),details);assertTrue(details.contains("decrypt")||details.contains("解密"),details);
            assertTrue(details.contains("encrypt")||details.contains("加密"),details);assertTrue(details.contains("X-Response-Signature"),details);
            get(panel,"searchField",JTextField.class).setText("no matching rule");
            assertEquals(0,list.getModel().getSize());assertFalse(get(panel,"addButton",JButton.class).isEnabled());
            assertEquals("",get(panel,"ruleDescriptionArea",JTextArea.class).getText());
        });
    }

    @Test void addingPresetPersistsDisabledDraftWithoutChangingTemplateOrExistingRule() throws Exception {
        RuleConfigStorage storage=new RuleConfigStorage(temp.toString());RuleManager manager=new RuleManager(storage);
        PresetRuleLibraryPanel panel=new PresetRuleLibraryPanel(null,manager,null);
        ProcessingRule template=DefaultRuleFactory.verifiedExampleRules().get(9);template.setEnabled(true);
        panel.addDraft(template);
        List<ProcessingRule> saved=storage.loadRules();assertEquals(1,saved.size());assertFalse(saved.get(0).isEnabled());
        assertTrue(template.isEnabled());assertEquals(3,saved.get(0).getResponseActions().size());
        assertThrows(IllegalArgumentException.class,()->panel.addDraft(template));
        assertEquals(1,manager.getRuleCount());assertFalse(manager.getRuleById(template.getId()).isEnabled());
    }

    @Test void failedSaveDoesNotLeaveAnUnsavedPresetInMemory() throws Exception {
        RuleConfigStorage storage=new RuleConfigStorage(temp.toString());RuleManager manager=new RuleManager(storage);
        Files.createDirectory(Path.of(storage.getConfigFilePath()));
        PresetRuleLibraryPanel panel=new PresetRuleLibraryPanel(null,manager,null);
        assertThrows(RuntimeException.class,()->panel.addDraft(DefaultRuleFactory.verifiedExampleRules().get(0)));
        assertEquals(0,manager.getRuleCount());
    }

    @Test void newPresetCategoriesAreAvailableInRuleManagementFilters() throws Exception {
        RuleManager manager=new RuleManager(new RuleConfigStorage(temp.toString()));
        manager.addRule(DefaultRuleFactory.verifiedExampleRules().get(0));
        SwingUtilities.invokeAndWait(()->{
            RuleManagementPanel panel=new RuleManagementPanel(null,manager,null);
            JComboBox<?> categories=get(panel,"categoryFilter",JComboBox.class);
            categories.setSelectedItem("可验证示例");
            assertEquals("可验证示例",categories.getSelectedItem());
            assertEquals(1,get(panel,"rulesTable",JTable.class).getRowCount());
        });
    }

    private static <T> T get(Object o,String name,Class<T> type){try{Field f=o.getClass().getDeclaredField(name);f.setAccessible(true);return type.cast(f.get(o));}catch(Exception ex){throw new RuntimeException(ex);}}
}
