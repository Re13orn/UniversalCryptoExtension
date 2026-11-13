package com.universal.crypto.ui;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.universal.crypto.burp.UniversalCryptoExtension;
import com.universal.crypto.engine.*;
import com.universal.crypto.model.*;
import com.universal.crypto.processor.ProcessorFactory;
import com.universal.crypto.util.ExtensionSettings;
import com.universal.crypto.util.LanguageManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentEvent;
import java.lang.reflect.*;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import static org.junit.jupiter.api.Assertions.*;

class UiLifecycleTest {
    @TempDir Path temp;

    @Test void languageRefreshPreservesAllPlaygroundInputsAndOutput() throws Exception {
        String previous = LanguageManager.getInstance().getCurrentLocale().getLanguage();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PlaygroundPanel panel = new PlaygroundPanel(null, ProcessorFactory.createDefaultProcessorManager(null));
                get(panel,"processorTypeCombo",JComboBox.class).setSelectedItem("signature");
                get(panel,"signContentCombo",JComboBox.class).setSelectedItem("custom");
                get(panel,"signCustomTemplateArea",JTextArea.class).setText("${header.Nonce}|${body}");
                get(panel,"signKeyField",JTextField.class).setText("unsaved-secret");
                get(panel,"scriptArea",JTextArea.class).setText("return content + '-edited';");
                panel.setInputText("original input\n中文");
                get(panel,"outputArea",JTextArea.class).setText("previous result");
                LanguageManager.getInstance().setLanguage("zh".equals(previous) ? "en" : "zh");
                panel.rebuildUI();
                assertEquals("signature",get(panel,"processorTypeCombo",JComboBox.class).getSelectedItem());
                assertEquals("custom",get(panel,"signContentCombo",JComboBox.class).getSelectedItem());
                assertEquals("${header.Nonce}|${body}",get(panel,"signCustomTemplateArea",JTextArea.class).getText());
                assertEquals("unsaved-secret",get(panel,"signKeyField",JTextField.class).getText());
                assertEquals("return content + '-edited';",get(panel,"scriptArea",JTextArea.class).getText());
                assertEquals("original input\n中文",get(panel,"inputArea",JTextArea.class).getText());
                assertEquals("previous result",get(panel,"outputArea",JTextArea.class).getText());
            } finally { LanguageManager.getInstance().setLanguage(previous); }
        });
    }

    @Test void sortedRuleMultiselectionUsesVisibleIdentitiesAndSurvivesRefresh() throws Exception {
        RuleManager manager = new RuleManager(new RuleConfigStorage(temp.toString()));
        for (String name : List.of("Zulu", "Alpha", "Beta")) {
            ProcessingRule rule = new ProcessingRule(name); rule.setName(name);rule.setCategory("crypto");rule.setEnabled(true);manager.addRule(rule);
        }
        SwingUtilities.invokeAndWait(() -> {
            RuleManagementPanel panel = new RuleManagementPanel(null, manager, action -> {});
            JTable table = get(panel,"rulesTable",JTable.class);
            table.getRowSorter().toggleSortOrder(1);
            table.setRowSelectionInterval(0,1);
            assertFalse(get(panel,"editButton",JButton.class).isEnabled());
            invoke(panel,"toggleRuleStatus",boolean.class,false);
            assertFalse(manager.getRuleById("Alpha").isEnabled());
            assertFalse(manager.getRuleById("Beta").isEnabled());
            assertTrue(manager.getRuleById("Zulu").isEnabled());
            assertEquals(2,table.getSelectedRowCount());
            get(panel,"categoryFilter",JComboBox.class).setSelectedItem("crypto");
            panel.refresh();
            assertEquals("crypto",get(panel,"categoryFilter",JComboBox.class).getSelectedItem());
            assertEquals(2,get(panel,"rulesTable",JTable.class).getSelectedRowCount());
            invoke(panel,"copyRule",ActionEvent.class,null);
            assertEquals(5,manager.getRuleCount());
            assertEquals(2,manager.getAllRules().stream().filter(r -> r.getName().contains("Copy") && !r.isEnabled()).count());
        });
    }

    @Test void importedSettingsRemainPendingAndCancelRestoresCurrentConfig() throws Exception {
        ExtensionSettings live = ExtensionSettings.getInstance();
        String before = new ObjectMapper().writeValueAsString(live);
        ExtensionSettings imported = new ObjectMapper().readValue("{\"apiBaseUrl\":\"https://imported.example/api\",\"language\":\"zh\",\"apiTimeoutMs\":45000,\"debugMode\":true}", ExtensionSettings.class);
        SwingUtilities.invokeAndWait(() -> {
            SettingsPanel panel = new SettingsPanel(null, new UniversalCryptoExtension());
            panel.validateImportedSettings(imported);
            panel.showSettings(imported);
            try {
                assertEquals(before,new ObjectMapper().writeValueAsString(live));
                assertEquals(imported.getApiBaseUrl(),panel.pendingSettings().getApiBaseUrl());
                panel.refresh();
                assertEquals(imported.getApiBaseUrl(),panel.pendingSettings().getApiBaseUrl());
                invoke(panel,"cancelSettings",ActionEvent.class,null);
                assertEquals(live.getApiBaseUrl(),get(panel,"apiEndpointField",JTextField.class).getText());
                assertEquals(before,new ObjectMapper().writeValueAsString(live));
            } catch (Exception ex) {throw new RuntimeException(ex);}
        });
    }

    @Test void invalidImportDoesNotPartiallyOverwriteForm() throws Exception {
        ExtensionSettings invalid = new ObjectMapper().readValue("{\"apiTimeoutMs\":999,\"apiBaseUrl\":\"https://bad.example/api\"}",ExtensionSettings.class);
        SwingUtilities.invokeAndWait(() -> {
            SettingsPanel panel = new SettingsPanel(null,new UniversalCryptoExtension());
            String original=get(panel,"apiEndpointField",JTextField.class).getText();
            assertThrows(IllegalArgumentException.class,()->panel.validateImportedSettings(invalid));
            assertEquals(original,get(panel,"apiEndpointField",JTextField.class).getText());
        });
    }

    @Test void slowTaskLeavesEdtResponsiveAndPublishesOnlyOnEdt() throws Exception {
        CountDownLatch started=new CountDownLatch(1), release=new CountDownLatch(1),done=new CountDownLatch(1);
        AtomicReference<Throwable> error=new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> UiTasks.start(() -> {
            assertFalse(SwingUtilities.isEventDispatchThread());started.countDown();
            assertTrue(release.await(5,TimeUnit.SECONDS));return "result";
        }, result->{assertTrue(SwingUtilities.isEventDispatchThread());assertEquals("result",result);},error::set,done::countDown));
        assertTrue(started.await(5,TimeUnit.SECONDS));
        try {SwingUtilities.invokeAndWait(()->assertEquals(1,done.getCount()));}
        finally {release.countDown();}
        assertTrue(done.await(5,TimeUnit.SECONDS)); assertNull(error.get());
    }

    @Test void failedTaskShowsActualCauseAndRestoresControls() throws Exception {
        CountDownLatch done=new CountDownLatch(1); AtomicReference<Exception> failure=new AtomicReference<>();
        SwingUtilities.invokeAndWait(()->UiTasks.start(()->{throw new IllegalArgumentException("invalid key");},
                result->fail("must not publish success"),failure::set,done::countDown));
        assertTrue(done.await(5,TimeUnit.SECONDS));assertEquals("invalid key",failure.get().getMessage());
    }

    @Test void cancelledTaskDoesNotPublishAResult() throws Exception {
        CountDownLatch started=new CountDownLatch(1), release=new CountDownLatch(1),done=new CountDownLatch(1);
        AtomicReference<SwingWorker<String,Void>> task=new AtomicReference<>(); AtomicBoolean published=new AtomicBoolean();
        SwingUtilities.invokeAndWait(()->task.set(UiTasks.start(()->{started.countDown();release.await();return "late";},
                result->published.set(true),ex->published.set(true),done::countDown)));
        assertTrue(started.await(5,TimeUnit.SECONDS));
        SwingUtilities.invokeAndWait(()->task.get().cancel(true));release.countDown();
        assertTrue(done.await(5,TimeUnit.SECONDS));assertFalse(published.get());
    }

    @Test void initialSplitLayoutIsUsableAndKeepsUserDividerWhenResized() throws Exception {
        SwingUtilities.invokeAndWait(()->{
            PlaygroundPanel panel=new PlaygroundPanel(null,ProcessorFactory.createDefaultProcessorManager(null));
            panel.setSize(900,640);layout(panel);
            JSplitPane split=get(panel,"mainSplit",JSplitPane.class);
            split.dispatchEvent(new ComponentEvent(split,ComponentEvent.COMPONENT_RESIZED));layout(panel);
            assertTrue(split.getDividerLocation()>split.getHeight()*0.3);
            assertTrue(split.getDividerLocation()<split.getHeight()*0.5);
            assertTrue(split.getBottomComponent().getHeight()>230);
            split.setDividerLocation(220);
            split.dispatchEvent(new ComponentEvent(split,ComponentEvent.COMPONENT_RESIZED));
            assertEquals(220,split.getDividerLocation());
            var image=new java.awt.image.BufferedImage(900,640,java.awt.image.BufferedImage.TYPE_INT_RGB);
            var graphics=image.createGraphics();panel.printAll(graphics);graphics.dispose();
            try {javax.imageio.ImageIO.write(image,"png",Path.of("target/ui-playground-layout.png").toFile());}
            catch(Exception ex){throw new RuntimeException(ex);}
        });
    }

    @Test void mainRefreshKeepsSelectedTabAndUpdatesRuleCounters() throws Exception {
        RuleManager manager = new RuleManager(new RuleConfigStorage(temp.toString()));
        UniversalCryptoExtension extension = new UniversalCryptoExtension();
        for (var entry : java.util.Map.of("ruleManager",manager,"processorManager",ProcessorFactory.createDefaultProcessorManager(null),
                "matchEngine",new RuleMatchEngine()).entrySet()) {
            Field field=UniversalCryptoExtension.class.getDeclaredField(entry.getKey());field.setAccessible(true);field.set(extension,entry.getValue());
        }
        UniversalCryptoTab[] holder=new UniversalCryptoTab[1];
        SwingUtilities.invokeAndWait(()->{
            holder[0]=new UniversalCryptoTab(null,extension);
            holder[0].getMainTabbedPane().setSelectedComponent(holder[0].getPlaygroundPanel());
            holder[0].getPlaygroundPanel().setInputText("keep me");
            holder[0].refreshUI();
        });
        SwingUtilities.invokeAndWait(()->{
            assertSame(holder[0].getPlaygroundPanel(),holder[0].getMainTabbedPane().getSelectedComponent());
            assertEquals("keep me",get(holder[0].getPlaygroundPanel(),"inputArea",JTextArea.class).getText());
        });
        ProcessingRule rule=new ProcessingRule("new");rule.setName("new");rule.setEnabled(true);manager.addRule(rule);
        SwingUtilities.invokeAndWait(()->assertEquals("Rules 1/1",get(holder[0],"rulesStatus",JLabel.class).getText()));
    }

    @Test void defaultSettingsDoNotContainAnUninitializedDirectoryPrefix() throws Exception {
        ExtensionSettings defaults=new ObjectMapper().readValue("{}",ExtensionSettings.class);
        assertEquals(System.getProperty("user.home")+"/.burp/universal-crypto-extension/logs",defaults.getLogDirectory());
        assertFalse(ExtensionSettings.getInstance().getLogDirectory().startsWith("null/"));
    }

    private static void layout(Container c) {c.doLayout();for(Component child:c.getComponents())if(child instanceof Container nested)layout(nested);}
    private static <T> T get(Object o,String name,Class<T> type){try{Field f=o.getClass().getDeclaredField(name);f.setAccessible(true);return type.cast(f.get(o));}catch(Exception ex){throw new RuntimeException(ex);}}
    private static void invoke(Object o,String name,Class<?> type,Object value){try{Method m=o.getClass().getDeclaredMethod(name,type);m.setAccessible(true);m.invoke(o,value);}catch(Exception ex){throw new RuntimeException(ex);}}
}
