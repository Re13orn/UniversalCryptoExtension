package com.universal.crypto.ui;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.engine.RuleConfigStorage;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.engine.RuleMatchEngine;
import com.universal.crypto.processor.ProcessorFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PlaygroundPanelTest {
    private String previousLanguage;
    @org.junit.jupiter.api.BeforeEach void useChineseHelp() {
        previousLanguage = com.universal.crypto.util.LanguageManager.getInstance().getCurrentLocale().getLanguage();
        com.universal.crypto.util.LanguageManager.getInstance().setLanguage("zh");
    }
    @org.junit.jupiter.api.AfterEach void restoreLanguage() {
        com.universal.crypto.util.LanguageManager.getInstance().setLanguage(previousLanguage);
    }


    @TempDir
    Path tempDir;

    @Test
    void languageRefreshPreservesCustomAlgorithmsAndTranslatedSelections() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            try {
                PlaygroundPanel panel = new PlaygroundPanel(null, ProcessorFactory.createTestProcessorManager());
                ProcessingAction crypto = new ProcessingAction(Constants.ActionType.DECRYPT,
                        Constants.TargetType.BODY, Constants.ProcessorType.CRYPTO);
                crypto.setConfig(Constants.ConfigKey.ALGORITHM, "AES/CBC/PKCS5Padding");
                crypto.setConfig(Constants.ConfigKey.KEY_SOURCE, "none");
                panel.importActionConfiguration(crypto);
                ProcessingAction signature = digestAction();
                signature.setConfig(Constants.ConfigKey.ALGORITHM, "HmacMD5");
                panel.importActionConfiguration(signature);
                panel.setInputText("unsaved input\n中文");
                getTextArea(panel, "outputArea").setText("previous output");

                com.universal.crypto.util.LanguageManager lang = com.universal.crypto.util.LanguageManager.getInstance();
                lang.setLanguage("en");
                panel.rebuildUI();

                assertEquals("AES/CBC/PKCS5Padding", getCombo(panel, "algorithmCombo").getSelectedItem());
                assertEquals("HmacMD5", getCombo(panel, "signAlgorithmCombo").getSelectedItem());
                assertEquals(Constants.ProcessorType.SIGNATURE, getCombo(panel, "processorTypeCombo").getSelectedItem());
                assertEquals(Constants.ActionType.DECRYPT, getCombo(panel, "actionCombo").getSelectedItem());
                assertEquals(lang.getString("playground.keysource.none"), getCombo(panel, "keySourceCombo").getSelectedItem());
                assertEquals("unsaved input\n中文", getTextArea(panel, "inputArea").getText());
                assertEquals("previous output", getTextArea(panel, "outputArea").getText());
            } catch (Exception ex) { throw new RuntimeException(ex); }
        });
    }

    @Test
    void refreshPreservesUncommittedAlgorithmEditorText() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            try {
                PlaygroundPanel panel = new PlaygroundPanel(null, ProcessorFactory.createTestProcessorManager());
                ((JTextField) getCombo(panel, "algorithmCombo").getEditor().getEditorComponent())
                        .setText("AES/CBC/NoPadding");
                ((JTextField) getCombo(panel, "signAlgorithmCombo").getEditor().getEditorComponent())
                        .setText("HmacSHA384");

                panel.rebuildUI();

                assertEquals("AES/CBC/NoPadding", getCombo(panel, "algorithmCombo").getSelectedItem());
                assertEquals("HmacSHA384", getCombo(panel, "signAlgorithmCombo").getSelectedItem());
            } catch (Exception ex) { throw new RuntimeException(ex); }
        });
    }

    @Test
    void scriptRawRequestUsesOriginalHeadersAndDeclaredBodyCharset() throws Exception {
        PlaygroundPanel panel = new PlaygroundPanel(null, ProcessorFactory.createDefaultProcessorManager(null));
        getCombo(panel, "processorTypeCombo").setSelectedItem(Constants.ProcessorType.SCRIPT);
        getTextArea(panel, "scriptArea").setText("return request.getOriginalHeader('x-nonce')+'|'+Bytes.toBase64(bodyBytes);");
        panel.setInputText("POST /demo HTTP/1.1\nHost: example.test\nContent-Type: text/plain; charset=GBK\nX-Nonce: hello\n\n中文");
        executeAndWait(panel);
        assertTrue(getTextArea(panel, "outputArea").getText().contains("hello|1tDOxA=="));
    }

    @Test
    void signaturePlaygroundDryRunParsesRawHttpRequestAndShowsFinalSignedRequest() throws Exception {
        PlaygroundPanel panel = new PlaygroundPanel(null, ProcessorFactory.createTestProcessorManager());
        panel.importActionConfiguration(digestAction());
        panel.setInputText("""
                GET /api/items?z=2&a=1 HTTP/2
                Host: api.example.test
                Timestamp: 1700000000123
                Sign: old-demo-signature
                
                """);

        executeAndWait(panel);

        JTextArea outputArea = getTextArea(panel, "outputArea");
        String output = outputArea.getText();
        assertTrue(output.contains("签名前原文"), output);
        assertTrue(output.contains("30EF2CA6B2AA44ADCA908AEE883440436E2270E7D3170975820BF7A9AC0E703D"), output);
        assertTrue(output.contains("Sign: 30EF2CA6B2AA44ADCA908AEE883440436E2270E7D3170975820BF7A9AC0E703D"), output);
    }

    @Test
    void signaturePlaygroundShowsRuleMatchDiagnosticsForRawHttpRequest() throws Exception {
        RuleManager ruleManager = new RuleManager(new RuleConfigStorage(tempDir.toString()));
        ProcessingRule rule = new ProcessingRule("demo-digest");
        rule.setName("测试摘要");
        rule.setCondition(new com.universal.crypto.model.RuleCondition());
        rule.getCondition().addHost("api.example.test");
        rule.addRequestAction(digestAction());
        ruleManager.addRule(rule);
        PlaygroundPanel panel = new PlaygroundPanel(null, ProcessorFactory.createTestProcessorManager(),
                ruleManager, new RuleMatchEngine());
        panel.importActionConfiguration(digestAction());
        panel.setInputText("""
                GET /api/items?z=2&a=1 HTTP/2
                Host: api.example.test
                Timestamp: 1700000000123
                
                """);

        executeAndWait(panel);

        JTextArea outputArea = getTextArea(panel, "outputArea");
        String output = outputArea.getText();
        assertTrue(output.contains("规则匹配情况"), output);
        assertTrue(output.contains("[匹配] 测试摘要"), output);
        assertTrue(output.contains("[执行] sign / signature -> header Sign"), output);
    }

    @Test
    void playgroundConfigCardsShowUsageGuidance() {
        PlaygroundPanel panel = new PlaygroundPanel(null, ProcessorFactory.createTestProcessorManager());

        assertTrue(componentTreeText(panel).contains("加解密测试说明"));
        assertTrue(componentTreeText(panel).contains("签名测试说明"));
        assertTrue(componentTreeText(panel).contains("字段处理测试说明"));
        assertTrue(componentTreeText(panel).contains("脚本怎么写"));
        assertTrue(componentTreeText(panel).contains("常用模板"));
        assertTrue(componentTreeText(panel).contains("没有 window、document、fetch、require"));
    }

    @Test
    void scriptPlaygroundParsesRawHttpRequestForRequestHelpers() throws Exception {
        PlaygroundPanel panel = new PlaygroundPanel(null, ProcessorFactory.createTestProcessorManager());
        getCombo(panel, "processorTypeCombo").setSelectedItem(Constants.ProcessorType.SCRIPT);
        getTextArea(panel, "scriptArea").setText("""
                return request.getPath()
                    + '|' + request.getQueryParam('a')
                    + '|' + request.getHeader('Timestamp')
                    + '|' + content;""");
        panel.setInputText("""
                POST /api/order?a=1&b=2 HTTP/1.1
                Host: api.example.com
                Timestamp: 12345
                Content-Type: application/json

                {"hello":"world"}
                """);

        executeAndWait(panel);

        String output = getTextArea(panel, "outputArea").getText();
        assertTrue(output.contains("/api/order|1|12345|{\"hello\":\"world\"}"), output);
    }

    private void executeAndWait(PlaygroundPanel panel) throws Exception {
        Method execute = PlaygroundPanel.class.getDeclaredMethod("executeTest", ActionEvent.class);
        execute.setAccessible(true);
        SwingUtilities.invokeAndWait(() -> {
            try { execute.invoke(panel, new Object[]{null}); }
            catch (Exception ex) { throw new RuntimeException(ex); }
        });
        Field worker = PlaygroundPanel.class.getDeclaredField("testWorker"); worker.setAccessible(true);
        java.util.concurrent.atomic.AtomicBoolean finished = new java.util.concurrent.atomic.AtomicBoolean();
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
        do {
            SwingUtilities.invokeAndWait(() -> {
                try { finished.set(worker.get(panel) == null); }
                catch (Exception ex) { throw new RuntimeException(ex); }
            });
            if (!finished.get()) Thread.sleep(10);
        } while (!finished.get() && System.nanoTime() < deadline);
        assertTrue(finished.get(), "UI must publish the test result and reenable Run");
    }

    private ProcessingAction digestAction() {
        ProcessingAction action = new ProcessingAction(Constants.ActionType.SIGN, Constants.TargetType.HEADER,
                "Sign", Constants.ProcessorType.SIGNATURE);
        Map<String, Object> config = new LinkedHashMap<>();
        config.put(Constants.ConfigKey.ALGORITHM, "SHA-256");
        config.put(Constants.ConfigKey.KEY_SOURCE, "none");
        config.put(Constants.ConfigKey.CRYPTO_PROVIDER, "internal");
        config.put(Constants.ConfigKey.CIPHER_FORMAT, "hex");
        config.put(Constants.ConfigKey.HASH_KEY_PLACEMENT, "none");
        config.put(Constants.ConfigKey.SIGNATURE_HEX_CASE, "upper");
        config.put(Constants.ConfigKey.SIGN_CONTENT, "custom");
        config.put(Constants.ConfigKey.CUSTOM_SIGN_TEMPLATE, "${header.Timestamp}:${stablejson:payload}");
        config.put(Constants.ConfigKey.HEADER_TEMPLATES, new LinkedHashMap<String, String>());
        action.setConfig(config);
        return action;
    }

    private JTextArea getTextArea(PlaygroundPanel panel, String fieldName) throws Exception {
        Field field = PlaygroundPanel.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return (JTextArea) field.get(panel);
    }

    @SuppressWarnings("unchecked")
    private JComboBox<String> getCombo(PlaygroundPanel panel, String fieldName) throws Exception {
        Field field = PlaygroundPanel.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return (JComboBox<String>) field.get(panel);
    }

    private String componentTreeText(java.awt.Component component) {
        StringBuilder builder = new StringBuilder();
        if (component instanceof JLabel label) {
            builder.append(label.getText()).append('\n');
        }
        if (component instanceof JTextArea textArea) {
            builder.append(textArea.getText()).append('\n');
        }
        if (component instanceof java.awt.Container container) {
            for (java.awt.Component child : container.getComponents()) {
                builder.append(componentTreeText(child));
            }
        }
        return builder.toString();
    }
}
