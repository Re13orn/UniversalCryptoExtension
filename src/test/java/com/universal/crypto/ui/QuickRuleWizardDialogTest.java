package com.universal.crypto.ui;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

class QuickRuleWizardDialogTest {

    @Test
    void sourceRequestInfersScopeAndSignatureHeader() {
        QuickRuleWizardDialog.SourceRequest source = QuickRuleWizardDialog.sourceRequest(
                "get",
                "https://api.example.test/api/items?category=20",
                Map.of(
                        "Content-Type", "application/json",
                        "Sign", "ABC123",
                        "X-Request-Id", "trace-1"
                ),
                false
        );

        assertEquals("GET", source.method());
        assertEquals("api.example.test", source.host());
        assertEquals("/api/items", source.path());
        assertEquals("application/json", source.contentType());
        assertEquals("Sign", source.signatureHeader());
    }

    @Test
    void sourceRequestPrefillsWizardAndGeneratedCondition() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        QuickRuleWizardDialog.SourceRequest source = QuickRuleWizardDialog.sourceRequest(
                "GET",
                "https://api.example.test/api/items?category=20",
                Map.of("Content-Type", "application/json", "Sign", "ABC123"),
                false
        );
        QuickRuleWizardDialog dialog = new QuickRuleWizardDialog(null, source);
        try {
            setText(dialog, "keyField", "secret");
            generate(dialog);

            ProcessingRule rule = dialog.getRule();
            assertEquals(Constants.ToolSource.REPEATER, rule.getCondition().getToolSource());
            assertEquals("api.example.test", rule.getCondition().getHosts().get(0));
            assertEquals("/api/items", rule.getCondition().getPaths().get(0));
            assertEquals("GET", rule.getCondition().getMethods().get(0));
            assertEquals("application/json", rule.getCondition().getContentType());
            ProcessingAction action = rule.getRequestActions().get(0);
            assertEquals("Sign", action.getTargetName());
        } finally {
            dialog.dispose();
        }
    }

    @Test
    void repeaterAutoResignCreatesRepeaterOnlySignatureRule() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        QuickRuleWizardDialog dialog = new QuickRuleWizardDialog(null, "api.example.com", "/api/*");
        try {
            selectScenario(dialog, "REPEATER_AUTO_RESIGN");
            setText(dialog, "keyField", "secret");
            generate(dialog);

            ProcessingRule rule = dialog.getRule();
            assertEquals(Constants.ToolSource.REPEATER, rule.getCondition().getToolSource());
            assertTrue(rule.getCondition().getMethods().contains("PATCH"));
            ProcessingAction action = rule.getRequestActions().get(0);
            assertEquals(Constants.ProcessorType.SIGNATURE, action.getProcessor());
            assertEquals(Constants.TargetType.HEADER, action.getTargetType());
            assertEquals("custom", action.getConfig(Constants.ConfigKey.SIGN_CONTENT));
            assertEquals("${method}${path}?${query}${body}", action.getConfig(Constants.ConfigKey.CUSTOM_SIGN_TEMPLATE));
        } finally {
            dialog.dispose();
        }
    }

    @Test
    void bodySignatureWritesSignatureIntoJsonField() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        QuickRuleWizardDialog dialog = new QuickRuleWizardDialog(null, "api.example.com", "/api/*");
        try {
            selectScenario(dialog, "SIGN_BODY");
            setText(dialog, "keyField", "secret");
            generate(dialog);

            ProcessingAction action = dialog.getRule().getRequestActions().get(1);
            assertEquals(Constants.TargetType.FIELD, action.getTargetType());
            assertEquals("signature", action.getTargetName());
            assertEquals("body", action.getConfig(Constants.ConfigKey.SIGN_CONTENT));
        } finally {
            dialog.dispose();
        }
    }

    @Test
    void externalRequestEncryptionKeepsPerActionEndpoint() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        QuickRuleWizardDialog dialog = new QuickRuleWizardDialog(null, "api.example.com", "/api/*");
        try {
            selectScenario(dialog, "ENCRYPT_REQUEST_ON_SEND");
            setText(dialog, "keyField", "secret");
            JComboBox<?> providerCombo = getField(dialog, "providerCombo", JComboBox.class);
            selectComboValue(providerCombo, "external");
            setText(dialog, "externalEndpointField", "/crypto/encrypt");
            generate(dialog);

            ProcessingAction action = dialog.getRule().getRequestActions().get(0);
            assertEquals(Constants.ProcessorType.CRYPTO, action.getProcessor());
            assertEquals("external", action.getConfig(Constants.ConfigKey.CRYPTO_PROVIDER));
            assertEquals("/crypto/encrypt", action.getConfig(Constants.ConfigKey.ENCRYPT_ENDPOINT));
        } finally {
            dialog.dispose();
        }
    }

    @Test void responseDisplayAndEditingScenariosExposePlaintextAndKeepWireEncrypted() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        for (String scenario : new String[]{"DECRYPT_RESPONSE", "EDIT_PLAINTEXT_RESPONSE"}) {
            QuickRuleWizardDialog dialog = new QuickRuleWizardDialog(null, "api.example.test", "/api/demo");
            try {
                selectScenario(dialog, scenario);
                setText(dialog, "keyField", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                setText(dialog, "cipherField", "data");
                setText(dialog, "ivField", "iv");
                setText(dialog, "ivLiteralField", "AAAAAAAAAAAAAAAA");
                generate(dialog);
                ProcessingRule rule = dialog.getRule();
                assertFalse(rule.isEnabled(), "Wizard creates a reviewable draft");
                assertTrue(rule.isShowInEditor());
                assertEquals("response-display", rule.getResponseActions().get(0).getConfigString("executionPhase"));
                assertEquals(scenario.equals("EDIT_PLAINTEXT_RESPONSE") ? 2 : 1,rule.getResponseActions().size());
                if (scenario.equals("EDIT_PLAINTEXT_RESPONSE")) {
                    assertEquals("response-editor-send",rule.getResponseActions().get(1).getConfigString("executionPhase"));
                    var processors=com.universal.crypto.processor.ProcessorFactory.createDefaultProcessorManager(null);
                    var context=com.universal.crypto.processor.ProcessorContext.forResponse("POST",new java.net.URL("https://api.example.test/api/demo"),Map.of(),"PROXY").build();
                    var result=processors.process(rule.getResponseActions().get(1),"{\"data\":\"edited\",\"iv\":\"AAAAAAAAAAAAAAAA\"}",context);
                    assertTrue(result.isSuccess(),result.getErrorMessage());
                    var json=new com.fasterxml.jackson.databind.ObjectMapper().readTree(result.getProcessedContent());
                    var cipher=javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(javax.crypto.Cipher.DECRYPT_MODE,new javax.crypto.spec.SecretKeySpec(new byte[32],"AES"),new javax.crypto.spec.GCMParameterSpec(128,new byte[12]));
                    assertEquals("edited",new String(cipher.doFinal(java.util.Base64.getDecoder().decode(json.get("data").asText())),java.nio.charset.StandardCharsets.UTF_8));
                    var decrypted=processors.process(rule.getResponseActions().get(0),result.getProcessedContent(),context);
                    assertTrue(decrypted.isSuccess(),decrypted.getErrorMessage());
                    assertEquals("edited",new com.fasterxml.jackson.databind.ObjectMapper().readTree(decrypted.getProcessedContent()).get("data").asText());
                }
            } finally {dialog.dispose();}
        }
    }

    @Test void providerChangeKeepsAlgorithmAndCustomizedMethods() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        QuickRuleWizardDialog dialog=new QuickRuleWizardDialog(null,"api.example.test","/api/demo");
        try {
            getField(dialog,"algorithmCombo",JComboBox.class).setSelectedItem("AES-CBC");
            setText(dialog,"methodsField","PATCH");
            selectComboValue(getField(dialog,"providerCombo",JComboBox.class),"external");
            assertEquals("AES-CBC",getField(dialog,"algorithmCombo",JComboBox.class).getSelectedItem());
            assertEquals("PATCH",getField(dialog,"methodsField",JTextField.class).getText());
            selectComboValue(getField(dialog,"providerCombo",JComboBox.class),"internal");
            assertEquals("AES-CBC",getField(dialog,"algorithmCombo",JComboBox.class).getSelectedItem());
        }finally{dialog.dispose();}
    }

    @Test void generatedHeaderAndBodySignaturesUseBodyAndBodyResigningIsStable() throws Exception {
        assumeFalse(GraphicsEnvironment.isHeadless());
        for(String scenario:new String[]{"SIGN_HEADER","SIGN_BODY"}) {
            QuickRuleWizardDialog dialog=new QuickRuleWizardDialog(null,"api.example.test","/api/demo");
            try {
                selectScenario(dialog,scenario);setText(dialog,"keyField","secret");generate(dialog);
                ProcessingRule rule=dialog.getRule();rule.setEnabled(true);
                var manager=new com.universal.crypto.engine.RuleManager(new com.universal.crypto.engine.RuleConfigStorage(java.nio.file.Files.createTempDirectory("uce-wizard-sign-").toString()));
                manager.addRule(rule);
                var interceptor=new com.universal.crypto.handler.HttpInterceptor(manager,new com.universal.crypto.engine.RuleMatchEngine(),com.universal.crypto.processor.ProcessorFactory.createDefaultProcessorManager(null));
                boolean body=scenario.equals("SIGN_BODY");
                String input=body ? "{\"value\":1,\"signature\":\"stale\"}" : "{\"value\":1}";
                var request=com.universal.crypto.handler.HttpRequestContext.builder().method("POST").url(new java.net.URL("https://api.example.test/api/demo"))
                        .headers(Map.of("Content-Type","application/json","X-Signature","old-header")).body(input).toolSource("REPEATER").build();
                var result=interceptor.processRequest(request);
                var mac=javax.crypto.Mac.getInstance("HmacSHA256");mac.init(new javax.crypto.spec.SecretKeySpec("secret".getBytes(java.nio.charset.StandardCharsets.UTF_8),"HmacSHA256"));
                String signingInput=body ? "{\"value\":1}" : "POST/api/demo{\"value\":1}";
                String expected=java.util.HexFormat.of().formatHex(mac.doFinal(signingInput.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                if(body) {
                    assertEquals(expected,new com.fasterxml.jackson.databind.ObjectMapper().readTree(result.getBody()).get("signature").asText());
                    assertEquals(result.getBody(),interceptor.processRequest(result).getBody());
                } else assertEquals(expected,result.getHeaderIgnoreCase("X-Signature"));
            } finally {dialog.dispose();}
        }
    }

    private void selectScenario(QuickRuleWizardDialog dialog, String name) throws Exception {
        JList<?> scenarioList = getField(dialog, "scenarioList", JList.class);
        ListModel<?> model = scenarioList.getModel();
        for (int i = 0; i < model.getSize(); i++) {
            Object value = model.getElementAt(i);
            if (name.equals(String.valueOf(value))) {
                scenarioList.setSelectedIndex(i);
                return;
            }
        }
        fail("Scenario not found: " + name);
    }

    private void setText(QuickRuleWizardDialog dialog, String fieldName, String value) throws Exception {
        JTextField field = getField(dialog, fieldName, JTextField.class);
        field.setText(value);
    }

    private void generate(QuickRuleWizardDialog dialog) throws Exception {
        Method method = QuickRuleWizardDialog.class.getDeclaredMethod("generateRule");
        method.setAccessible(true);
        method.invoke(dialog);
        assertTrue(dialog.isConfirmed());
        assertNotNull(dialog.getRule());
    }

    private void selectComboValue(JComboBox<?> combo, String rawValue) {
        for (int i = 0; i < combo.getItemCount(); i++) {
            Object item = combo.getItemAt(i);
            if (String.valueOf(item).contains("(" + rawValue + ")") || rawValue.equals(String.valueOf(item))) {
                combo.setSelectedIndex(i);
                return;
            }
        }
        fail("Combo value not found: " + rawValue);
    }

    private <T> T getField(Object target, String fieldName, Class<T> type) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return type.cast(field.get(target));
    }
}
