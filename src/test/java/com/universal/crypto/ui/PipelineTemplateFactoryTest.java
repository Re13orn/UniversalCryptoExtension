package com.universal.crypto.ui;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PipelineTemplateFactoryTest {

    @Test
    void responseRoundTripTemplateEncryptsRealGcmAndRetainsDisplayAction() throws Exception {
        String key = java.util.Base64.getEncoder().encodeToString(new byte[32]);
        String iv = java.util.Base64.getEncoder().encodeToString(new byte[12]);
        var config = new PipelineTemplateFactory.Base64WrappedCipherFieldConfig("data","AES-GCM",key,"base64","iv",iv,"base64");
        var actions = PipelineTemplateFactory.base64WrappedCipherFieldResponseRoundTrip(config);
        assertEquals(Constants.ExecutionPhase.RESPONSE_DISPLAY,actions.get(0).getConfigString(Constants.ConfigKey.EXECUTION_PHASE));
        assertEquals(Constants.ExecutionPhase.RESPONSE_EDITOR_SEND,actions.get(1).getConfigString(Constants.ConfigKey.EXECUTION_PHASE));
        var processors = com.universal.crypto.processor.ProcessorFactory.createDefaultProcessorManager(null);
        String body = "{\"data\":\"hello\",\"iv\":\""+iv+"\"}";
        var context = com.universal.crypto.processor.ProcessorContext.forResponse("POST",new java.net.URL("https://example.test/"),java.util.Map.of(),"PROXY").build();
        var encrypted = processors.process(actions.get(1),body,context);
        assertTrue(encrypted.isSuccess(), encrypted.getErrorMessage());
        var json = new com.fasterxml.jackson.databind.ObjectMapper().readTree(encrypted.getProcessedContent());
        var cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE,new javax.crypto.spec.SecretKeySpec(new byte[32],"AES"),new javax.crypto.spec.GCMParameterSpec(128,new byte[12]));
        assertEquals("hello",new String(cipher.doFinal(java.util.Base64.getDecoder().decode(json.get("data").asText())),java.nio.charset.StandardCharsets.UTF_8));
        var decoded = processors.process(actions.get(0),encrypted.getProcessedContent(),context);
        assertTrue(decoded.isSuccess(),decoded.getErrorMessage());
        assertEquals("hello",new com.fasterxml.jackson.databind.ObjectMapper().readTree(decoded.getProcessedContent()).get("data").asText());
    }

    @Test
    void requestRoundTripTemplateCreatesDisplayDecryptAndEditorSendEncrypt() {
        PipelineTemplateFactory.Base64WrappedCipherFieldConfig config =
                new PipelineTemplateFactory.Base64WrappedCipherFieldConfig(
                        "payload",
                        "AES-CBC",
                        "MTIzNDU2Nzg5MDEyMzQ1Ng==",
                        "base64",
                        "iv",
                        "",
                        "base64"
                );

        List<ProcessingAction> actions = PipelineTemplateFactory.base64WrappedCipherFieldRequestRoundTrip(config);

        assertEquals(2, actions.size());

        ProcessingAction decrypt = actions.get(0);
        assertEquals(Constants.ActionType.DECRYPT, decrypt.getActionType());
        assertEquals(Constants.ExecutionPhase.DISPLAY, decrypt.getConfig(Constants.ConfigKey.EXECUTION_PHASE));
        assertEquals("AES-CBC", decrypt.getConfig(Constants.ConfigKey.ALGORITHM));
        assertEquals("payload", decrypt.getConfig(Constants.ConfigKey.CIPHER_FIELD));
        assertEquals("payload", decrypt.getConfig(Constants.ConfigKey.PLAIN_FIELD));
        assertEquals("base64", decrypt.getConfig(Constants.ConfigKey.CIPHER_FORMAT));

        ProcessingAction encrypt = actions.get(1);
        assertEquals(Constants.ActionType.ENCRYPT, encrypt.getActionType());
        assertEquals(Constants.ExecutionPhase.EDITOR_SEND, encrypt.getConfig(Constants.ConfigKey.EXECUTION_PHASE));
        assertEquals("AES-CBC", encrypt.getConfig(Constants.ConfigKey.ALGORITHM));
        assertEquals("iv", encrypt.getConfig(Constants.ConfigKey.IV_FIELD));
    }

    @Test
    void responseTemplateCreatesOnlyResponseDisplayDecrypt() {
        PipelineTemplateFactory.Base64WrappedCipherFieldConfig config =
                new PipelineTemplateFactory.Base64WrappedCipherFieldConfig(
                        "data",
                        "AES-GCM",
                        "secret",
                        "plain",
                        "iv_b64",
                        "",
                        "base64"
                );

        List<ProcessingAction> actions = PipelineTemplateFactory.base64WrappedCipherFieldResponseDecrypt(config);

        assertEquals(1, actions.size());
        ProcessingAction action = actions.get(0);
        assertEquals(Constants.ActionType.DECRYPT, action.getActionType());
        assertEquals(Constants.ExecutionPhase.RESPONSE_DISPLAY, action.getConfig(Constants.ConfigKey.EXECUTION_PHASE));
        assertEquals("data", action.getConfig(Constants.ConfigKey.CIPHER_FIELD));
    }
}
