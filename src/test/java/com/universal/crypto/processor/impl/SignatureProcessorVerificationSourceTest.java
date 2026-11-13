package com.universal.crypto.processor.impl;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.processor.ProcessorResult;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureProcessorVerificationSourceTest {

    @Test
    void verifyReadsExpectedSignatureFromQueryParameter() throws Exception {
        ProcessingAction action = baseVerifyAction("${body}");
        String content = "hello";
        String signature = InternalSignatureEngine.sign(action, content, "");
        action.getConfig().put(Constants.ConfigKey.SIGNATURE_SOURCE, "query");
        action.getConfig().put(Constants.ConfigKey.SIGNATURE_QUERY_PARAM, "sign");

        ProcessorContext context = ProcessorContext.forRequest(
                "GET",
                new URL("https://example.com/api?sign=" + signature),
                Map.of(),
                "REPEATER"
        ).build();

        ProcessorResult result = new SignatureProcessor(null).process(action, content, context);

        assertTrue(result.isSuccess());
        assertEquals("true", result.getProcessedContent());
        assertEquals("query", result.getMetadata("signatureSource"));
    }

    @Test
    void verifyReadsExpectedSignatureFromBodyJsonField() throws Exception {
        ProcessingAction action = baseVerifyAction("${json:data}");
        String signature = InternalSignatureEngine.sign(action, "hello", "");
        String body = "{\"data\":\"hello\",\"signature\":\"" + signature + "\"}";
        action.getConfig().put(Constants.ConfigKey.SIGNATURE_SOURCE, "body-field");
        action.getConfig().put(Constants.ConfigKey.SIGNATURE_FIELD_PATH, "$.signature");

        ProcessorContext context = ProcessorContext.forRequest(
                "POST",
                new URL("https://example.com/api"),
                Map.of(),
                "REPEATER"
        ).build();

        ProcessorResult result = new SignatureProcessor(null).process(action, body, context);

        assertTrue(result.isSuccess());
        assertEquals("true", result.getProcessedContent());
        assertEquals("body-field", result.getMetadata("signatureSource"));
    }

    private ProcessingAction baseVerifyAction(String template) {
        ProcessingAction action = new ProcessingAction(
                Constants.ActionType.VERIFY,
                Constants.TargetType.BODY,
                Constants.ProcessorType.SIGNATURE
        );
        action.getConfig().put(Constants.ConfigKey.ALGORITHM, "SHA-256");
        action.getConfig().put(Constants.ConfigKey.KEY_SOURCE, "none");
        action.getConfig().put(Constants.ConfigKey.SIGN_CONTENT, "custom");
        action.getConfig().put(Constants.ConfigKey.CUSTOM_SIGN_TEMPLATE, template);
        action.getConfig().put(Constants.ConfigKey.CRYPTO_PROVIDER, "internal");
        action.getConfig().put(Constants.ConfigKey.CIPHER_FORMAT, "hex");
        action.getConfig().put(Constants.ConfigKey.HASH_KEY_PLACEMENT, "none");
        action.getConfig().put(Constants.ConfigKey.SIGNATURE_HEX_CASE, "upper");
        return action;
    }
}
