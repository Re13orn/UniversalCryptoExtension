package com.universal.crypto.ui;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Builds common step-flow templates from a few protocol-level choices.
 */
public final class PipelineTemplateFactory {

    private PipelineTemplateFactory() {
    }

    public record Base64WrappedCipherFieldConfig(
            String fieldName,
            String algorithm,
            String keyValue,
            String keyFormat,
            String ivField,
            String ivLiteral,
            String ivFormat
    ) {
    }

    public static List<ProcessingAction> base64WrappedCipherFieldRequestRoundTrip(Base64WrappedCipherFieldConfig config) {
        List<ProcessingAction> actions = new ArrayList<>();
        actions.add(cipherFieldAction(Constants.ActionType.DECRYPT, Constants.ExecutionPhase.DISPLAY, config));
        ProcessingAction encrypt = cipherFieldAction(Constants.ActionType.ENCRYPT, Constants.ExecutionPhase.EDITOR_SEND, config);
        encrypt.setConfig(Constants.ConfigKey.EDITOR_ONLY, true);
        actions.add(encrypt);
        return actions;
    }

    public static List<ProcessingAction> base64WrappedCipherFieldResponseDecrypt(Base64WrappedCipherFieldConfig config) {
        return List.of(cipherFieldAction(Constants.ActionType.DECRYPT, Constants.ExecutionPhase.RESPONSE_DISPLAY, config));
    }

    public static List<ProcessingAction> base64WrappedCipherFieldResponseRoundTrip(Base64WrappedCipherFieldConfig config) {
        return List.of(cipherFieldAction(Constants.ActionType.DECRYPT, Constants.ExecutionPhase.RESPONSE_DISPLAY, config),
                cipherFieldAction(Constants.ActionType.ENCRYPT, Constants.ExecutionPhase.RESPONSE_EDITOR_SEND, config));
    }

    private static ProcessingAction cipherFieldAction(String actionType,
                                                      String executionPhase,
                                                      Base64WrappedCipherFieldConfig config) {
        ProcessingAction action = new ProcessingAction();
        action.setActionType(actionType);
        action.setTargetType(Constants.TargetType.BODY);
        action.setProcessor(Constants.ProcessorType.CRYPTO);
        action.setEnabled(true);
        action.setDescription(description(actionType, config));

        action.setConfig(Map.ofEntries(
                Map.entry(Constants.ConfigKey.ALGORITHM, valueOr(config.algorithm(), "AES-GCM")),
                Map.entry(Constants.ConfigKey.CRYPTO_PROVIDER, "internal"),
                Map.entry(Constants.ConfigKey.KEY_SOURCE, "static"),
                Map.entry(Constants.ConfigKey.KEY_VALUE, valueOr(config.keyValue(), "")),
                Map.entry(Constants.ConfigKey.KEY_FORMAT, valueOr(config.keyFormat(), "base64")),
                Map.entry(Constants.ConfigKey.PAYLOAD_FORMAT, "json"),
                Map.entry(Constants.ConfigKey.CIPHER_FIELD, valueOr(config.fieldName(), "data")),
                Map.entry(Constants.ConfigKey.PLAIN_FIELD, valueOr(config.fieldName(), "data")),
                Map.entry(Constants.ConfigKey.CIPHER_FORMAT, "base64"),
                Map.entry(Constants.ConfigKey.PLAIN_FORMAT, "plain"),
                Map.entry(Constants.ConfigKey.IV_FIELD, valueOr(config.ivField(), "iv_b64")),
                Map.entry(Constants.ConfigKey.IV_LITERAL_VALUE, valueOr(config.ivLiteral(), "")),
                Map.entry(Constants.ConfigKey.IV_FORMAT, valueOr(config.ivFormat(), "base64")),
                Map.entry(Constants.ConfigKey.CHARSET, "UTF-8"),
                Map.entry(Constants.ConfigKey.GCM_TAG_LENGTH, "128"),
                Map.entry(Constants.ConfigKey.EXECUTION_PHASE, executionPhase)
        ));
        return action;
    }

    private static String description(String actionType, Base64WrappedCipherFieldConfig config) {
        String field = valueOr(config.fieldName(), "data");
        String algorithm = valueOr(config.algorithm(), "AES-GCM");
        if (Constants.ActionType.DECRYPT.equals(actionType)) {
            return "Decode Base64 ciphertext field " + field + " and decrypt with " + algorithm;
        }
        return "Encrypt field " + field + " with " + algorithm + " and write Base64 ciphertext";
    }

    private static String valueOr(String value, String fallback) {
        return value == null || value.trim().isEmpty() ? fallback : value.trim();
    }
}
