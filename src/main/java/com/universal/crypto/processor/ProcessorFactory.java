package com.universal.crypto.processor;

import com.universal.crypto.model.Constants.ActionType;
import com.universal.crypto.processor.impl.CryptoProcessor;
import com.universal.crypto.processor.impl.FieldProcessor;
import com.universal.crypto.processor.impl.SignatureProcessor;
import com.universal.crypto.processor.impl.ScriptProcessor;

/**
 * Factory for creating and configuring processors
 */
public class ProcessorFactory {

    /**
     * Create a processor manager with all default processors registered
     *
     * @param apiClient API client for crypto operations
     * @return configured processor manager
     */
    public static ProcessorManager createDefaultProcessorManager(CryptoProcessor.ApiClient apiClient) {
        ProcessorManager manager = new ProcessorManager();

        manager.registerProcessor(new CryptoProcessor(apiClient));
        manager.registerProcessor(new SignatureProcessor(apiClient));
        manager.registerProcessor(new FieldProcessor());
        manager.registerProcessor(new ScriptProcessor());

        return manager;
    }

    /**
     * Create a minimal processor manager with essential processors
     *
     * @param apiClient API client for crypto operations
     * @return configured processor manager
     */
    public static ProcessorManager createMinimalProcessorManager(CryptoProcessor.ApiClient apiClient) {
        ProcessorManager manager = new ProcessorManager();

        manager.registerProcessor(new CryptoProcessor(apiClient));


        return manager;
    }

    /**
     * Create a processor manager for testing (no external dependencies)
     *
     * @return configured processor manager for testing
     */
    public static ProcessorManager createTestProcessorManager() {
        ProcessorManager manager = new ProcessorManager();

        manager.registerProcessor(new FieldProcessor());


        MockApiClient mockApiClient = new MockApiClient();
        manager.registerProcessor(new CryptoProcessor(mockApiClient));
        manager.registerProcessor(new SignatureProcessor(mockApiClient));
        manager.registerProcessor(new ScriptProcessor());

        return manager;
    }

    /**
     * Create a crypto processor with the given API client
     *
     * @param apiClient API client for crypto operations
     * @return crypto processor instance
     */
    public static CryptoProcessor createCryptoProcessor(CryptoProcessor.ApiClient apiClient) {
        return new CryptoProcessor(apiClient);
    }

    /**
     * Create a signature processor with the given API client
     *
     * @param apiClient API client for crypto operations
     * @return signature processor instance
     */
    public static SignatureProcessor createSignatureProcessor(CryptoProcessor.ApiClient apiClient) {
        return new SignatureProcessor(apiClient);
    }

    /**
     * Create a field processor
     *
     * @return field processor instance
     */
    public static FieldProcessor createFieldProcessor() {
        return new FieldProcessor();
    }



    /**
     * Mock API client for testing purposes
     */
    public static class MockApiClient implements CryptoProcessor.ApiClient {

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public CryptoProcessor.ApiResponse processRequest(CryptoProcessor.ApiRequest request) throws Exception {
            String action = request.getAction();
            String data = request.getData();

            switch (action) {
                case ActionType.ENCRYPT:
                    return new CryptoProcessor.ApiResponse(true, "encrypted_" + data, null, 10, null);

                case ActionType.DECRYPT:
                    if (data != null && data.startsWith("encrypted_")) {
                        return new CryptoProcessor.ApiResponse(true, data.substring("encrypted_".length()), null, 10, null);
                    } else {
                        return new CryptoProcessor.ApiResponse(false, null, "Invalid encrypted data", 5, null);
                    }

                case ActionType.SIGN:
                    return new CryptoProcessor.ApiResponse(true, "signature_" + data.hashCode(), null, 15, null);

                case ActionType.VERIFY:
                    String signature = request.getParameters().get("signature");
                    String expectedSignature = "signature_" + data.hashCode();
                    boolean verified = expectedSignature.equals(signature);
                    return new CryptoProcessor.ApiResponse(true, Boolean.toString(verified), null, 12, null);

                case "lookup_key":
                    return new CryptoProcessor.ApiResponse(true, "mock_key_" + data.hashCode(), null, 20, null);

                default:
                    return new CryptoProcessor.ApiResponse(false, null, "Unsupported action: " + action, 1, null);
            }
        }
    }

    /**
     * Validate processor configuration
     *
     * @param processor the processor to validate
     * @return true if processor is properly configured
     */
    public static boolean validateProcessor(ProcessorInterface processor) {
        if (processor == null) {
            return false;
        }

        if (processor.getProcessorType() == null || processor.getProcessorType().trim().isEmpty()) {
            return false;
        }

        try {
            return processor.isAvailable();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get processor information for debugging
     *
     * @param processor the processor to inspect
     * @return processor information map
     */
    public static java.util.Map<String, Object> getProcessorInfo(ProcessorInterface processor) {
        java.util.Map<String, Object> info = new java.util.HashMap<>();

        if (processor != null) {
            info.put("type", processor.getProcessorType());
            info.put("available", processor.isAvailable());
            info.put("class", processor.getClass().getSimpleName());

            java.util.Map<String, String> requiredParams = processor.getRequiredParameters();
            info.put("requiredParameters", requiredParams != null ? requiredParams.keySet() : java.util.Collections.emptySet());

            String[] testActions = {ActionType.ENCRYPT, ActionType.DECRYPT, ActionType.SIGN, ActionType.VERIFY,
                                   ActionType.REPLACE, ActionType.ADD, ActionType.REMOVE};
            java.util.List<String> supportedActions = new java.util.ArrayList<>();
            for (String action : testActions) {
                if (processor.canHandle(action)) {
                    supportedActions.add(action);
                }
            }
            info.put("supportedActions", supportedActions);
        }

        return info;
    }
}
