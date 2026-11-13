package com.universal.crypto.processor.impl;

import com.universal.crypto.model.Constants.ActionType;
import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.AbstractProcessor;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.processor.ProcessorException;
import com.universal.crypto.processor.ProcessorResult;
import com.universal.crypto.processor.impl.InternalCryptoEngine.InternalResult;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Crypto processor for handling encryption and decryption operations
 * Delegates actual crypto operations to external API service
 */
public class CryptoProcessor extends AbstractProcessor {

    private final ApiClient apiClient;

    public CryptoProcessor(ApiClient apiClient) {
        super("crypto", Set.of(ActionType.ENCRYPT, ActionType.DECRYPT));
        this.apiClient = apiClient;
    }

    @Override
    public Map<String, String> getRequiredParameters() {
        Map<String, String> params = new HashMap<>();
        params.put(ConfigKey.ALGORITHM, "Cryptographic algorithm to use (e.g., AES-GCM, AES-CBC)");
        params.put(ConfigKey.KEY_SOURCE, "Key source type (static, lookup, cached)");
        return params;
    }

    @Override
    protected boolean validateSpecificConfiguration(ProcessingAction action) {
        String algorithm = getConfigString(action, ConfigKey.ALGORITHM);
        if (algorithm == null || algorithm.trim().isEmpty()) {
            return false;
        }

        String keySource = getConfigString(action, ConfigKey.KEY_SOURCE);
        String provider = getConfigString(action, ConfigKey.CRYPTO_PROVIDER, "external");
        if (keySource == null || keySource.trim().isEmpty()) {
            return false;
        }

        if ("none".equalsIgnoreCase(keySource)) {
            return "internal".equalsIgnoreCase(provider);
        }

        switch (keySource.toLowerCase()) {
            case "static":
                return action.hasConfig(ConfigKey.KEY_VALUE);
            case "lookup":
                return action.hasConfig(ConfigKey.LOOKUP_METHOD) &&
                       action.hasConfig(ConfigKey.LOOKUP_ENDPOINT);
            case "cached":
                return true;
            default:
                return false;
        }
    }

    @Override
    public boolean isAvailable() {
        return true; // Internal algorithms remain available independently of the external client.
    }

    @Override
    protected ProcessorResult processInternal(ProcessingAction action, String content,
                                            ProcessorContext context) throws Exception {

        String actionType = action.getActionType();
        String algorithm = getConfigString(action, ConfigKey.ALGORITHM);
        String keySource = getConfigString(action, ConfigKey.KEY_SOURCE);
        String provider = getConfigString(action, ConfigKey.CRYPTO_PROVIDER, "external");

        if (!"internal".equalsIgnoreCase(provider) && (apiClient == null || !apiClient.isAvailable()))
            return ProcessorResult.failure("External crypto client is unavailable; no encryption/decryption was performed.").build();
        String key = resolveKey(action, content, context);
        if (key == null && requiresKeyForOperation(provider, algorithm)) {
            return ProcessorResult.failure("Failed to resolve cryptographic key").build();
        }

        if ("internal".equalsIgnoreCase(provider)) {
            try {
                InternalResult internalResult = InternalCryptoEngine.process(
                        action,
                        actionType,
                        content,
                        key
                );

                ProcessorResult.Builder resultBuilder = ProcessorResult.success(internalResult.content())
                        .addMetadata("algorithm", algorithm)
                        .addMetadata("keySource", keySource)
                        .addMetadata("provider", "internal");

                internalResult.metadata().forEach(resultBuilder::addMetadata);

                if ("lookup".equalsIgnoreCase(keySource)) {
                    // Internal flow may still rely on cached lookup key
                    context.setSharedData("cached_key", key);
                    resultBuilder.addMetadata("keyCached", true);
                }

                return resultBuilder.build();
            } catch (ProcessorException ex) {
                return ProcessorResult.failure("Internal crypto failed: " + ex.getMessage())
                        .addMetadata("algorithm", algorithm)
                        .addMetadata("provider", "internal")
                        .build();
            }
        }

        ApiRequest.Builder builder = new ApiRequest.Builder()
                .action(actionType)
                .algorithm(algorithm)
                .key(key)
                .data(content);

        // Allow per-action endpoint/method overrides via rule config
        if (ActionType.ENCRYPT.equals(actionType)) {
            String ep = getConfigString(action, ConfigKey.ENCRYPT_ENDPOINT);
            String m = getConfigString(action, ConfigKey.ENCRYPT_METHOD, "POST");
            if (ep != null && !ep.trim().isEmpty()) {
                builder.endpoint(ep);
            }
            if (m != null && !m.trim().isEmpty()) {
                builder.method(m);
            }
        } else if (ActionType.DECRYPT.equals(actionType)) {
            String ep = getConfigString(action, ConfigKey.DECRYPT_ENDPOINT);
            String m = getConfigString(action, ConfigKey.DECRYPT_METHOD, "POST");
            if (ep != null && !ep.trim().isEmpty()) {
                builder.endpoint(ep);
            }
            if (m != null && !m.trim().isEmpty()) {
                builder.method(m);
            }
        }

        applyExternalApiOverrides(action, builder, null);

        ApiRequest request = builder.build();

        ApiResponse response = apiClient.processRequest(request);

        if (response.isSuccess()) {
            ProcessorResult.Builder resultBuilder = ProcessorResult.success(response.getData())
                    .addMetadata("algorithm", algorithm)
                    .addMetadata("keySource", keySource)
                    .addMetadata("provider", "external")
                    .addMetadata("apiResponseTime", response.getProcessingTimeMs());

            if ("lookup".equals(keySource) && response.hasMetadata("key")) {
                context.setSharedData("cached_key", response.getMetadata("key"));
                resultBuilder.addMetadata("keyCached", true);
            }

            return resultBuilder.build();
        } else {
            return ProcessorResult.failure("API processing failed: " + response.getErrorMessage())
                    .addMetadata("algorithm", algorithm)
                    .addMetadata("provider", "external")
                    .addMetadata("keySource", keySource)
                    .build();
        }
    }

    private String resolveKey(ProcessingAction action, String content, ProcessorContext context)
            throws ProcessorException {

        String keySource = getConfigString(action, ConfigKey.KEY_SOURCE);
        String provider = getConfigString(action, ConfigKey.CRYPTO_PROVIDER, "external");

        if (keySource == null || keySource.trim().isEmpty()) {
            throw new ProcessorException("Key source is not configured");
        }

        if ("none".equalsIgnoreCase(keySource)) {
            if (!"internal".equalsIgnoreCase(provider)) {
                throw new ProcessorException("Key source 'none' is only supported for internal provider");
            }
            return null;
        }

        switch (keySource.toLowerCase()) {
            case "static":
                return getConfigString(action, ConfigKey.KEY_VALUE);

            case "cached":
                String cachedKey = (String) context.getSharedData("cached_key");
                if (cachedKey != null) {
                    return cachedKey;
                }

                boolean fallbackLookup = getConfigBoolean(action, ConfigKey.FALLBACK_LOOKUP, false);
                if (fallbackLookup) {
                    return lookupKey(action, content, context);
                } else {
                    throw new ProcessorException("No cached key available and fallback lookup disabled");
                }

            case "lookup":
                return lookupKey(action, content, context);

            default:
                throw new ProcessorException("Unsupported key source: " + keySource);
        }
    }

    private String lookupKey(ProcessingAction action, String content, ProcessorContext context)
            throws ProcessorException {

        if (apiClient == null || !apiClient.isAvailable())
            throw new ProcessorException("Key lookup client is unavailable.");
        String lookupMethod = getConfigString(action, ConfigKey.LOOKUP_METHOD);
        String lookupEndpoint = getConfigString(action, ConfigKey.LOOKUP_ENDPOINT);
        String responseKeyPath = getConfigString(action, ConfigKey.RESPONSE_KEY_PATH, "key");
        String lookupHttpMethod = getConfigString(action, ConfigKey.LOOKUP_HTTP_METHOD, "POST");

        try {
            ApiRequest.Builder builder = new ApiRequest.Builder()
                    .action("lookup_key")
                    .method(lookupHttpMethod)
                    .endpoint(lookupEndpoint)
                    .data(content)
                    .addParameter("lookupMethod", lookupMethod)
                    .addParameter("keyPath", responseKeyPath);

            applyExternalApiOverrides(action, builder, responseKeyPath);

            ApiRequest lookupRequest = builder.build();

            ApiResponse response = apiClient.processRequest(lookupRequest);

            if (response.isSuccess()) {
                return response.getData();
            } else {
                throw new ProcessorException("Key lookup failed: " + response.getErrorMessage());
            }

        } catch (Exception e) {
            throw new ProcessorException("Key lookup error: " + e.getMessage(), e);
        }
    }

    private void applyExternalApiOverrides(ProcessingAction action,
                                          ApiRequest.Builder builder,
                                          String defaultResponsePath) {
        if (action == null || builder == null) {
            return;
        }

        String template = getConfigString(action, ConfigKey.API_REQUEST_TEMPLATE);
        if (template != null && !template.trim().isEmpty()) {
            builder.bodyTemplate(template);
        }

        String contentType = getConfigString(action, ConfigKey.API_CONTENT_TYPE);
        if (contentType != null && !contentType.trim().isEmpty()) {
            builder.contentType(contentType);
        }

        Map<String, String> fieldMap = getConfigStringMap(action, ConfigKey.API_FIELD_MAP);
        if (fieldMap != null && !fieldMap.isEmpty()) {
            builder.fieldMap(fieldMap);
        }

        Map<String, String> headers = getConfigStringMap(action, ConfigKey.API_HEADERS);
        if (headers != null && !headers.isEmpty()) {
            builder.headers(headers);
        }

        String responsePath = getConfigString(action, ConfigKey.API_RESPONSE_PATH);
        if ((responsePath == null || responsePath.trim().isEmpty()) && defaultResponsePath != null) {
            responsePath = defaultResponsePath;
        }
        if (responsePath != null && !responsePath.trim().isEmpty()) {
            builder.responsePath(responsePath);
        }
    }

    private boolean requiresKeyForOperation(String provider, String algorithm) {
        if (!"internal".equalsIgnoreCase(provider)) {
            return true;
        }

        if (algorithm == null) {
            return true;
        }

        String normalized = algorithm.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "base64", "base64-encode", "base64-decode",
                    "hex", "hex-encode", "hex-decode",
                    "url", "url-encode", "url-decode", "urlencode", "urldecode",
                    "md5", "sha1", "sha-1", "sha256", "sha-256", "sha512", "sha-512", "sm3" -> false;
            default -> true;
        };
    }

    /**
     * Simple API client interface for external crypto service
     */
    public interface ApiClient {
        boolean isAvailable();
        ApiResponse processRequest(ApiRequest request) throws Exception;
    }

    /**
     * API request wrapper
     */
    public static class ApiRequest {
        private final String action;
        private final String algorithm;
        private final String key;
        private final String data;
        private final String method;
        private final String endpoint;
        private final Map<String, String> parameters;
        private final String contentType;
        private final String bodyTemplate;
        private final String responsePath;
        private final Map<String, String> fieldMap;
        private final Map<String, String> headers;

        private ApiRequest(Builder builder) {
            this.action = builder.action;
            this.algorithm = builder.algorithm;
            this.key = builder.key;
            this.data = builder.data;
            this.method = builder.method;
            this.endpoint = builder.endpoint;
            this.parameters = builder.parameters != null ? new HashMap<>(builder.parameters) : new HashMap<>();
            this.contentType = builder.contentType;
            this.bodyTemplate = builder.bodyTemplate;
            this.responsePath = builder.responsePath;
            this.fieldMap = builder.fieldMap != null ? new HashMap<>(builder.fieldMap) : new HashMap<>();
            this.headers = builder.headers != null ? new HashMap<>(builder.headers) : new HashMap<>();
        }

        public String getAction() { return action; }
        public String getAlgorithm() { return algorithm; }
        public String getKey() { return key; }
        public String getData() { return data; }
        public String getMethod() { return method; }
        public String getEndpoint() { return endpoint; }
        public Map<String, String> getParameters() { return new HashMap<>(parameters); }
        public String getContentType() { return contentType; }
        public String getBodyTemplate() { return bodyTemplate; }
        public String getResponsePath() { return responsePath; }
        public Map<String, String> getFieldMap() { return new HashMap<>(fieldMap); }
        public Map<String, String> getHeaders() { return new HashMap<>(headers); }

        public static class Builder {
            private String action;
            private String algorithm;
            private String key;
            private String data;
            private String method;
            private String endpoint;
            private Map<String, String> parameters;
            private String contentType;
            private String bodyTemplate;
            private String responsePath;
            private Map<String, String> fieldMap;
            private Map<String, String> headers;

            public Builder action(String action) { this.action = action; return this; }
            public Builder algorithm(String algorithm) { this.algorithm = algorithm; return this; }
            public Builder key(String key) { this.key = key; return this; }
            public Builder data(String data) { this.data = data; return this; }
            public Builder method(String method) { this.method = method; return this; }
            public Builder endpoint(String endpoint) { this.endpoint = endpoint; return this; }
            public Builder contentType(String contentType) { this.contentType = contentType; return this; }
            public Builder bodyTemplate(String bodyTemplate) { this.bodyTemplate = bodyTemplate; return this; }
            public Builder responsePath(String responsePath) { this.responsePath = responsePath; return this; }

            public Builder fieldMap(Map<String, String> fieldMap) {
                this.fieldMap = fieldMap != null ? new HashMap<>(fieldMap) : null;
                return this;
            }

            public Builder headers(Map<String, String> headers) {
                this.headers = headers != null ? new HashMap<>(headers) : null;
                return this;
            }

            public Builder addParameter(String key, String value) {
                if (this.parameters == null) {
                    this.parameters = new HashMap<>();
                }
                this.parameters.put(key, value);
                return this;
            }

            public ApiRequest build() { return new ApiRequest(this); }
        }
    }

    /**
     * API response wrapper
     */
    public static class ApiResponse {
        private final boolean success;
        private final String data;
        private final String errorMessage;
        private final long processingTimeMs;
        private final Map<String, Object> metadata;

        public ApiResponse(boolean success, String data, String errorMessage,
                          long processingTimeMs, Map<String, Object> metadata) {
            this.success = success;
            this.data = data;
            this.errorMessage = errorMessage;
            this.processingTimeMs = processingTimeMs;
            this.metadata = metadata != null ? new HashMap<>(metadata) : new HashMap<>();
        }

        public boolean isSuccess() { return success; }
        public String getData() { return data; }
        public String getErrorMessage() { return errorMessage; }
        public long getProcessingTimeMs() { return processingTimeMs; }
        public Map<String, Object> getMetadata() { return new HashMap<>(metadata); }
        public Object getMetadata(String key) { return metadata.get(key); }
        public boolean hasMetadata(String key) { return metadata.containsKey(key); }
    }
}
