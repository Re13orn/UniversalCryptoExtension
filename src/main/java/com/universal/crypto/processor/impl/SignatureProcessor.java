package com.universal.crypto.processor.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.universal.crypto.model.Constants.ActionType;
import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.AbstractProcessor;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.processor.ProcessorResult;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Signature processor for generating and verifying signatures
 */
public class SignatureProcessor extends AbstractProcessor {

    private final CryptoProcessor.ApiClient apiClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public SignatureProcessor(CryptoProcessor.ApiClient apiClient) {
        super("signature", Set.of(ActionType.SIGN, ActionType.VERIFY));
        this.apiClient = apiClient;
    }

    @Override
    public Map<String, String> getRequiredParameters() {
        Map<String, String> params = new HashMap<>();
        params.put(ConfigKey.ALGORITHM, "Signature algorithm (e.g., HMAC-SHA256, RSA-SHA256)");
        params.put(ConfigKey.KEY_SOURCE, "Key source type (static, lookup)");
        params.put(ConfigKey.SIGN_CONTENT, "Content to sign (method+path+body, body, custom)");
        return params;
    }

    @Override
    protected boolean validateSpecificConfiguration(ProcessingAction action) {
        String algorithm = getConfigString(action, ConfigKey.ALGORITHM);
        if (algorithm == null || algorithm.trim().isEmpty()) {
            return false;
        }

        String keySource = getConfigString(action, ConfigKey.KEY_SOURCE);
        if (keySource == null || keySource.trim().isEmpty()) {
            return false;
        }

        String signContent = getConfigString(action, ConfigKey.SIGN_CONTENT);
        if (signContent == null || signContent.trim().isEmpty()) {
            return false;
        }

        return true;
    }

    @Override
    public boolean isAvailable() {
        return true; // Internal algorithms remain available independently of the external client.
    }

    @Override
    protected ProcessorResult processInternal(ProcessingAction action, String content,
                                            ProcessorContext context) throws Exception {

        if (!"internal".equalsIgnoreCase(getConfigString(action, ConfigKey.CRYPTO_PROVIDER, "external"))
                && (apiClient == null || !apiClient.isAvailable()))
            return ProcessorResult.failure("External signature client is unavailable; no signing/verification was performed.").build();

        String actionType = action.getActionType();

        if (ActionType.SIGN.equals(actionType)) {
            return performSigning(action, content, context);
        } else if (ActionType.VERIFY.equals(actionType)) {
            return performVerification(action, content, context);
        } else {
            return ProcessorResult.failure("Unsupported action type: " + actionType).build();
        }
    }

    private ProcessorResult performSigning(ProcessingAction action, String content,
                                         ProcessorContext context) throws Exception {

        String algorithm = getConfigString(action, ConfigKey.ALGORITHM);
        String signContent = getConfigString(action, ConfigKey.SIGN_CONTENT);
        String provider = getConfigString(action, ConfigKey.CRYPTO_PROVIDER, "external");

        Map<String, String> preparedHeaders = applyHeaderTemplates(action, content, context);
        String dataToSign = buildSigningData(signContent, content, context, action);
        String key = resolveSigningKey(action, context, content);

        if (key == null) {
            return ProcessorResult.failure("Failed to resolve signing key").build();
        }

        if ("internal".equalsIgnoreCase(provider)) {
            // Internal signing
            String signature = InternalSignatureEngine.sign(action, dataToSign, key);
            
            return createSignResult(action, content, signature, algorithm, "internal", dataToSign, preparedHeaders);
        }

        // External signing (existing logic)
        CryptoProcessor.ApiRequest.Builder builder = new CryptoProcessor.ApiRequest.Builder()
                .action("sign")
                .algorithm(algorithm)
                .key(key)
                .data(dataToSign);

        // Optional per-action endpoint/method overrides
        String ep = getConfigString(action, ConfigKey.SIGN_ENDPOINT);
        String m = getConfigString(action, ConfigKey.SIGN_METHOD, "POST");
        if (ep != null && !ep.trim().isEmpty()) {
            builder.endpoint(ep);
        }
        if (m != null && !m.trim().isEmpty()) {
            builder.method(m);
        }

        applyExternalApiOverrides(action, builder, null);

        CryptoProcessor.ApiRequest request = builder.build();

        CryptoProcessor.ApiResponse response = apiClient.processRequest(request);

        if (response.isSuccess()) {
            String signature = response.getData();

            return createSignResult(action, content, signature, algorithm, "external", dataToSign, preparedHeaders);
        } else {
            return ProcessorResult.failure("Signature generation failed: " + response.getErrorMessage())
                    .addMetadata("algorithm", algorithm)
                    .build();
        }
    }

    private ProcessorResult performVerification(ProcessingAction action, String content,
                                              ProcessorContext context) throws Exception {

        String algorithm = getConfigString(action, ConfigKey.ALGORITHM);
        String signContent = getConfigString(action, ConfigKey.SIGN_CONTENT);
        String provider = getConfigString(action, ConfigKey.CRYPTO_PROVIDER, "external");

        ResolvedSignature expected = resolveExpectedSignature(action, content, context);
        String expectedSignature = expected.value();
        if (expectedSignature == null) {
            return ProcessorResult.failure("未找到用于验签的签名值")
                    .addMetadata("signatureSource", expected.source())
                    .build();
        }

        String dataToSign = buildSigningData(signContent, content, context, action);
        String key = resolveSigningKey(action, context, content);

        if (key == null) {
            return ProcessorResult.failure("Failed to resolve verification key").build();
        }

        if ("internal".equalsIgnoreCase(provider)) {
            // Internal verification
            String calculatedSignature = InternalSignatureEngine.sign(action, dataToSign, key);
            
            String format = getConfigString(action, ConfigKey.CIPHER_FORMAT, "hex");
            boolean verified;
            if ("base64".equalsIgnoreCase(format)) {
                verified = calculatedSignature.equals(expectedSignature);
            } else {
                verified = calculatedSignature.equalsIgnoreCase(expectedSignature);
            }

             return ProcessorResult.success(Boolean.toString(verified))
                .addMetadata("algorithm", algorithm)
                .addMetadata("provider", "internal")
                .addMetadata("verified", verified)
                .addMetadata("signatureSource", expected.source())
                .addMetadata("expectedSignature", expectedSignature)
                .addMetadata("calculatedSignature", calculatedSignature)
                .addMetadata("signedData", dataToSign)
                .build();
        }

        // External verification
        CryptoProcessor.ApiRequest.Builder builder = new CryptoProcessor.ApiRequest.Builder()
                .action("verify")
                .algorithm(algorithm)
                .key(key)
                .data(dataToSign)
                .addParameter("signature", expectedSignature);

        String ep = getConfigString(action, ConfigKey.VERIFY_ENDPOINT);
        String m = getConfigString(action, ConfigKey.VERIFY_METHOD, "POST");
        if (ep != null && !ep.trim().isEmpty()) {
            builder.endpoint(ep);
        }
        if (m != null && !m.trim().isEmpty()) {
            builder.method(m);
        }

        applyExternalApiOverrides(action, builder, null);

        CryptoProcessor.ApiRequest request = builder.build();

        CryptoProcessor.ApiResponse response = apiClient.processRequest(request);

        boolean verified = response.isSuccess() && "true".equals(response.getData());

        return ProcessorResult.success(Boolean.toString(verified))
                .addMetadata("algorithm", algorithm)
                .addMetadata("verified", verified)
                .addMetadata("signatureSource", expected.source())
                .addMetadata("expectedSignature", expectedSignature)
                .addMetadata("signedData", dataToSign)
                .build();
    }

    private ResolvedSignature resolveExpectedSignature(ProcessingAction action, String content, ProcessorContext context) {
        String configuredSource = getConfigString(action, ConfigKey.SIGNATURE_SOURCE);
        String fixedSignature = getConfigString(action, ConfigKey.EXPECTED_SIGNATURE);

        // Backward compatibility: older rules used expectedSignature as an override without a source selector.
        if ((configuredSource == null || configuredSource.trim().isEmpty())
                && fixedSignature != null && !fixedSignature.trim().isEmpty()) {
            return new ResolvedSignature("fixed", fixedSignature.trim());
        }

        String source = configuredSource == null || configuredSource.trim().isEmpty()
                ? "header"
                : configuredSource.trim().toLowerCase(Locale.ROOT);

        return switch (source) {
            case "fixed" -> new ResolvedSignature(source,
                    fixedSignature == null || fixedSignature.trim().isEmpty() ? null : fixedSignature.trim());
            case "body-field" -> new ResolvedSignature(source,
                    resolveSignatureFromBody(content, getConfigString(action, ConfigKey.SIGNATURE_FIELD_PATH, "$.signature")));
            case "query" -> new ResolvedSignature(source,
                    resolveSignatureFromQuery(context, getConfigString(action, ConfigKey.SIGNATURE_QUERY_PARAM, "sign")));
            case "header" -> {
                String signatureHeader = getConfigString(action, ConfigKey.SIGNATURE_HEADER, "X-Signature");
                yield new ResolvedSignature(source, context != null ? context.getHeader(signatureHeader) : null);
            }
            default -> new ResolvedSignature(source, null);
        };
    }

    private String resolveSignatureFromBody(String content, String path) {
        if (content == null || content.trim().isEmpty()) {
            return null;
        }
        try {
            JsonNode current = objectMapper.readTree(content);
            String normalized = normalizeJsonPath(path);
            if (normalized.isEmpty()) {
                return jsonNodeToSignature(current);
            }
            for (String segment : normalized.split("\\.")) {
                current = resolveJsonSegment(current, segment);
                if (current == null || current.isMissingNode() || current.isNull()) {
                    return null;
                }
            }
            return jsonNodeToSignature(current);
        } catch (Exception e) {
            return null;
        }
    }

    private String normalizeJsonPath(String path) {
        if (path == null) {
            return "";
        }
        String normalized = path.trim();
        if (normalized.startsWith("$.")) {
            normalized = normalized.substring(2);
        } else if (normalized.startsWith("$")) {
            normalized = normalized.substring(1);
        }
        if (normalized.startsWith(".")) {
            normalized = normalized.substring(1);
        }
        return normalized;
    }

    private JsonNode resolveJsonSegment(JsonNode current, String segment) {
        if (current == null || segment == null || segment.isEmpty()) {
            return current;
        }
        String remaining = segment;
        int bracket = remaining.indexOf('[');
        if (bracket > 0) {
            String field = remaining.substring(0, bracket);
            current = current.get(field);
            remaining = remaining.substring(bracket);
        } else if (bracket < 0) {
            return current.get(remaining);
        }

        while (current != null && remaining.startsWith("[")) {
            int end = remaining.indexOf(']');
            if (end <= 1) {
                return null;
            }
            int index = Integer.parseInt(remaining.substring(1, end));
            current = current.get(index);
            remaining = remaining.substring(end + 1);
        }
        return current;
    }

    private String jsonNodeToSignature(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        return node.isValueNode() ? node.asText() : node.toString();
    }

    private String resolveSignatureFromQuery(ProcessorContext context, String paramName) {
        if (context == null || context.getUrl() == null || context.getUrl().getQuery() == null) {
            return null;
        }
        String expectedName = paramName == null || paramName.trim().isEmpty() ? "sign" : paramName.trim();
        for (String pair : context.getUrl().getQuery().split("&")) {
            int idx = pair.indexOf('=');
            String rawKey = idx >= 0 ? pair.substring(0, idx) : pair;
            String rawValue = idx >= 0 ? pair.substring(idx + 1) : "";
            String key = urlDecode(rawKey);
            if (expectedName.equals(key)) {
                return urlDecode(rawValue);
            }
        }
        return null;
    }

    private String urlDecode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private record ResolvedSignature(String source, String value) {}

    private String buildSigningData(String signContent, String content, ProcessorContext context, ProcessingAction action) {
        String baseContent;
        switch (signContent.toLowerCase()) {
            case "body":
                baseContent = content != null ? content : "";
                break;

            case "method+path+body":
                StringBuilder sb = new StringBuilder();
                if (context.getMethod() != null) {
                    sb.append(context.getMethod().toUpperCase());
                }
                if (context.getPath() != null) {
                    sb.append(context.getPath());
                }
                if (content != null) {
                    sb.append(content);
                }
                baseContent = sb.toString();
                break;

            case "custom":
                String customTemplate = getConfigString(action, ConfigKey.CUSTOM_SIGN_TEMPLATE);
                if (customTemplate != null) {
                    baseContent = replaceTemplateVariables(customTemplate, content, context);
                } else {
                    baseContent = content != null ? content : "";
                }
                break;

            default:
                baseContent = content != null ? content : "";
        }
        
        // Apply canonicalization if configured
        if (action != null && "true".equalsIgnoreCase(getConfigString(action, ConfigKey.SORT_KEYS))) {
            return canonicalize(baseContent, action);
        }
        
        return baseContent;
    }

    private String canonicalize(String content, ProcessingAction action) {
        if (content == null || content.isEmpty()) {
            return "";
        }

        try {
            // Try parsing as JSON first
            JsonNode root = objectMapper.readTree(content);
            if (root.isObject()) {
                return sortJsonKeys((ObjectNode) root, action);
            }
        } catch (Exception e) {
            // Not JSON, try parsing as URL params
        }

        // Try parsing as URL params (k=v&a=b)
        if (content.contains("=") && content.contains("&")) {
            return sortUrlParams(content, action);
        }

        return content; // Return original if no structure detected
    }

    private String sortJsonKeys(ObjectNode node, ProcessingAction action) {
        TreeMap<String, JsonNode> sortedMap = new TreeMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            sortedMap.put(field.getKey(), field.getValue());
        }

        String pairSep = getConfigString(action, ConfigKey.PAIR_SEPARATOR, "&");
        String kvSep = getConfigString(action, ConfigKey.KV_SEPARATOR, "=");
        boolean encode = "true".equalsIgnoreCase(getConfigString(action, ConfigKey.URL_ENCODE_VALUES));

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, JsonNode> entry : sortedMap.entrySet()) {
            if (sb.length() > 0) {
                sb.append(pairSep);
            }
            sb.append(entry.getKey()).append(kvSep);
            
            String val = entry.getValue().isValueNode() ? entry.getValue().asText() : entry.getValue().toString();
            if (encode) {
                val = urlEncode(val);
            }
            sb.append(val);
        }
        return sb.toString();
    }

    private String sortUrlParams(String content, ProcessingAction action) {
        String[] pairs = content.split("&");
        TreeMap<String, String> sortedMap = new TreeMap<>();
        
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            if (idx > 0) {
                String key = pair.substring(0, idx);
                String val = pair.substring(idx + 1);
                sortedMap.put(key, val);
            } else {
                sortedMap.put(pair, "");
            }
        }

        String pairSep = getConfigString(action, ConfigKey.PAIR_SEPARATOR, "&");
        String kvSep = getConfigString(action, ConfigKey.KV_SEPARATOR, "=");
        boolean encode = "true".equalsIgnoreCase(getConfigString(action, ConfigKey.URL_ENCODE_VALUES));

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : sortedMap.entrySet()) {
            if (sb.length() > 0) {
                sb.append(pairSep);
            }
            sb.append(entry.getKey()).append(kvSep);
            
            String val = entry.getValue();
            // Assuming input might already be encoded or not. 
            // Ideally we should decode first if re-encoding, but let's assume raw for now
            // or that the user wants to double encode if they checked the box.
            // A safer bet for "canonicalization" is usually: Decode -> Sort -> Encode
            try {
                val = java.net.URLDecoder.decode(val, StandardCharsets.UTF_8);
            } catch (Exception ignored) {}

            if (encode) {
                val = urlEncode(val);
            }
            sb.append(val);
        }
        return sb.toString();
    }

    private String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8)
                    .replace("+", "%20")
                    .replace("*", "%2A")
                    .replace("%7E", "~");
        } catch (Exception e) {
            return value;
        }
    }

    private String replaceTemplateVariables(String template, String content, ProcessorContext context) {
        return com.universal.crypto.util.TemplateEngine.process(template, context, content);
    }

    private Map<String, String> applyHeaderTemplates(ProcessingAction action, String content, ProcessorContext context) {
        Map<String, String> templates = getConfigStringMap(action, ConfigKey.HEADER_TEMPLATES);
        if (templates.isEmpty() || context == null) {
            return Map.of();
        }

        Map<String, String> resolved = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : templates.entrySet()) {
            String value = replaceTemplateVariables(entry.getValue(), content, context);
            context.setHeader(entry.getKey(), value);
            resolved.put(entry.getKey(), value);
        }
        return resolved;
    }

    private String resolveSigningKey(ProcessingAction action, ProcessorContext context, String content) throws com.universal.crypto.processor.ProcessorException {
        String keySource = getConfigString(action, ConfigKey.KEY_SOURCE);

        switch (keySource.toLowerCase()) {
            case "none":
                return "";

            case "static":
                return getConfigString(action, ConfigKey.KEY_VALUE);

            case "lookup":
                Object cached = context.getSharedData("signature_key");
                if (cached != null) return cached.toString();
                
                String lookupEndpoint = getConfigString(action, ConfigKey.LOOKUP_ENDPOINT);
                String lookupMethodParam = getConfigString(action, ConfigKey.LOOKUP_METHOD); // e.g. md5-hash
                String lookupMethodHttp = getConfigString(action, ConfigKey.LOOKUP_HTTP_METHOD, "POST"); // e.g. POST
                String responsePath = getConfigString(action, ConfigKey.RESPONSE_KEY_PATH);
                
                // Align with CryptoProcessor: default to "key" if not specified
                if (responsePath == null || responsePath.trim().isEmpty()) {
                    responsePath = "key";
                }
                
                if (lookupEndpoint == null || lookupEndpoint.isEmpty()) return null;
                if (apiClient == null || !apiClient.isAvailable())
                    throw new com.universal.crypto.processor.ProcessorException("Signature key lookup client is unavailable.");

                try {
                    // Fix: Use lookup_key action to match CryptoProcessor's expected protocol
                    CryptoProcessor.ApiRequest.Builder requestBuilder = new CryptoProcessor.ApiRequest.Builder()
                        .action("lookup_key")
                        .endpoint(lookupEndpoint)
                        .method(lookupMethodHttp);
                    
                    if (content != null) {
                        requestBuilder.data(content);
                    }

                    if (lookupMethodParam != null && !lookupMethodParam.isEmpty()) {
                        requestBuilder.addParameter("lookupMethod", lookupMethodParam);
                    }
                    if (responsePath != null && !responsePath.isEmpty()) {
                        requestBuilder.addParameter("keyPath", responsePath);
                        // Also set responsePath on the request so HttpApiClient handles extraction
                        requestBuilder.responsePath(responsePath); 
                    }
                    
                    // Apply overrides (templates, headers, field map, etc.)
                    applyExternalApiOverrides(action, requestBuilder, responsePath);

                    CryptoProcessor.ApiRequest request = requestBuilder.build();

                    CryptoProcessor.ApiResponse response = apiClient.processRequest(request);
                    if (response.isSuccess()) {
                        String key = response.getData();
                        // HttpApiClient handles extraction if responsePath is set.
                        // So response.getData() is already the extracted key.
                        
                        context.setSharedData("signature_key", key);
                        return key;
                    }
                    throw new com.universal.crypto.processor.ProcessorException("Signature key lookup failed: " + response.getErrorMessage());
                } catch (Exception e) {
                    throw new com.universal.crypto.processor.ProcessorException("Signature key lookup error: " + e.getMessage(), e);
                }

            default:
                return null;
        }
    }

    private void applyExternalApiOverrides(ProcessingAction action,
                                          CryptoProcessor.ApiRequest.Builder builder,
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

    private String generateTimestamp() {
        return generateTimestamp(null);
    }

    private String generateTimestamp(ProcessingAction action) {
        String format = action != null ? getConfigString(action, ConfigKey.TIMESTAMP_FORMAT) : null;
        if (format == null) {
            return Long.toString(System.currentTimeMillis() / 1000);
        }

        try {
            SimpleDateFormat sdf = new SimpleDateFormat(format);
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
            return sdf.format(new Date());
        } catch (Exception e) {
            return Long.toString(System.currentTimeMillis() / 1000);
        }
    }

    private ProcessorResult createSignResult(ProcessingAction action, String content, String signature, String algorithm,
                                             String provider, String dataToSign, Map<String, String> preparedHeaders) {
        // Check if we need to inject signature into JSON body
        if (com.universal.crypto.model.Constants.TargetType.FIELD.equals(action.getTargetType()) 
                && action.getTargetName() != null) {
            
            String fieldName = action.getTargetName();
            try {
                if (content != null && !content.isEmpty()) {
                    JsonNode root = objectMapper.readTree(content);
                    if (root.isObject()) {
                        ((ObjectNode) root).put(fieldName, signature);
                        signature = root.toString(); // Return full body as signature payload
                    }
                }
            } catch (Exception e) {
                // Ignore JSON error
            }
        }

        ProcessorResult.Builder resultBuilder = ProcessorResult.success(signature)
                    .addMetadata("algorithm", algorithm)
                    .addMetadata("provider", provider)
                    .addMetadata("signedData", dataToSign)
                    .addMetadata("timestamp", System.currentTimeMillis());

        if (preparedHeaders != null && !preparedHeaders.isEmpty()) {
            resultBuilder.addMetadata("setHeaders", preparedHeaders);
        }

        String timestampHeader = getConfigString(action, ConfigKey.TIMESTAMP_HEADER);
        if (timestampHeader != null && !timestampHeader.trim().isEmpty()) {
            String timestamp = generateTimestamp(action);
            resultBuilder.addMetadata("timestampHeader", timestampHeader)
                       .addMetadata("timestampValue", timestamp);
        }
        return resultBuilder.build();
    }
}
