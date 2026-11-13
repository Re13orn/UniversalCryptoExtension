package com.universal.crypto.processor.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.universal.crypto.processor.impl.CryptoProcessor.ApiClient;
import com.universal.crypto.processor.impl.CryptoProcessor.ApiRequest;
import com.universal.crypto.processor.impl.CryptoProcessor.ApiResponse;
import com.universal.crypto.util.ExtensionSettings;
import com.universal.crypto.util.Logger;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * HTTP-based ApiClient implementation. Delegates encrypt/decrypt/sign/verify/lookup_key
 * to external HTTP endpoints configurable per action. The base URL and timeout are
 * taken from ExtensionSettings.
 */
public class HttpApiClient implements ApiClient {

    private static final Logger logger = Logger.getInstance();

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public HttpApiClient() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(ExtensionSettings.getInstance().getApiTimeoutMs()))
                .build();
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public ApiResponse processRequest(ApiRequest request) throws Exception {
        long start = System.currentTimeMillis();
        try {
            String endpoint = request.getEndpoint();
            String method = request.getMethod() != null
                    ? request.getMethod().toUpperCase(Locale.ROOT)
                    : "POST";

            if (endpoint == null || endpoint.trim().isEmpty()) {
                // For lookup_key we may allow endpoint to be provided in request; otherwise fail
                // To keep behavior explicit, require endpoint for all actions here.
                return new ApiResponse(false, null,
                        "Missing endpoint for action: " + request.getAction(),
                        System.currentTimeMillis() - start, null);
            }

            String base = ExtensionSettings.getInstance().getApiBaseUrl();
            String fullUrl = buildUrl(base, endpoint);

            String requestBody = buildRequestBody(request);
            boolean sendBody = shouldSendBody(method);

            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(fullUrl))
                    .timeout(Duration.ofMillis(ExtensionSettings.getInstance().getApiTimeoutMs()));

            // Apply per-request headers first
            Map<String, String> extraHeaders = request.getHeaders();
            if (extraHeaders != null) {
                for (Map.Entry<String, String> header : extraHeaders.entrySet()) {
                    if (header.getKey() == null || header.getKey().trim().isEmpty()) {
                        continue;
                    }
                    builder.setHeader(header.getKey(), header.getValue() != null ? header.getValue() : "");
                }
            }

            if (sendBody && !containsHeader(extraHeaders, "Content-Type")) {
                String contentType = request.getContentType();
                if (contentType == null || contentType.trim().isEmpty()) {
                    contentType = "application/json";
                }
                builder.setHeader("Content-Type", contentType);
            }

            if ("GET".equals(method)) {
                builder.GET();
            } else if ("HEAD".equals(method)) {
                builder.method("HEAD", HttpRequest.BodyPublishers.noBody());
            } else {
                builder.method(method, HttpRequest.BodyPublishers.ofString(
                        requestBody != null ? requestBody : "",
                        StandardCharsets.UTF_8));
            }

            HttpResponse<String> resp = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            boolean ok = resp.statusCode() / 100 == 2;
            String respBody = resp.body();

            Map<String, Object> metadata = null;
            String extracted = respBody;
            String responsePath = request.getResponsePath();
            if (ok && responsePath != null && !responsePath.trim().isEmpty()) {
                try {
                    extracted = extractResponseValue(respBody, responsePath);
                    metadata = new HashMap<>();
                    metadata.put("responsePath", responsePath);
                    metadata.put("responseExtracted", true);
                } catch (IllegalArgumentException e) {
                    metadata = new HashMap<>();
                    metadata.put("responsePath", responsePath);
                    metadata.put("responseExtracted", false);
                    metadata.put("rawResponse", respBody);
                    logger.error("apiResponsePath extraction failed: action=" + request.getAction()
                            + ", endpoint=" + endpoint + ", path=" + responsePath + " - " + e.getMessage());
                    return new ApiResponse(false, null, e.getMessage(),
                            System.currentTimeMillis() - start, metadata);
                } catch (Exception e) {
                    // If JSON parsing fails, fall back to raw body for compatibility
                    metadata = new HashMap<>();
                    metadata.put("responsePath", responsePath);
                    metadata.put("responseExtracted", false);
                    logger.error("apiResponsePath extraction failed (non-JSON response): action=" + request.getAction()
                            + ", endpoint=" + endpoint + ", path=" + responsePath + " - " + e.getMessage());
                }
            }

            return new ApiResponse(ok, extracted, ok ? null : ("HTTP " + resp.statusCode()),
                    System.currentTimeMillis() - start, metadata);
        } catch (Exception e) {
            return new ApiResponse(false, null, "HttpApiClient error: " + e.getMessage(),
                    System.currentTimeMillis() - start, null);
        }
    }

    private String buildUrl(String baseUrl, String endpoint) {
        String b = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String e = endpoint.startsWith("/") ? endpoint : "/" + endpoint;
        return b + e;
    }

    private boolean shouldSendBody(String method) {
        if (method == null) {
            return true;
        }
        return !("GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method));
    }

    private boolean containsHeader(Map<String, String> headers, String name) {
        if (headers == null || name == null) {
            return false;
        }
        for (String key : headers.keySet()) {
            if (key != null && key.equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }

    private String buildRequestBody(ApiRequest request) throws Exception {
        String template = request.getBodyTemplate();
        if (template != null && !template.trim().isEmpty()) {
            return applyTemplate(template, request);
        }

        Map<String, String> fieldMap = request.getFieldMap();
        String actionField = mappedField(fieldMap, "action");
        String algorithmField = mappedField(fieldMap, "algorithm");
        String keyField = mappedField(fieldMap, "key");
        String dataField = mappedField(fieldMap, "data");
        String parametersField = mappedField(fieldMap, "parameters");

        ObjectNode body = objectMapper.createObjectNode();
        if (request.getAction() != null) body.put(actionField, request.getAction());
        if (request.getAlgorithm() != null) body.put(algorithmField, request.getAlgorithm());
        if (request.getKey() != null) body.put(keyField, request.getKey());
        if (request.getData() != null) body.put(dataField, request.getData());

        if (request.getParameters() != null && !request.getParameters().isEmpty()) {
            ObjectNode params = objectMapper.createObjectNode();
            for (Map.Entry<String, String> e : request.getParameters().entrySet()) {
                if (e.getKey() == null) {
                    continue;
                }
                params.put(e.getKey(), e.getValue());
            }
            body.set(parametersField, params);
        }

        return objectMapper.writeValueAsString(body);
    }

    private String mappedField(Map<String, String> fieldMap, String defaultName) {
        if (fieldMap == null || fieldMap.isEmpty()) {
            return defaultName;
        }
        String mapped = fieldMap.get(defaultName);
        return mapped != null && !mapped.trim().isEmpty() ? mapped.trim() : defaultName;
    }

    private String applyTemplate(String template, ApiRequest request) {
        String result = template;
        result = result.replace("${action}", nullToEmpty(request.getAction()));
        result = result.replace("${algorithm}", nullToEmpty(request.getAlgorithm()));
        result = result.replace("${key}", nullToEmpty(request.getKey()));
        result = result.replace("${data}", nullToEmpty(request.getData()));

        Map<String, String> params = request.getParameters();
        if (params != null) {
            for (Map.Entry<String, String> entry : params.entrySet()) {
                if (entry.getKey() == null) {
                    continue;
                }
                String placeholder = "${param." + entry.getKey() + "}";
                result = result.replace(placeholder, nullToEmpty(entry.getValue()));
            }
        }

        return result;
    }

    private static String nullToEmpty(String value) {
        return value != null ? value : "";
    }

    private String extractResponseValue(String body, String path) throws Exception {
        if (body == null) {
            throw new IllegalArgumentException("Empty response body");
        }

        JsonNode root = objectMapper.readTree(body);
        String pointer = toJsonPointer(path);
        JsonNode node = pointer.isEmpty() ? root : root.at(pointer);

        if (node == null || node.isMissingNode()) {
            throw new IllegalArgumentException("Response path not found: " + path);
        }

        if (node.isNull()) {
            return "null";
        }
        if (node.isValueNode()) {
            return node.asText();
        }
        return node.toString();
    }

    private String toJsonPointer(String path) {
        String trimmed = path != null ? path.trim() : "";
        if (trimmed.isEmpty()) {
            return "";
        }
        if (trimmed.startsWith("/")) {
            return trimmed;
        }

        String normalized = trimmed;
        if (normalized.startsWith("$")) {
            normalized = normalized.substring(1);
        }
        if (normalized.startsWith(".")) {
            normalized = normalized.substring(1);
        }

        StringBuilder pointer = new StringBuilder();
        String[] segments = normalized.split("\\.");
        for (String segment : segments) {
            if (segment == null || segment.isEmpty()) {
                continue;
            }

            String remaining = segment;
            while (true) {
                int open = remaining.indexOf('[');
                if (open < 0) {
                    if (!remaining.isEmpty()) {
                        pointer.append('/').append(escapeJsonPointerToken(remaining));
                    }
                    break;
                }

                String fieldName = remaining.substring(0, open);
                if (!fieldName.isEmpty()) {
                    pointer.append('/').append(escapeJsonPointerToken(fieldName));
                }

                int close = remaining.indexOf(']', open);
                if (close < 0) {
                    // Treat malformed bracket as literal
                    pointer.append('/').append(escapeJsonPointerToken(remaining.substring(open)));
                    break;
                }

                String index = remaining.substring(open + 1, close);
                if (!index.isEmpty()) {
                    pointer.append('/').append(escapeJsonPointerToken(index));
                }

                remaining = remaining.substring(close + 1);
            }
        }

        return pointer.toString();
    }

    private String escapeJsonPointerToken(String token) {
        return token.replace("~", "~0").replace("/", "~1");
    }
}
