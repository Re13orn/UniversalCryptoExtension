package com.universal.crypto.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.universal.crypto.processor.ProcessorContext;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import java.math.BigDecimal;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Handles processing of template strings with variables and functions.
 * Supports:
 * - Basic variables: ${method}, ${path}, ${body}, ${timestamp}, ${header.name}
 * - Data extraction: ${json:path}
 * - Functions: ${base64:...}, ${md5:...}, ${sha256:...}, ${random:16}
 * - Nested expressions are supported via recursive processing.
 */
public class TemplateEngine {

    private static final Pattern TAG_PATTERN = Pattern.compile("\\$\\{([^}]+)\\}");
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final SecureRandom random = new SecureRandom();

    /**
     * Replaces all variables in the template with values from the context.
     */
    public static String process(String template, ProcessorContext context, String bodyContent) {
        return processRecursive(template, context, bodyContent, 0);
    }

    /**
     * Processes the template and returns a trace of what was replaced.
     * Useful for debugging (Dry Run).
     */
    public static Map<String, String> trace(String template, ProcessorContext context, String bodyContent) {
        Map<String, String> traceMap = new LinkedHashMap<>();
        
        // We do a single pass to capture top-level tags for the trace
        Matcher matcher = TAG_PATTERN.matcher(template);
        while (matcher.find()) {
            String tag = matcher.group(0);
            String content = matcher.group(1);
            try {
                String val = resolve(content, context, bodyContent);
                traceMap.put(tag, val);
            } catch (Exception e) {
                traceMap.put(tag, "<Error: " + e.getMessage() + ">");
            }
        }
        return traceMap;
    }

    private static String processRecursive(String input, ProcessorContext context, String bodyContent, int depth) {
        if (depth > 5) return input; // Safety limit
        if (input == null || !input.contains("${")) return input;

        Matcher matcher = TAG_PATTERN.matcher(input);
        StringBuffer sb = new StringBuffer();
        
        while (matcher.find()) {
            String content = matcher.group(1);
            // Recursively process the inner content first if it contains tags
            // But strict regex usage typically matches innermost or needs careful handling.
            // Our regex matches ${...} non-greedy for }, so it matches innermost if nested like ${a${b}}.
            // Actually [^}]+ stops at first }, so ${fn:${inner}} works if processed inside out?
            // Simple approach: Resolve the matched tag.
            
            String val = resolve(content, context, bodyContent);
            matcher.appendReplacement(sb, Matcher.quoteReplacement(val));
        }
        matcher.appendTail(sb);
        
        // If result still contains tags (nested case), recurse
        String result = sb.toString();
        if (result.contains("${") && !result.equals(input)) {
            return processRecursive(result, context, bodyContent, depth + 1);
        }
        return result;
    }

    private static String resolve(String expression, ProcessorContext context, String bodyContent) {
        // 1. Basic Variables
        switch (expression.toLowerCase()) {
            case "method": return context.getMethod() != null ? context.getMethod() : "";
            case "path": return context.getPath() != null ? context.getPath() : "";
            case "body": return bodyContent != null ? bodyContent : "";
            case "timestamp": return String.valueOf(context != null ? context.getTimestamp() : System.currentTimeMillis());
            case "host": return context != null && context.getHost() != null ? context.getHost() : "";
            case "query": return context != null && context.getUrl() != null && context.getUrl().getQuery() != null ? context.getUrl().getQuery() : "";
            case "queryjson": return queryToJson(context);
            case "payloadjson": return methodAwarePayloadJson(context, bodyContent);
            case "uuid": return UUID.randomUUID().toString();
            case "uuid32": return UUID.randomUUID().toString().replace("-", "");
        }

        // 2. Headers
        if (expression.toLowerCase().startsWith("header.")) {
            String headerName = expression.substring(7);
            String val = context.getHeader(headerName);
            return val != null ? val : ""; // Return empty if missing, or maybe keep tag?
        }

        // 3. Functions
        int colonIdx = expression.indexOf(':');
        if (colonIdx > 0) {
            String func = expression.substring(0, colonIdx).toLowerCase();
            String arg = expression.substring(colonIdx + 1);
            
            return applyFunction(func, arg, context, bodyContent);
        }

        return "${" + expression + "}"; // Unresolved, keep it
    }

    private static String applyFunction(String func, String arg, ProcessorContext context, String bodyContent) {
        try {
            switch (func) {
                case "json":
                    return extractJson(bodyContent, arg);
                case "base64":
                    return Base64.getEncoder().encodeToString(arg.getBytes(StandardCharsets.UTF_8));
                case "md5":
                    return DigestUtils.md5Hex(arg);
                case "sha256":
                    return DigestUtils.sha256Hex(arg);
                case "sha1":
                    return DigestUtils.sha1Hex(arg);
                case "random":
                    int len = Integer.parseInt(arg);
                    return generateRandomString(len);
                case "cryptoparam":
                    // Legacy crypto param behavior if needed, or map to canonicalize
                    return generateLegacyParamString(bodyContent); // or arg?
                case "canonicalize":
                    return canonicalize(arg, bodyContent);
                case "stablejson":
                case "stable-json":
                    return stableJson(arg, context, bodyContent);
                default:
                    return "${" + func + ":" + arg + "}";
            }
        } catch (Exception e) {
            return "<Error: " + e.getMessage() + ">";
        }
    }

    private static String canonicalize(String arg, String bodyContent) {
        // Format: path:pairSep:kvSep:exclude
        // Example 1: json:params:&:=:sign (Standard URL params excluding sign)
        // Example 2: json:json:sign (Sorted JSON excluding sign, pairSep='json' triggers json mode)
        
        String[] parts = arg.split(":");
        String path = parts.length > 0 ? parts[0] : "body";
        String pairSep = parts.length > 1 ? parts[1] : "&";
        String kvSep = parts.length > 2 ? parts[2] : "=";
        String exclude = parts.length > 3 ? parts[3] : null;

        String content = bodyContent;
        if (path.startsWith("json")) {
            // path might be "json" (root) or "json:foo" (nested)
            // But split(":") above might have broken "json:foo".
            // Let's refine parsing.
        }
        
        // Better parsing:
        // We expect arg to be like "json:params:&:=:sign" -> which split(:) handles roughly.
        // But "json:params" is one token for "path".
        // Let's assume the first part is ALWAYS the source/path.
        // If it starts with "json", it implies JSON extraction. 
        // We won't support arbitrarily complex paths with colons in this simple parser.
        
        // Re-parsing to handle potentially missing args safely
        path = "body";
        if (parts.length > 0) path = parts[0];
        
        if (parts.length > 1) pairSep = parts[1];
        if (parts.length > 2) kvSep = parts[2];
        if (parts.length > 3) exclude = parts[3];

        if (path.equalsIgnoreCase("json")) {
            content = bodyContent; // Root
        } else if (path.toLowerCase().startsWith("json")) {
             // Handle "json" without path as "json"
             if (path.equals("json")) {
                 content = bodyContent;
             } else {
                 // jsonfoo or json... ? 
                 // Actually TemplateEngine extraction used "json:path".
                 // If the user writes ${canonicalize:json:foo:&:=}, split give ["json", "foo", "&", "="].
                 // This is ambiguous.
                 // Let's stick to the convention: "json" means root json. "json.foo" means foo field?
                 // Or we reconstruct path if possible.
                 // To avoid breaking "json:params" syntax, let's treat the first argument as the path selector.
             }
        }
        
        // Actually, let's look at `extractJson`. It takes "path".
        // If user input is ${canonicalize:json:params:&:=}
        // split -> ["json", "params", "&", "="].
        // This shifts everything.
        // We should parse carefully.
        
        // Let's assume standard format is ALWAYS 3 or 4 delimiters?
        // Or we use different logic.
        // Allow simplified syntax: ${canonicalize:json:json:exclude}
        
        // Revised Logic:
        // 1. Path/Source
        // 2. Format (or pairSep)
        // 3. KvSep (optional)
        // 4. Exclude (optional)
        
        // If arg starts with "json:", we extract it first? 
        // No, let's use a simpler separator or assume the user uses placeholders correctly.
        
        // Let's rely on standard args.
        // If arg contains "json:", we treat it as "source".
        return processCanonicalize(arg, bodyContent);
    }

    private static String processCanonicalize(String arg, String bodyContent) {
        String[] tokens = arg.split(":");
        // Expected: [source_type, source_path, pair_sep, kv_sep, exclude]
        // But "json:path" is common. 
        // Let's support: source_path:pair_sep:kv_sep:exclude
        // where source_path can be "json" (root) or "json.field" (dot notation).
        
        String path = tokens.length > 0 ? tokens[0] : "json";
        String pairSep = tokens.length > 1 ? tokens[1] : "&";
        String kvSep = tokens.length > 2 ? tokens[2] : "=";
        String excludeField = tokens.length > 3 ? tokens[3] : null;

        // Special handling for JSON output format: json:json:exclude_fields
        if ("json".equalsIgnoreCase(pairSep) && excludeField == null && !kvSep.equals("=")) {
             excludeField = kvSep;
        }

        // Extract content
        String content = bodyContent;
        if (path.startsWith("json")) {
            if (path.length() > 4 && path.charAt(4) == '.') {
                 content = extractJson(bodyContent, path.substring(5)); // "json.foo" -> "foo"
            } else if (path.equals("json")) {
                 content = bodyContent;
            }
        }
        
        if (content == null || content.isEmpty()) return "";

        try {
            JsonNode root = objectMapper.readTree(content);
            if (root.isObject()) {
                Set<String> exclusions = new HashSet<>();
                if (excludeField != null && !excludeField.isEmpty()) {
                    for(String ex : excludeField.split(",")) exclusions.add(ex.trim());
                }
                
                TreeMap<String, JsonNode> sorted = new TreeMap<>();
                Iterator<Map.Entry<String, JsonNode>> fields = root.fields();
                while(fields.hasNext()) {
                    Map.Entry<String, JsonNode> entry = fields.next();
                    if (!exclusions.contains(entry.getKey())) {
                        sorted.put(entry.getKey(), entry.getValue());
                    }
                }
                
                // If pairSep is "json", output JSON object
                if ("json".equalsIgnoreCase(pairSep)) {
                    // Reconstruct JSON from sorted map
                    // We can't use sorted.toString() directly on TreeMap<String, JsonNode>, need mapper or manual
                    // Mapper is safer
                    return objectMapper.writeValueAsString(sorted);
                }
                
                // Else Key-Value pairs
                StringBuilder sb = new StringBuilder();
                for (Map.Entry<String, JsonNode> entry : sorted.entrySet()) {
                    if (sb.length() > 0) sb.append(pairSep);
                    sb.append(entry.getKey()).append(kvSep);
                    
                    JsonNode val = entry.getValue();
                    if (val.isValueNode()) {
                        sb.append(val.asText());
                    } else {
                        sb.append(val.toString());
                    }
                }
                return sb.toString();
            }
        } catch (Exception e) {
             // Fallback for non-json
        }
        return content;
    }

    private static String stableJson(String arg, ProcessorContext context, String bodyContent) {
        String source = arg == null || arg.trim().isEmpty() ? "payload" : arg.trim().toLowerCase(Locale.ROOT);
        JsonNode sourceNode = resolveStableJsonSource(source, context, bodyContent);
        if (sourceNode == null || sourceNode.isNull()) {
            return "{}";
        }

        JsonNode cleaned = cleanForStableJson(sourceNode.deepCopy());
        if (cleaned == null || cleaned.isNull()) {
            return "{}";
        }
        JsonNode stringified = stringifyScalarValues(cleaned);
        String result = stableStringify(stringified);
        return result == null || result.isEmpty() ? "{}" : result;
    }

    private static JsonNode resolveStableJsonSource(String source, ProcessorContext context, String bodyContent) {
        if ("query".equals(source) || "params".equals(source)) {
            return queryToNode(context);
        }
        if ("body".equals(source) || "data".equals(source)) {
            return parseJsonOrEmptyObject(bodyContent);
        }
        if ("payload".equals(source) || "requestpayload".equals(source) || "request-payload".equals(source)) {
            String method = context != null ? context.getMethod() : null;
            if ("GET".equalsIgnoreCase(method)) {
                return queryToNode(context);
            }
            return parseJsonOrEmptyObject(bodyContent);
        }
        if (source.startsWith("json.")) {
            String extracted = extractJson(bodyContent, source.substring(5));
            return parseJsonOrTextNode(extracted);
        }
        return parseJsonOrEmptyObject(bodyContent);
    }

    private static JsonNode parseJsonOrEmptyObject(String content) {
        if (content == null || content.trim().isEmpty()) {
            return JsonNodeFactory.instance.objectNode();
        }
        try {
            return objectMapper.readTree(content);
        } catch (Exception e) {
            return JsonNodeFactory.instance.objectNode();
        }
    }

    private static JsonNode parseJsonOrTextNode(String content) {
        if (content == null || content.trim().isEmpty()) {
            return JsonNodeFactory.instance.objectNode();
        }
        try {
            return objectMapper.readTree(content);
        } catch (Exception e) {
            return TextNode.valueOf(content);
        }
    }

    private static String queryToJson(ProcessorContext context) {
        return stableStringify(queryToNode(context));
    }

    private static String methodAwarePayloadJson(ProcessorContext context, String bodyContent) {
        String method = context != null ? context.getMethod() : null;
        JsonNode node = "GET".equalsIgnoreCase(method) ? queryToNode(context) : parseJsonOrEmptyObject(bodyContent);
        return stableStringify(node);
    }

    private static ObjectNode queryToNode(ProcessorContext context) {
        ObjectNode root = JsonNodeFactory.instance.objectNode();
        if (context == null || context.getUrl() == null || context.getUrl().getQuery() == null
                || context.getUrl().getQuery().isEmpty()) {
            return root;
        }

        String query = context.getUrl().getQuery();
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int idx = pair.indexOf('=');
            String rawKey = idx >= 0 ? pair.substring(0, idx) : pair;
            String rawValue = idx >= 0 ? pair.substring(idx + 1) : "";
            String key = urlDecode(rawKey);
            String value = urlDecode(rawValue);
            JsonNode existing = root.get(key);
            if (existing == null) {
                root.put(key, value);
            } else if (existing.isArray()) {
                ((ArrayNode) existing).add(value);
            } else {
                ArrayNode values = JsonNodeFactory.instance.arrayNode();
                values.add(existing.asText());
                values.add(value);
                root.set(key, values);
            }
        }
        return root;
    }

    private static String urlDecode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private static JsonNode cleanForStableJson(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isObject()) {
            ObjectNode object = (ObjectNode) node;
            List<String> remove = new ArrayList<>();
            Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                JsonNode cleaned = cleanForStableJson(field.getValue());
                if (cleaned == null || (cleaned.isObject() && cleaned.size() == 0)) {
                    remove.add(field.getKey());
                } else {
                    object.set(field.getKey(), cleaned);
                }
            }
            object.remove(remove);
            return object.size() == 0 ? null : object;
        }
        if (node.isArray()) {
            ArrayNode output = JsonNodeFactory.instance.arrayNode();
            for (JsonNode child : node) {
                JsonNode cleaned = cleanForStableJson(child);
                if (cleaned != null && !(cleaned.isObject() && cleaned.size() == 0)) {
                    output.add(cleaned);
                }
            }
            return output;
        }
        if (node.isNumber() && !Double.isFinite(node.asDouble())) {
            return null;
        }
        return node;
    }

    private static JsonNode stringifyScalarValues(JsonNode node) {
        if (node == null || node.isNull()) {
            return node;
        }
        if (node.isObject()) {
            ObjectNode object = JsonNodeFactory.instance.objectNode();
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                object.set(field.getKey(), stringifyScalarValues(field.getValue()));
            }
            return object;
        }
        if (node.isArray()) {
            ArrayNode array = JsonNodeFactory.instance.arrayNode();
            for (JsonNode child : node) {
                array.add(stringifyScalarValues(child));
            }
            return array;
        }
        if (node.isBoolean()) {
            return TextNode.valueOf(Boolean.toString(node.asBoolean()));
        }
        if (node.isNumber()) {
            return TextNode.valueOf(numberToJavaScriptString(node));
        }
        return node;
    }

    private static String numberToJavaScriptString(JsonNode node) {
        try {
            BigDecimal decimal = node.decimalValue().stripTrailingZeros();
            if (decimal.scale() < 0) {
                decimal = decimal.setScale(0);
            }
            return decimal.toPlainString().toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            return node.asText().toUpperCase(Locale.ROOT);
        }
    }

    private static String stableStringify(JsonNode node) {
        if (node == null || node.isNull()) {
            return "null";
        }
        if (node.isObject()) {
            List<String> keys = new ArrayList<>();
            node.fieldNames().forEachRemaining(keys::add);
            Collections.sort(keys);
            StringBuilder sb = new StringBuilder("{");
            for (String key : keys) {
                if (sb.length() > 1) {
                    sb.append(',');
                }
                sb.append(quoteJson(key)).append(':').append(stableStringify(node.get(key)));
            }
            return sb.append('}').toString();
        }
        if (node.isArray()) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < node.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(stableStringify(node.get(i)));
            }
            return sb.append(']').toString();
        }
        if (node.isTextual()) {
            return quoteJson(node.asText());
        }
        if (node.isNumber()) {
            return numberToJavaScriptString(node);
        }
        if (node.isBoolean()) {
            return Boolean.toString(node.asBoolean());
        }
        try {
            return objectMapper.writeValueAsString(node);
        } catch (Exception e) {
            return "null";
        }
    }

    private static String quoteJson(String value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }
    }

    private static String generateLegacyParamString(String content) {
        // Legacy support wrapper or alias
        return processCanonicalize("json::recursive", content); // Not fully compatible, but keeping placeholder if needed or remove
    }

    private static String extractJson(String json, String path) {
        if (json == null || json.isEmpty()) return "";
        try {
            JsonNode root = objectMapper.readTree(json);
            String[] parts = path.split("\\.");
            JsonNode current = root;
            for (String part : parts) {
                if (current.isObject()) {
                    current = current.get(part);
                } else if (current.isArray()) {
                    try {
                        int idx = Integer.parseInt(part);
                        current = current.get(idx);
                    } catch (NumberFormatException e) {
                        return "";
                    }
                }
                if (current == null) return "";
            }
            if (current.isValueNode()) {
                return current.asText();
            }
            return current.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String generateRandomString(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return Hex.encodeHexString(bytes).substring(0, length); // Simple hex string
    }
}
