package com.universal.crypto.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.universal.crypto.util.Logger;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for serializing and deserializing processing rules to/from JSON
 */
public class RuleSerializer {

    private static volatile ObjectMapper objectMapper;

    /**
     * Get ObjectMapper instance with thread-safe lazy initialization
     */
    public static ObjectMapper getObjectMapper() {
        if (objectMapper == null) {
            synchronized (RuleSerializer.class) {
                if (objectMapper == null) {
                    objectMapper = createObjectMapper();
                }
            }
        }
        return objectMapper;
    }

    /**
     * Create and configure ObjectMapper instance
     */
    private static ObjectMapper createObjectMapper() {
        try {
            ObjectMapper mapper = new ObjectMapper();

        // Configure for pretty printing
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        // Don't fail on unknown properties
        mapper.configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

            // Handle empty beans
            mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

            return mapper;
        } catch (Exception e) {
            Logger.getInstance().error("Failed to create ObjectMapper: " + e.getMessage(), e);
            throw new RuntimeException("Jackson ObjectMapper initialization failed. Ensure Jackson dependencies are available.", e);
        }
    }

    /**
     * Convert a processing rule to JSON string
     *
     * @param rule the processing rule to serialize
     * @return JSON string representation
     * @throws RuntimeException if serialization fails
     */
    public static String toJson(ProcessingRule rule) {
        if (rule == null) {
            return "null";
        }

        try {
            return getObjectMapper().writeValueAsString(rule);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize ProcessingRule to JSON", e);
        }
    }

    /**
     * Convert a list of processing rules to JSON string
     *
     * @param rules the list of processing rules to serialize
     * @return JSON string representation
     * @throws RuntimeException if serialization fails
     */
    public static String toJson(List<ProcessingRule> rules) {
        if (rules == null) {
            return "null";
        }

        try {
            return getObjectMapper().writeValueAsString(rules);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize ProcessingRule list to JSON", e);
        }
    }

    /**
     * Convert JSON string to processing rule
     *
     * @param json JSON string
     * @return ProcessingRule object
     * @throws RuntimeException if deserialization fails
     */
    public static ProcessingRule fromJson(String json) {
        if (json == null || json.trim().isEmpty() || "null".equals(json.trim())) {
            return null;
        }

        try {
            return getObjectMapper().readValue(json, ProcessingRule.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to deserialize ProcessingRule from JSON: " + json, e);
        }
    }

    /**
     * Convert JSON string to list of processing rules
     *
     * @param json JSON string
     * @return List of ProcessingRule objects
     * @throws RuntimeException if deserialization fails
     */
    public static List<ProcessingRule> fromJsonList(String json) {
        if (json == null || "null".equals(json.trim())) {
            return null;
        }

        // Empty string represents empty list
        if (json.trim().isEmpty()) {
            return new ArrayList<>();
        }

        try {
            return getObjectMapper().readValue(json, new TypeReference<List<ProcessingRule>>() {});
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to deserialize ProcessingRule list from JSON: " + json, e);
        }
    }

    public static final int SCHEMA_VERSION = 1;
    public static final String ENGINE_BUILD = "rhino-1.8.1-sandbox-v1";

    public static String exportRules(List<ProcessingRule> rules) {
        try { return getObjectMapper().writeValueAsString(java.util.Map.of("schemaVersion", SCHEMA_VERSION, "engineBuild", ENGINE_BUILD, "rules", rules)); }
        catch (JsonProcessingException e) { throw new IllegalArgumentException("Rule export failed", e); }
    }

    /** Legacy arrays remain readable; imported rules are validated and disabled. */
    public static List<ProcessingRule> importRules(String json) {
        try {
            com.fasterxml.jackson.databind.JsonNode node = getObjectMapper().readTree(json);
            if (node.isObject()) {
                if (node.path("schemaVersion").asInt(-1) != SCHEMA_VERSION || !ENGINE_BUILD.equals(node.path("engineBuild").asText()))
                    throw new IllegalArgumentException("规则格式或脚本引擎版本不匹配，请核对 schemaVersion / engineBuild");
                node = node.get("rules");
            }
            if (node == null || !node.isArray()) throw new IllegalArgumentException("Expected rules array");
            List<ProcessingRule> rules = fromJsonList(node.toString());
            java.util.Set<String> ids = new java.util.HashSet<>();
            for (ProcessingRule rule : rules) {
                if (rule == null || rule.getId() == null || rule.getId().isBlank() || !ids.add(rule.getId())) throw new IllegalArgumentException("Missing or duplicate rule ID");
                List<ProcessingAction> actions = new ArrayList<>();
                if (rule.getRequestActions() != null) actions.addAll(rule.getRequestActions());
                if (rule.getResponseActions() != null) actions.addAll(rule.getResponseActions());
                for (ProcessingAction action : actions) {
                    if (action == null || !java.util.Set.of("crypto", "signature", "field", "script").contains(action.getProcessor() == null ? "" : action.getProcessor())) throw new IllegalArgumentException("Unknown processor");
                    if (!java.util.Set.of("body", "header", "field", "variable").contains(action.getTargetType() == null ? "" : action.getTargetType())) throw new IllegalArgumentException("Unknown targetType");
                    String phase = action.getConfigString(Constants.ConfigKey.EXECUTION_PHASE);
                    if (phase != null) for (String token : phase.split(",", -1))
                        if (!Constants.ExecutionPhase.VALUES.contains(token.trim())) throw new IllegalArgumentException("Unknown executionPhase: " + token);
                    if ("script".equals(action.getProcessor())) {
                        if (!new com.universal.crypto.processor.impl.ScriptProcessor().canHandle(action.getActionType())) throw new IllegalArgumentException("Unknown script action");
                        String code = action.getConfigString(Constants.ConfigKey.SCRIPT_CODE);
                        if (code == null || code.isBlank()) throw new IllegalArgumentException("Missing scriptCode");
                        com.universal.crypto.processor.impl.ScriptProcessor.validateScript(code);
                    }
                }
                rule.setEnabled(false);
            }
            return rules;
        } catch (IOException e) { throw new IllegalArgumentException("Invalid rule file", e); }
    }

    /**
     * Check if a JSON string is valid
     *
     * @param json JSON string to validate
     * @return true if JSON is valid
     */
    public static boolean isValidJson(String json) {
        if (json == null || json.trim().isEmpty()) {
            return false;
        }

        try {
            getObjectMapper().readTree(json);
            return true;
        } catch (JsonProcessingException e) {
            return false;
        }
    }

    /**
     * Validate if JSON represents a valid ProcessingRule
     *
     * @param json JSON string
     * @return true if JSON can be deserialized to ProcessingRule
     */
    public static boolean isValidRuleJson(String json) {
        try {
            ProcessingRule rule = fromJson(json);
            return rule != null && rule.getId() != null && !rule.getId().trim().isEmpty();
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Validate if JSON represents a valid list of ProcessingRules
     *
     * @param json JSON string
     * @return true if JSON can be deserialized to List<ProcessingRule>
     */
    public static boolean isValidRuleListJson(String json) {
        if (json == null) {
            return false;
        }
        // Empty string is considered valid (represents empty rule list)
        if (json.trim().isEmpty()) {
            return true;
        }
        try {
            List<ProcessingRule> rules = fromJsonList(json);
            return rules != null;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Pretty print JSON string
     *
     * @param json input JSON string
     * @return formatted JSON string
     * @throws RuntimeException if formatting fails
     */
    public static String prettyPrint(String json) {
        try {
            Object obj = getObjectMapper().readValue(json, Object.class);
            return getObjectMapper().writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to pretty print JSON", e);
        }
    }

}
