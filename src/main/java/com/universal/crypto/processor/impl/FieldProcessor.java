package com.universal.crypto.processor.impl;

import com.universal.crypto.model.Constants.ActionType;
import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.AbstractProcessor;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.processor.ProcessorException;
import com.universal.crypto.util.TemplateEngine;
import com.universal.crypto.processor.ProcessorResult;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Field processor for handling JSON field operations like replace, add, remove
 */
public class FieldProcessor extends AbstractProcessor {

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final Pattern JSON_PATH_PATTERN = Pattern.compile("\\$\\.([a-zA-Z0-9_\\-]+(?:\\[[0-9]+\\])?(?:\\.[a-zA-Z0-9_\\-]+(?:\\[[0-9]+\\])?)*)");

    public FieldProcessor() {
        super("field", Set.of(ActionType.REPLACE, ActionType.ADD, ActionType.REMOVE));
    }

    @Override
    public Map<String, String> getRequiredParameters() {
        Map<String, String> params = new HashMap<>();
        params.put(ConfigKey.OPERATION, "Field operation to perform (replace, add, remove)");
        params.put(ConfigKey.FIELD_PATH, "JSON path to the field (e.g., $.userId, $.data.name)");
        return params;
    }

    @Override
    protected boolean validateSpecificConfiguration(ProcessingAction action) {
        String operation = getConfigString(action, ConfigKey.OPERATION);
        if (operation == null || operation.trim().isEmpty()) {
            return false;
        }

        String fieldPath = getConfigString(action, ConfigKey.FIELD_PATH);
        if (fieldPath == null || fieldPath.trim().isEmpty()) {
            return false;
        }

        if (!isValidJsonPath(fieldPath)) {
            return false;
        }

        if (ActionType.REPLACE.equals(operation) || ActionType.ADD.equals(operation)) {
            return action.hasConfig(ConfigKey.TO);
        }

        return true;
    }

    @Override
    protected ProcessorResult processInternal(ProcessingAction action, String content,
                                            ProcessorContext context) throws Exception {

        if (content == null || content.trim().isEmpty()) {
            return ProcessorResult.failure("Content is empty").build();
        }

        String operation = getConfigString(action, ConfigKey.OPERATION);
        String fieldPath = getConfigString(action, ConfigKey.FIELD_PATH);

        try {
            JsonNode rootNode = objectMapper.readTree(content);

            switch (operation.toLowerCase()) {
                case ActionType.REPLACE:
                    return performReplace(rootNode, fieldPath, action, context);
                case ActionType.ADD:
                    return performAdd(rootNode, fieldPath, action, context);
                case ActionType.REMOVE:
                    return performRemove(rootNode, fieldPath, action);
                default:
                    return ProcessorResult.failure("Unsupported operation: " + operation).build();
            }

        } catch (Exception e) {
            return ProcessorResult.failure("JSON processing failed: " + e.getMessage())
                    .addMetadata("operation", operation)
                    .addMetadata("fieldPath", fieldPath)
                    .build();
        }
    }

    private ProcessorResult performReplace(JsonNode rootNode, String fieldPath, ProcessingAction action, ProcessorContext context)
            throws Exception {

        String fromValue = getConfigString(action, ConfigKey.FROM);
        String toValue = getConfigString(action, ConfigKey.TO);
        
        // Resolve variables in toValue
        if (toValue != null && toValue.contains("${")) {
            toValue = TemplateEngine.process(toValue, context, rootNode.toString());
        }

        JsonNode targetNode = findNode(rootNode, fieldPath);
        if (targetNode == null) {
            return ProcessorResult.failure("Field not found: " + fieldPath).build();
        }

        if (fromValue != null && !"auto".equals(fromValue)) {
            String currentValue = targetNode.asText();
            if (!fromValue.equals(currentValue)) {
                return ProcessorResult.failure("Current value doesn't match expected 'from' value")
                        .addMetadata("currentValue", currentValue)
                        .addMetadata("expectedValue", fromValue)
                        .build();
            }
        }

        JsonNode parentNode = findContainerNode(rootNode, fieldPath);
        Object targetKey = extractTargetKey(fieldPath);

        if (parentNode != null && targetKey != null) {
            if (parentNode.isArray() && targetKey instanceof Integer) {
                ((com.fasterxml.jackson.databind.node.ArrayNode) parentNode).set((Integer) targetKey, com.fasterxml.jackson.databind.node.TextNode.valueOf(toValue));
            } else if (parentNode.isObject() && targetKey instanceof String) {
                ((ObjectNode) parentNode).put((String) targetKey, toValue);
            } else {
                 return ProcessorResult.failure("Type mismatch for field: " + fieldPath).build();
            }

            String processedContent = objectMapper.writeValueAsString(rootNode);
            return ProcessorResult.success(processedContent)
                    .addMetadata("operation", ActionType.REPLACE)
                    .addMetadata("fieldPath", fieldPath)
                    .addMetadata("oldValue", targetNode.asText())
                    .addMetadata("newValue", toValue)
                    .build();
        } else {
            return ProcessorResult.failure("Unable to locate parent node for field: " + fieldPath).build();
        }
    }

    private ProcessorResult performAdd(JsonNode rootNode, String fieldPath, ProcessingAction action, ProcessorContext context)
            throws Exception {

        String toValue = getConfigString(action, ConfigKey.TO);
        
        // Resolve variables in toValue
        if (toValue != null && toValue.contains("${")) {
             toValue = TemplateEngine.process(toValue, context, rootNode.toString());
        }

        boolean overwrite = getConfigBoolean(action, ConfigKey.OVERWRITE, false);

        JsonNode existingNode = findNode(rootNode, fieldPath);
        if (existingNode != null && !overwrite) {
            return ProcessorResult.failure("Field already exists and overwrite is disabled: " + fieldPath)
                    .addMetadata("existingValue", existingNode.asText())
                    .build();
        }

        JsonNode parentNode = findContainerNode(rootNode, fieldPath);
        Object targetKey = extractTargetKey(fieldPath);

        if (parentNode != null && targetKey != null) {
            if (parentNode.isArray() && targetKey instanceof Integer) {
                 ((com.fasterxml.jackson.databind.node.ArrayNode) parentNode).set((Integer) targetKey, com.fasterxml.jackson.databind.node.TextNode.valueOf(toValue));
            } else if (parentNode.isObject() && targetKey instanceof String) {
                ((ObjectNode) parentNode).put((String) targetKey, toValue);
            }

            String processedContent = objectMapper.writeValueAsString(rootNode);
            return ProcessorResult.success(processedContent)
                    .addMetadata("operation", ActionType.ADD)
                    .addMetadata("fieldPath", fieldPath)
                    .addMetadata("newValue", toValue)
                    .addMetadata("overwritten", existingNode != null)
                    .build();
        } else {
            return ProcessorResult.failure("Unable to locate parent node for field: " + fieldPath).build();
        }
    }

    private ProcessorResult performRemove(JsonNode rootNode, String fieldPath, ProcessingAction action)
            throws Exception {

        JsonNode targetNode = findNode(rootNode, fieldPath);
        if (targetNode == null) {
            boolean ignoreNotFound = getConfigBoolean(action, ConfigKey.IGNORE_NOT_FOUND, false);
            if (ignoreNotFound) {
                String content = objectMapper.writeValueAsString(rootNode);
                return ProcessorResult.success(content)
                        .addMetadata("operation", ActionType.REMOVE)
                        .addMetadata("fieldPath", fieldPath)
                        .addMetadata("found", false)
                        .build();
            } else {
                return ProcessorResult.failure("Field not found: " + fieldPath).build();
            }
        }

        JsonNode parentNode = findContainerNode(rootNode, fieldPath);
        Object targetKey = extractTargetKey(fieldPath);

        if (parentNode != null && targetKey != null) {
            String oldValue = targetNode.asText();
            
            if (parentNode.isArray() && targetKey instanceof Integer) {
                 ((com.fasterxml.jackson.databind.node.ArrayNode) parentNode).remove((Integer) targetKey);
            } else if (parentNode.isObject() && targetKey instanceof String) {
                ((ObjectNode) parentNode).remove((String) targetKey);
            }

            String processedContent = objectMapper.writeValueAsString(rootNode);
            return ProcessorResult.success(processedContent)
                    .addMetadata("operation", ActionType.REMOVE)
                    .addMetadata("fieldPath", fieldPath)
                    .addMetadata("oldValue", oldValue)
                    .build();
        } else {
            return ProcessorResult.failure("Unable to locate parent node for field: " + fieldPath).build();
        }
    }

    private boolean isValidJsonPath(String path) {
        return path != null && path.startsWith("$.") && JSON_PATH_PATTERN.matcher(path).matches();
    }

    private JsonNode findNode(JsonNode rootNode, String path) {
        if (!path.startsWith("$.")) {
            return null;
        }

        String[] parts = path.substring(2).split("\\.");
        JsonNode current = rootNode;

        for (String part : parts) {
            if (current == null) {
                return null;
            }

            if (part.contains("[") && part.contains("]")) {
                String fieldName = part.substring(0, part.indexOf('['));
                String indexStr = part.substring(part.indexOf('[') + 1, part.indexOf(']'));
                int index = Integer.parseInt(indexStr);

                current = current.get(fieldName);
                if (current != null && current.isArray()) {
                    current = current.get(index);
                } else {
                    return null;
                }
            } else {
                current = current.get(part);
            }
        }

        return current;
    }

    private JsonNode findContainerNode(JsonNode rootNode, String path) {
        if (!path.startsWith("$.")) {
            return null;
        }

        String[] parts = path.substring(2).split("\\.");
        JsonNode current = rootNode;
        
        // Traverse up to the last part
        for (int i = 0; i < parts.length - 1; i++) {
            String part = parts[i];
            current = traverseStep(current, part);
            if (current == null) return null;
        }
        
        // Handle the last part
        String lastPart = parts[parts.length - 1];
        if (lastPart.contains("[")) {
            // Case: items[0] -> container is 'items' (Array)
            String fieldName = lastPart.substring(0, lastPart.indexOf('['));
            current = current.get(fieldName);
            if (current != null && current.isArray()) {
                return current;
            }
            return null;
        } else {
            // Case: field -> container is current (Object)
            return current.isObject() ? current : null;
        }
    }
    
    // Helper to reuse traversal
    private JsonNode traverseStep(JsonNode current, String part) {
         if (part.contains("[") && part.contains("]")) {
            String fieldName = part.substring(0, part.indexOf('['));
            String indexStr = part.substring(part.indexOf('[') + 1, part.indexOf(']'));
            int index = Integer.parseInt(indexStr);

            current = current.get(fieldName);
            if (current != null && current.isArray()) {
                return current.get(index);
            }
        } else {
            return current.get(part);
        }
        return null;
    }

    private Object extractTargetKey(String path) {
        if (!path.startsWith("$.")) {
            return null;
        }

        String[] parts = path.substring(2).split("\\.");
        String lastPart = parts[parts.length - 1];

        if (lastPart.contains("[")) {
            // Returns Integer index
            try {
                String indexStr = lastPart.substring(lastPart.indexOf('[') + 1, lastPart.indexOf(']'));
                return Integer.parseInt(indexStr);
            } catch (Exception e) {
                return null;
            }
        } else {
            // Returns String field name
            return lastPart;
        }
    }
}