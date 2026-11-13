package com.universal.crypto.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Processing action model class that defines what operation should be performed
 * on the HTTP request or response content.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ProcessingAction {

    @JsonProperty("actionType")
    private String actionType;

    @JsonProperty("targetType")
    private String targetType;

    @JsonProperty("targetName")
    private String targetName;

    @JsonProperty("processor")
    private String processor;

    @JsonProperty("config")
    private Map<String, Object> config;

    @JsonProperty("enabled")
    private boolean enabled;

    @JsonProperty("description")
    private String description;

    /**
     * Default constructor for JSON deserialization
     */
    public ProcessingAction() {
        this.enabled = true;
        this.config = new HashMap<>();
    }

    /**
     * Constructor with basic action properties
     *
     * @param actionType type of action (decrypt, encrypt, sign, etc.)
     * @param targetType target type (body, header, field, etc.)
     * @param processor processor type (crypto, signature, field)
     */
    public ProcessingAction(String actionType, String targetType, String processor) {
        this();
        this.actionType = actionType;
        this.targetType = targetType;
        this.processor = processor;
    }

    /**
     * Constructor with target name
     *
     * @param actionType type of action
     * @param targetType target type
     * @param targetName target name (e.g., header name, field path)
     * @param processor processor type
     */
    public ProcessingAction(String actionType, String targetType, String targetName, String processor) {
        this(actionType, targetType, processor);
        this.targetName = targetName;
    }

    // Getters and Setters

    public String getActionType() {
        return actionType;
    }

    public void setActionType(String actionType) {
        this.actionType = actionType;
    }

    public String getTargetType() {
        return targetType;
    }

    public void setTargetType(String targetType) {
        this.targetType = targetType;
    }

    public String getTargetName() {
        return targetName;
    }

    public void setTargetName(String targetName) {
        this.targetName = targetName;
    }

    public String getProcessor() {
        return processor;
    }

    public void setProcessor(String processor) {
        this.processor = processor;
    }

    public Map<String, Object> getConfig() {
        return config;
    }

    public void setConfig(Map<String, Object> config) {
        this.config = copyConfig(config);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    // Convenience methods for config management

    /**
     * Set a configuration parameter
     *
     * @param key configuration key
     * @param value configuration value
     */
    public void setConfig(String key, Object value) {
        if (this.config == null) {
            this.config = new HashMap<>();
        }
        this.config.put(key, copyValue(value));
    }

    /**
     * Get a configuration parameter
     *
     * @param key configuration key
     * @return configuration value or null if not found
     */
    public Object getConfig(String key) {
        return this.config != null ? this.config.get(key) : null;
    }

    /**
     * Get a configuration parameter with default value
     *
     * @param key configuration key
     * @param defaultValue default value if key not found
     * @param <T> type of the value
     * @return configuration value or default value
     */
    @SuppressWarnings("unchecked")
    public <T> T getConfig(String key, T defaultValue) {
        if (this.config == null || !this.config.containsKey(key)) {
            return defaultValue;
        }

        Object value = this.config.get(key);
        if (value == null) {
            return defaultValue;
        }

        // If no default is provided, fall back to an unchecked cast (may fail at call site).
        if (defaultValue == null) {
            return (T) value;
        }

        if (defaultValue.getClass().isInstance(value)) {
            return (T) value;
        }

        // Allow safe numeric widening/narrowing between Number types.
        if (defaultValue instanceof Integer && value instanceof Number) {
            return (T) Integer.valueOf(((Number) value).intValue());
        }
        if (defaultValue instanceof Long && value instanceof Number) {
            return (T) Long.valueOf(((Number) value).longValue());
        }
        if (defaultValue instanceof Double && value instanceof Number) {
            return (T) Double.valueOf(((Number) value).doubleValue());
        }
        if (defaultValue instanceof Float && value instanceof Number) {
            return (T) Float.valueOf(((Number) value).floatValue());
        }

        return defaultValue;
    }

    /**
     * Get a string configuration parameter
     *
     * @param key configuration key
     * @return string value or null
     */
    public String getConfigString(String key) {
        Object value = getConfig(key);
        return value != null ? value.toString() : null;
    }

    /**
     * Get a string configuration parameter with default
     *
     * @param key configuration key
     * @param defaultValue default value
     * @return string value or default
     */
    public String getConfigString(String key, String defaultValue) {
        String value = getConfigString(key);
        return value != null ? value : defaultValue;
    }

    /**
     * Check if a configuration key exists
     *
     * @param key configuration key
     * @return true if key exists
     */
    public boolean hasConfig(String key) {
        return this.config != null && this.config.containsKey(key);
    }

    /**
     * Remove a configuration parameter
     *
     * @param key configuration key to remove
     * @return previous value or null
     */
    public Object removeConfig(String key) {
        return this.config != null ? this.config.remove(key) : null;
    }

    /**
     * Check if this action is valid
     *
     * @return true if action has required fields
     */
    public boolean isValid() {
        return actionType != null && !actionType.trim().isEmpty() &&
               targetType != null && !targetType.trim().isEmpty() &&
               processor != null && !processor.trim().isEmpty();
    }

    /**
     * Create a copy of this action
     *
     * @return cloned action
     */
    public ProcessingAction clone() {
        ProcessingAction cloned = new ProcessingAction();
        cloned.actionType = this.actionType;
        cloned.targetType = this.targetType;
        cloned.targetName = this.targetName;
        cloned.processor = this.processor;
        cloned.enabled = this.enabled;
        cloned.description = this.description;

        if (this.config != null) {
            cloned.config = copyConfig(this.config);
        }

        return cloned;
    }

    private static Map<String,Object> copyConfig(Map<String,Object> values) {
        var copy = new HashMap<String,Object>();
        if (values != null) values.forEach((key,value) -> copy.put(key, copyValue(value)));
        return copy;
    }

    /** Own nested JSON configuration too; cancelled editors must not mutate stored rules. */
    private static Object copyValue(Object value) {
        if (value instanceof Map<?,?> map) {
            var copy = new java.util.LinkedHashMap<Object,Object>();
            map.forEach((key,item) -> copy.put(key, copyValue(item)));
            return copy;
        }
        if (value instanceof java.util.List<?> list) {
            var copy = new java.util.ArrayList<Object>();
            list.forEach(item -> copy.add(copyValue(item)));
            return copy;
        }
        if (value != null && value.getClass().isArray()) {
            int size = java.lang.reflect.Array.getLength(value);
            Object copy = java.lang.reflect.Array.newInstance(value.getClass().getComponentType(), size);
            for (int i = 0; i < size; i++) java.lang.reflect.Array.set(copy,i,copyValue(java.lang.reflect.Array.get(value,i)));
            return copy;
        }
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProcessingAction that = (ProcessingAction) o;
        return enabled == that.enabled &&
               Objects.equals(actionType, that.actionType) &&
               Objects.equals(targetType, that.targetType) &&
               Objects.equals(targetName, that.targetName) &&
               Objects.equals(processor, that.processor) &&
               Objects.equals(config, that.config);
    }

    @Override
    public int hashCode() {
        return Objects.hash(actionType, targetType, targetName, processor, config, enabled);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("ProcessingAction{");
        sb.append("actionType='").append(actionType).append('\'');
        sb.append(", targetType='").append(targetType).append('\'');
        if (targetName != null) {
            sb.append(", targetName='").append(targetName).append('\'');
        }
        sb.append(", processor='").append(processor).append('\'');
        sb.append(", enabled=").append(enabled);
        if (config != null && !config.isEmpty()) {
            sb.append(", config=").append(config);
        }
        sb.append('}');
        return sb.toString();
    }
}
