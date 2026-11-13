package com.universal.crypto.processor;

import com.universal.crypto.model.ProcessingAction;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Abstract base class for processors providing common functionality
 */
public abstract class AbstractProcessor implements ProcessorInterface {

    protected final String processorType;
    protected final Set<String> supportedActions;

    protected AbstractProcessor(String processorType, Set<String> supportedActions) {
        this.processorType = processorType;
        this.supportedActions = supportedActions;
    }

    @Override
    public String getProcessorType() {
        return processorType;
    }

    @Override
    public boolean canHandle(String actionType) {
        return actionType != null && supportedActions.contains(actionType);
    }

    @Override
    public boolean validateConfiguration(ProcessingAction action) {
        if (action == null) {
            return false;
        }

        if (!canHandle(action.getActionType())) {
            return false;
        }

        Map<String, String> required = getRequiredParameters();
        if (required != null && !required.isEmpty()) {
            for (String param : required.keySet()) {
                if (!action.hasConfig(param)) {
                    return false;
                }
                Object value = action.getConfig(param);
                if (value == null || (value instanceof String && ((String) value).trim().isEmpty())) {
                    return false;
                }
            }
        }

        return validateSpecificConfiguration(action);
    }

    @Override
    public ProcessorResult process(ProcessingAction action, String content, ProcessorContext context)
            throws ProcessorException {

        if (!validateConfiguration(action)) {
            throw new ProcessorException("Invalid configuration for action: " + action.getActionType(),
                    processorType, action.getActionType());
        }

        if (!isAvailable()) {
            throw new ProcessorException("Processor is not available: " + processorType,
                    processorType, action.getActionType());
        }

        long startTime = System.currentTimeMillis();

        try {
            ProcessorResult result = processInternal(action, content, context);
            long endTime = System.currentTimeMillis();

            return new ProcessorResult.Builder()
                    .success(result.isSuccess())
                    .processedContent(result.getProcessedContent())
                    .processedBytes(result.getProcessedBytes())
                    .errorMessage(result.getErrorMessage())
                    .metadata(result.getMetadata())
                    .processingTimeMs(endTime - startTime)
                    .build();

        } catch (Exception e) {
            long endTime = System.currentTimeMillis();
            throw new ProcessorException("Processing failed: " + e.getMessage(), e,
                    processorType, action.getActionType());
        }
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public Map<String, String> getRequiredParameters() {
        return new HashMap<>();
    }

    /**
     * Validate processor-specific configuration
     *
     * @param action the action to validate
     * @return true if configuration is valid
     */
    protected boolean validateSpecificConfiguration(ProcessingAction action) {
        return true;
    }

    /**
     * Perform the actual processing logic
     *
     * @param action the processing action
     * @param content the content to process
     * @param context the processing context
     * @return processing result
     * @throws Exception if processing fails
     */
    protected abstract ProcessorResult processInternal(ProcessingAction action, String content,
                                                     ProcessorContext context) throws Exception;

    /**
     * Get a configuration parameter value as string
     */
    protected String getConfigString(ProcessingAction action, String key) {
        Object value = action.getConfig(key);
        return value != null ? value.toString() : null;
    }

    /**
     * Get a configuration parameter value as string with default
     */
    protected String getConfigString(ProcessingAction action, String key, String defaultValue) {
        String value = getConfigString(action, key);
        return value != null ? value : defaultValue;
    }

    /**
     * Get a configuration parameter value as boolean
     */
    protected boolean getConfigBoolean(ProcessingAction action, String key) {
        return getConfigBoolean(action, key, false);
    }

    /**
     * Get a configuration parameter value as boolean with default
     */
    protected boolean getConfigBoolean(ProcessingAction action, String key, boolean defaultValue) {
        Object value = action.getConfig(key);
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value instanceof String) {
            return Boolean.parseBoolean((String) value);
        }
        return defaultValue;
    }

    /**
     * Get a configuration parameter value as integer
     */
    protected int getConfigInt(ProcessingAction action, String key, int defaultValue) {
        Object value = action.getConfig(key);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    /**
     * Get a configuration parameter value as a string map.
     * Accepts {@code Map<?,?>} values and coerces keys/values via {@code toString()}.
     */
    protected Map<String, String> getConfigStringMap(ProcessingAction action, String key) {
        Object value = action.getConfig(key);
        if (!(value instanceof Map<?, ?> rawMap)) {
            return Map.of();
        }

        Map<String, String> result = new HashMap<>();
        for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
            if (entry.getKey() == null) {
                continue;
            }
            String mapKey = entry.getKey().toString();
            if (mapKey.trim().isEmpty()) {
                continue;
            }
            String mapValue = entry.getValue() != null ? entry.getValue().toString() : "";
            result.put(mapKey, mapValue);
        }
        return result;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "processorType='" + processorType + '\'' +
                ", supportedActions=" + supportedActions +
                ", available=" + isAvailable() +
                '}';
    }
}
