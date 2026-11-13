package com.universal.crypto.processor;

import com.universal.crypto.model.Constants.ActionType;
import com.universal.crypto.model.ProcessingAction;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manager for processor instances and routing processing requests
 */
public class ProcessorManager {

    private final Map<String, ProcessorInterface> processors;
    private final Map<String, List<String>> actionTypeMapping;

    public ProcessorManager() {
        this.processors = new ConcurrentHashMap<>();
        this.actionTypeMapping = new ConcurrentHashMap<>();
    }

    /**
     * Register a processor
     *
     * @param processor the processor to register
     */
    public void registerProcessor(ProcessorInterface processor) {
        if (processor == null) {
            throw new IllegalArgumentException("Processor cannot be null");
        }

        String processorType = processor.getProcessorType();
        if (processorType == null || processorType.trim().isEmpty()) {
            throw new IllegalArgumentException("Processor type cannot be null or empty");
        }

        processors.put(processorType, processor);
        updateActionTypeMapping();
    }

    /**
     * Unregister a processor
     *
     * @param processorType the processor type to unregister
     * @return true if processor was found and removed
     */
    public boolean unregisterProcessor(String processorType) {
        if (processorType == null) {
            return false;
        }

        ProcessorInterface removed = processors.remove(processorType);
        if (removed != null) {
            updateActionTypeMapping();
            return true;
        }
        return false;
    }

    /**
     * Get a processor by type
     *
     * @param processorType the processor type
     * @return the processor or null if not found
     */
    public ProcessorInterface getProcessor(String processorType) {
        return processors.get(processorType);
    }

    /**
     * Find a processor that can handle the given action type
     *
     * @param actionType the action type to handle
     * @return the processor or null if none can handle it
     */
    public ProcessorInterface findProcessorForAction(String actionType) {
        if (actionType == null) {
            return null;
        }

        for (ProcessorInterface processor : processors.values()) {
            if (processor.canHandle(actionType)) {
                return processor;
            }
        }

        return null;
    }

    /**
     * Process content using the appropriate processor
     *
     * @param action the processing action
     * @param content the content to process
     * @param context the processing context
     * @return processing result
     * @throws ProcessorException if processing fails
     */
    public ProcessorResult process(ProcessingAction action, String content, ProcessorContext context)
            throws ProcessorException {

        if (action == null) {
            throw new ProcessorException("Processing action cannot be null");
        }

        ProcessorInterface processor = getProcessor(action.getProcessor());
        if (processor == null) {
            processor = findProcessorForAction(action.getActionType());
        }

        if (processor == null) {
            throw new ProcessorException("No processor found for action: " + action.getActionType());
        }

        if (!processor.canHandle(action.getActionType())) {
            throw new ProcessorException("Processor " + processor.getProcessorType() +
                    " cannot handle action type: " + action.getActionType());
        }

        if (!processor.isAvailable()) {
            throw new ProcessorException("Processor " + processor.getProcessorType() + " is not available");
        }

        return processor.process(action, content, context);
    }

    /**
     * Get all registered processors
     *
     * @return map of processor type to processor instance
     */
    public Map<String, ProcessorInterface> getAllProcessors() {
        return new HashMap<>(processors);
    }

    /**
     * Get all supported action types
     *
     * @return list of supported action types
     */
    public List<String> getSupportedActionTypes() {
        return new ArrayList<>(actionTypeMapping.keySet());
    }

    /**
     * Get processors that support a specific action type
     *
     * @param actionType the action type
     * @return list of processor types that support the action
     */
    public List<String> getProcessorsForActionType(String actionType) {
        return actionTypeMapping.getOrDefault(actionType, new ArrayList<>());
    }

    /**
     * Check if an action type is supported
     *
     * @param actionType the action type to check
     * @return true if supported
     */
    public boolean isActionTypeSupported(String actionType) {
        return actionTypeMapping.containsKey(actionType);
    }

    /**
     * Get the number of registered processors
     *
     * @return processor count
     */
    public int getProcessorCount() {
        return processors.size();
    }

    /**
     * Get all available processor types
     *
     * @return set of processor type names
     */
    public java.util.Set<String> getAvailableProcessors() {
        return processors.keySet();
    }

    /**
     * Check if any processors are registered
     *
     * @return true if at least one processor is registered
     */
    public boolean hasProcessors() {
        return !processors.isEmpty();
    }

    /**
     * Validate if a processing action can be handled
     *
     * @param action the action to validate
     * @return true if action can be processed
     */
    public boolean canProcess(ProcessingAction action) {
        if (action == null) {
            return false;
        }

        ProcessorInterface processor = getProcessor(action.getProcessor());
        if (processor == null) {
            processor = findProcessorForAction(action.getActionType());
        }

        if (processor == null) {
            return false;
        }

        return processor.canHandle(action.getActionType()) &&
               processor.isAvailable() &&
               processor.validateConfiguration(action);
    }

    /**
     * Get configuration requirements for an action
     *
     * @param actionType the action type
     * @param processorType the processor type (optional)
     * @return map of required parameters or null if not found
     */
    public Map<String, String> getConfigurationRequirements(String actionType, String processorType) {
        ProcessorInterface processor = null;

        if (processorType != null) {
            processor = getProcessor(processorType);
        } else {
            processor = findProcessorForAction(actionType);
        }

        if (processor != null && processor.canHandle(actionType)) {
            return processor.getRequiredParameters();
        }

        return null;
    }

    /**
     * Clear all registered processors
     */
    public void clearProcessors() {
        processors.clear();
        actionTypeMapping.clear();
    }

    private void updateActionTypeMapping() {
        actionTypeMapping.clear();

        for (ProcessorInterface processor : processors.values()) {
            for (String actionType : getSupportedActionTypes(processor)) {
                actionTypeMapping.computeIfAbsent(actionType, k -> new ArrayList<>())
                        .add(processor.getProcessorType());
            }
        }
    }

    private List<String> getSupportedActionTypes(ProcessorInterface processor) {
        List<String> supportedTypes = new ArrayList<>();

        String[] allActionTypes = {
                ActionType.ENCRYPT, ActionType.DECRYPT, ActionType.SIGN, ActionType.VERIFY,
                ActionType.REPLACE, ActionType.ADD, ActionType.REMOVE
        };

        for (String actionType : allActionTypes) {
            if (processor.canHandle(actionType)) {
                supportedTypes.add(actionType);
            }
        }

        return supportedTypes;
    }

    @Override
    public String toString() {
        return "ProcessorManager{" +
                "processorCount=" + processors.size() +
                ", supportedActionTypes=" + getSupportedActionTypes().size() +
                ", processors=" + processors.keySet() +
                '}';
    }
}