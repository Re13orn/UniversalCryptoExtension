package com.universal.crypto.processor;

import com.universal.crypto.model.ProcessingAction;
import java.util.Map;

/**
 * Base interface for all processors that handle specific types of processing actions
 */
public interface ProcessorInterface {

    /**
     * Process the given content according to the action configuration
     *
     * @param action the processing action with configuration
     * @param content the content to process
     * @param context additional context information
     * @return processing result
     * @throws ProcessorException if processing fails
     */
    ProcessorResult process(ProcessingAction action, String content, ProcessorContext context)
            throws ProcessorException;

    /**
     * Check if this processor can handle the given action type
     *
     * @param actionType the action type to check
     * @return true if this processor can handle the action
     */
    boolean canHandle(String actionType);

    /**
     * Get the processor type identifier
     *
     * @return processor type string
     */
    String getProcessorType();

    /**
     * Validate the action configuration before processing
     *
     * @param action the action to validate
     * @return true if configuration is valid
     */
    boolean validateConfiguration(ProcessingAction action);

    /**
     * Get required configuration parameters for this processor
     *
     * @return map of required parameter names and their descriptions
     */
    Map<String, String> getRequiredParameters();

    /**
     * Check if processor is available and properly configured
     *
     * @return true if processor is ready to use
     */
    boolean isAvailable();
}