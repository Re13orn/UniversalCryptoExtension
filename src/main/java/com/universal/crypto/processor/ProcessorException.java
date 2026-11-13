package com.universal.crypto.processor;

/**
 * Exception thrown by processors when processing fails
 */
public class ProcessorException extends Exception {

    private final String processorType;
    private final String actionType;

    public ProcessorException(String message) {
        super(message);
        this.processorType = null;
        this.actionType = null;
    }

    public ProcessorException(String message, Throwable cause) {
        super(message, cause);
        this.processorType = null;
        this.actionType = null;
    }

    public ProcessorException(String message, String processorType, String actionType) {
        super(message);
        this.processorType = processorType;
        this.actionType = actionType;
    }

    public ProcessorException(String message, Throwable cause, String processorType, String actionType) {
        super(message, cause);
        this.processorType = processorType;
        this.actionType = actionType;
    }

    public String getProcessorType() {
        return processorType;
    }

    public String getActionType() {
        return actionType;
    }

    @Override
    public String getMessage() {
        StringBuilder sb = new StringBuilder();
        if (processorType != null) {
            sb.append("[").append(processorType).append("]");
        }
        if (actionType != null) {
            sb.append("[").append(actionType).append("]");
        }
        if (sb.length() > 0) {
            sb.append(" ");
        }
        sb.append(super.getMessage());
        return sb.toString();
    }
}