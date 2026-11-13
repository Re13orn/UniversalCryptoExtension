package com.universal.crypto.processor;

import java.util.HashMap;
import java.util.Map;

/**
 * Result of a processor operation
 */
public class ProcessorResult {

    private final boolean success;
    private final String processedContent;
    private final byte[] processedBytes;
    private final String errorMessage;
    private final Map<String, Object> metadata;
    private final long processingTimeMs;

    private ProcessorResult(Builder builder) {
        this.success = builder.success;
        this.processedContent = builder.processedContent;
        this.processedBytes = builder.processedBytes == null ? null : builder.processedBytes.clone();
        this.errorMessage = builder.errorMessage;
        this.metadata = builder.metadata != null ? new HashMap<>(builder.metadata) : new HashMap<>();
        this.processingTimeMs = builder.processingTimeMs;
    }

    public boolean isNoChange() { return Boolean.TRUE.equals(metadata.get("noChange")) || "true".equals(metadata.get("noChange")); }

    public boolean isSuccess() {
        return success;
    }

    public String getProcessedContent() {
        return processedContent;
    }

    public byte[] getProcessedBytes() { return processedBytes == null ? null : processedBytes.clone(); }

    public String getErrorMessage() {
        return errorMessage;
    }

    public Map<String, Object> getMetadata() {
        return new HashMap<>(metadata);
    }

    public Object getMetadata(String key) {
        return metadata.get(key);
    }

    /** Additional header writes emitted by processors such as signature headerTemplates. */
    public Map<String,String> getGeneratedHeaders() {
        Object value = metadata.get("setHeaders");
        if (!(value instanceof Map<?,?> raw)) return Map.of();
        var headers = new java.util.TreeMap<String,String>(String.CASE_INSENSITIVE_ORDER);
        raw.forEach((key, item) -> { if (key != null) headers.put(key.toString(), item == null ? "" : item.toString()); });
        return java.util.Collections.unmodifiableMap(headers);
    }

    public long getProcessingTimeMs() {
        return processingTimeMs;
    }

    public boolean hasMetadata(String key) {
        return metadata.containsKey(key);
    }

    public static Builder success(String processedContent) {
        return new Builder().success(true).processedContent(processedContent);
    }

    public static Builder failure(String errorMessage) {
        return new Builder().success(false).errorMessage(errorMessage);
    }

    public static class Builder {
        private boolean success;
        private String processedContent;
        private byte[] processedBytes;
        private String errorMessage;
        private Map<String, Object> metadata;
        private long processingTimeMs;

        public Builder success(boolean success) {
            this.success = success;
            return this;
        }

        public Builder processedContent(String processedContent) {
            this.processedContent = processedContent;
            return this;
        }

        public Builder processedBytes(byte[] bytes) { this.processedBytes = bytes == null ? null : bytes.clone(); return this; }

        public Builder errorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        public Builder addMetadata(String key, Object value) {
            if (this.metadata == null) {
                this.metadata = new HashMap<>();
            }
            this.metadata.put(key, value);
            return this;
        }

        public Builder processingTimeMs(long processingTimeMs) {
            this.processingTimeMs = processingTimeMs;
            return this;
        }

        public ProcessorResult build() {
            return new ProcessorResult(this);
        }
    }

    @Override
    public String toString() {
        return "ProcessorResult{" +
                "success=" + success +
                ", processedContent='" + (processedContent != null ? processedContent.substring(0, Math.min(50, processedContent.length())) + "..." : "null") + '\'' +
                ", errorMessage='" + errorMessage + '\'' +
                ", metadataSize=" + metadata.size() +
                ", processingTimeMs=" + processingTimeMs +
                '}';
    }
}