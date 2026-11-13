package com.universal.crypto.processor;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Context information available to processors during processing
 */
public class ProcessorContext {

    private final String method;
    private final URL url;
    private final Map<String, String> headers;
    private final Map<String, String> requestHeaders;
    private final String toolSource;
    private final boolean isRequest;
    private final Map<String, Object> sharedData;
    private final long timestamp;
    private byte[] bodyBytes;

    private ProcessorContext(Builder builder) {
        this.method = builder.method;
        this.url = builder.url;
        // Use TreeMap with case-insensitive comparator for headers
        this.headers = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (builder.headers != null) {
            this.headers.putAll(builder.headers);
        }
        var original = new java.util.TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
        if (builder.requestHeaders != null) original.putAll(builder.requestHeaders);
        this.requestHeaders = java.util.Collections.unmodifiableMap(original);
        this.toolSource = builder.toolSource;
        this.isRequest = builder.isRequest;
        this.sharedData = builder.sharedData != null ? new HashMap<>(builder.sharedData) : new HashMap<>();
        this.timestamp = builder.timestamp > 0 ? builder.timestamp : System.currentTimeMillis();
    }

    /** Restore local execution state after a failed action; original request headers never change. */
    public void restoreState(Map<String,String> headers, Map<String,Object> sharedData, byte[] bytes) {
        this.headers.clear(); this.headers.putAll(headers);
        this.sharedData.clear(); this.sharedData.putAll(sharedData);
        setBodyBytes(bytes);
    }

    public void setBodyBytes(byte[] bytes) { bodyBytes = bytes == null ? null : bytes.clone(); }
    public byte[] getBodyBytes() { return bodyBytes == null ? null : bodyBytes.clone(); }

    public void setBodyText(String text) {
        setBodyBytes(text == null ? new byte[0] : text.getBytes(com.universal.crypto.util.HttpBodyEncoding.charset(headers)));
    }

    /** Preserve byte results for later script steps; derive the current text with HTTP charset. */
    public String applyBodyResult(ProcessorResult result) {
        byte[] bytes = result.getProcessedBytes();
        if (bytes != null) {
            setBodyBytes(bytes);
            return new String(bytes, com.universal.crypto.util.HttpBodyEncoding.charset(headers));
        }
        setBodyText(result.getProcessedContent());
        return result.getProcessedContent();
    }

    public String getMethod() {
        return method;
    }

    public URL getUrl() {
        return url;
    }

    public Map<String, String> getHeaders() {
        java.util.TreeMap<String, String> copy = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        copy.putAll(headers);
        return java.util.Collections.unmodifiableMap(copy);
    }

    public Map<String, String> getOriginalHeaders() { return requestHeaders; }
    public String getOriginalHeader(String name) { return name == null ? null : requestHeaders.get(name); }

    public String getHeader(String name) {
        return headers.get(name);
    }
    
    /**
     * Update a header value in the context (used for synchronization during rule processing)
     */
    public void setHeader(String name, String value) {
        headers.put(name, value);
    }

    public String getToolSource() {
        return toolSource;
    }

    public boolean isRequest() {
        return isRequest;
    }

    public boolean isResponse() {
        return !isRequest;
    }

    public Map<String, Object> getSharedData() {
        return new HashMap<>(sharedData);
    }

    public Object getSharedData(String key) {
        return sharedData.get(key);
    }

    public void setSharedData(String key, Object value) {
        sharedData.put(key, value);
    }

    public boolean hasSharedData(String key) {
        return sharedData.containsKey(key);
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getHost() {
        return url != null ? url.getHost() : null;
    }

    public String getPath() {
        return url != null ? url.getPath() : null;
    }

    public int getPort() {
        return url != null ? url.getPort() : -1;
    }

    public String getProtocol() {
        return url != null ? url.getProtocol() : null;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder forRequest(String method, URL url, Map<String, String> headers, String toolSource) {
        return new Builder()
                .method(method)
                .url(url)
                .headers(headers)
                .requestHeaders(headers)
                .toolSource(toolSource)
                .isRequest(true);
    }

    public static Builder forResponse(String method, URL url, Map<String, String> headers, String toolSource) {
        return new Builder()
                .method(method)
                .url(url)
                .headers(headers)
                .toolSource(toolSource)
                .isRequest(false);
    }

    public static class Builder {
        private String method;
        private URL url;
        private Map<String, String> headers;
        private Map<String, String> requestHeaders;
        private String toolSource;
        private boolean isRequest;
        private Map<String, Object> sharedData;
        private long timestamp;

        public Builder method(String method) {
            this.method = method;
            return this;
        }

        public Builder url(URL url) {
            this.url = url;
            return this;
        }

        public Builder headers(Map<String, String> headers) {
            this.headers = headers;
            return this;
        }

        public Builder requestHeaders(Map<String, String> headers) {
            this.requestHeaders = headers;
            return this;
        }

        public Builder toolSource(String toolSource) {
            this.toolSource = toolSource;
            return this;
        }

        public Builder isRequest(boolean isRequest) {
            this.isRequest = isRequest;
            return this;
        }

        public Builder sharedData(Map<String, Object> sharedData) {
            this.sharedData = sharedData;
            return this;
        }

        public Builder addSharedData(String key, Object value) {
            if (this.sharedData == null) {
                this.sharedData = new HashMap<>();
            }
            this.sharedData.put(key, value);
            return this;
        }

        public Builder timestamp(long timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public ProcessorContext build() {
            return new ProcessorContext(this);
        }
    }

    @Override
    public String toString() {
        return "ProcessorContext{" +
                "method='" + method + '\'' +
                ", url=" + url +
                ", toolSource='" + toolSource + '\'' +
                ", isRequest=" + isRequest +
                ", sharedDataKeys=" + sharedData.keySet() +
                ", timestamp=" + timestamp +
                '}';
    }
}