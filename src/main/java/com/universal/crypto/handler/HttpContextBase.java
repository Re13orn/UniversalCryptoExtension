package com.universal.crypto.handler;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Base class for HTTP request/response context
 */
public abstract class HttpContextBase {

    protected final String method;
    protected final URL url;
    protected final Map<String, String> headers;
    protected final Map<String, String> requestHeaders;
    protected final String body;
    protected final byte[] bodyBytes;
    protected final java.nio.charset.Charset bodyCharset;
    protected final String toolSource;
    protected final String errorMessage;
    protected final Integer messageId;

    protected HttpContextBase(Builder<?> builder) {
        this.method = builder.method;
        this.url = builder.url;
        this.headers = builder.headers != null ? new HashMap<>(builder.headers) : new HashMap<>();
        if (builder.requestHeaders == null) {
            this.requestHeaders = null;
        } else {
            var original = new java.util.TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
            original.putAll(builder.requestHeaders);
            this.requestHeaders = java.util.Collections.unmodifiableMap(original);
        }
        java.nio.charset.Charset charset = com.universal.crypto.util.HttpBodyEncoding.charset(this.headers);
        this.bodyCharset = charset;
        this.bodyBytes = builder.bodyBytes != null ? builder.bodyBytes.clone() : (builder.body == null ? new byte[0] : builder.body.getBytes(charset));
        this.body = builder.bodyBytes != null ? new String(this.bodyBytes, charset) : builder.body;
        this.toolSource = builder.toolSource;
        this.errorMessage = builder.errorMessage;
        this.messageId = builder.messageId;
    }

    public String getMethod() { return method; }
    public URL getUrl() { return url; }
    public Map<String, String> getHeaders() { return new HashMap<>(headers); }
    /** Original initiating request headers, independent of current-direction headers. */
    public Map<String, String> getRequestHeaders() { return requestHeaders; }
    public String getOriginalHeader(String name) {
        return requestHeaders == null || name == null ? null : requestHeaders.get(name);
    }
    public String getBody() { return body; }
    public byte[] getBodyBytes() { return bodyBytes.clone(); }
    public String getToolSource() { return toolSource; }
    public String getErrorMessage() { return errorMessage; }
    public Integer getMessageId() { return messageId; }
    public boolean hasError() { return errorMessage != null; }

    public String getHost() {
        return url != null ? url.getHost() : null;
    }

    public String getPath() {
        return url != null ? url.getPath() : null;
    }

    /**
     * Get header value ignoring case
     */
    public String getHeaderIgnoreCase(String headerName) {
        if (headers == null || headerName == null) {
            return null;
        }

        // First try exact match (fastest path)
        String value = headers.get(headerName);
        if (value != null) {
            return value;
        }

        // Fall back to case-insensitive search
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (headerName.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue();
            }
        }

        return null;
    }

    /**
     * Base builder for HTTP contexts
     */
    public abstract static class Builder<T extends Builder<T>> {
        protected String method;
        protected URL url;
        protected Map<String, String> headers;
        protected Map<String, String> requestHeaders;
        protected String body;
        protected byte[] bodyBytes;
        protected String toolSource;
        protected String errorMessage;
        protected Integer messageId;

        public T method(String method) {
            this.method = method;
            return self();
        }

        public T url(URL url) {
            this.url = url;
            return self();
        }

        public T headers(Map<String, String> headers) {
            this.headers = headers;
            return self();
        }

        public T requestHeaders(Map<String, String> headers) {
            this.requestHeaders = headers;
            return self();
        }

        public T body(String body) {
            this.body = body;
            this.bodyBytes = null;
            return self();
        }

        public T bodyBytes(byte[] bytes) { this.bodyBytes = bytes.clone(); return self(); }

        public T toolSource(String toolSource) {
            this.toolSource = toolSource;
            return self();
        }

        public T errorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
            return self();
        }

        public T messageId(Integer messageId) {
            this.messageId = messageId;
            return self();
        }

        public T addHeader(String name, String value) {
            if (this.headers == null) {
                this.headers = new HashMap<>();
            }

            // Remove any existing header with case-insensitive name match
            String existingKey = findHeaderKeyIgnoreCase(name);
            if (existingKey != null) {
                this.headers.remove(existingKey);
            }

            this.headers.put(name, value);
            return self();
        }

        /**
         * Find existing header key ignoring case
         */
        private String findHeaderKeyIgnoreCase(String headerName) {
            if (this.headers == null || headerName == null) {
                return null;
            }

            for (String key : this.headers.keySet()) {
                if (headerName.equalsIgnoreCase(key)) {
                    return key;
                }
            }
            return null;
        }

        protected abstract T self();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "method='" + method + '\'' +
                ", url=" + url +
                ", headersCount=" + headers.size() +
                ", bodyLength=" + (body != null ? body.length() : 0) +
                ", toolSource='" + toolSource + '\'' +
                ", hasError=" + hasError() +
                '}';
    }
}
