package com.universal.crypto.handler;

import java.net.URL;
import java.util.Map;

/**
 * HTTP response context for processing
 */
public class HttpResponseContext extends HttpContextBase {

    private final int statusCode;
    private final Integer requestBodyHash;

    private HttpResponseContext(Builder builder) {
        super(builder);
        this.statusCode = builder.statusCode;
        this.requestBodyHash = builder.requestBodyHash;
    }

    public int getStatusCode() { return statusCode; }

    public Integer getRequestBodyHash() { return requestBodyHash; }

    /**
     * Create a new context with modified body
     */
    public HttpResponseContext withBody(String newBody) {
        if (java.util.Objects.equals(this.body, newBody)) return this;
        return new Builder()
                .method(this.method)
                .url(this.url)
                .headers(getHeaders()) // Use getter to get defensive copy
                .requestHeaders(getRequestHeaders())
                .body(newBody)
                .toolSource(this.toolSource)
                .statusCode(this.statusCode)
                .requestBodyHash(this.requestBodyHash)
                .errorMessage(this.errorMessage)
                .messageId(this.messageId)
                .build();
    }

    public HttpResponseContext withBodyBytes(byte[] bytes) {
        if (java.util.Arrays.equals(this.bodyBytes, bytes)) return this;
        return new Builder()
                .method(this.method)
                .url(this.url)
                .headers(getHeaders()) // Use getter to get defensive copy
                .requestHeaders(getRequestHeaders())
                .bodyBytes(bytes)
                .toolSource(this.toolSource)
                .statusCode(this.statusCode)
                .requestBodyHash(this.requestBodyHash)
                .errorMessage(this.errorMessage)
                .messageId(this.messageId)
                .build();
    }


    /**
     * Create a new context with added/modified header
     */
    public HttpResponseContext withHeader(String name, String value) {
        return new Builder()
                .method(this.method)
                .url(this.url)
                .headers(getHeaders()) // Use getter to get defensive copy
                .requestHeaders(getRequestHeaders())
                .addHeader(name, value)
                .bodyBytes(this.bodyBytes)
                .toolSource(this.toolSource)
                .statusCode(this.statusCode)
                .requestBodyHash(this.requestBodyHash)
                .errorMessage(this.errorMessage)
                .messageId(this.messageId)
                .build();
    }

    public HttpResponseContext withHeaders(Map<String, String> headers) {
        if (this.headers.equals(headers)) return this;
        return new Builder()
                .method(this.method)
                .url(this.url)
                .headers(headers)
                .requestHeaders(getRequestHeaders())
                .bodyBytes(this.bodyBytes)
                .toolSource(this.toolSource)
                .statusCode(this.statusCode)
                .requestBodyHash(this.requestBodyHash)
                .errorMessage(this.errorMessage)
                .messageId(this.messageId)
                .build();
    }

    /**
     * Create a new context with error message
     */
    public HttpResponseContext withError(String errorMessage) {
        return new Builder()
                .method(this.method)
                .url(this.url)
                .headers(getHeaders()) // Use getter to get defensive copy
                .requestHeaders(getRequestHeaders())
                .bodyBytes(this.bodyBytes)
                .toolSource(this.toolSource)
                .statusCode(this.statusCode)
                .requestBodyHash(this.requestBodyHash)
                .errorMessage(errorMessage)
                .messageId(this.messageId)
                .build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends HttpContextBase.Builder<Builder> {
        private int statusCode;

        public Builder statusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        private Integer requestBodyHash;

        public Builder requestBodyHash(Integer requestBodyHash) {
            this.requestBodyHash = requestBodyHash;
            return this;
        }

        @Override
        protected Builder self() {
            return this;
        }

        public HttpResponseContext build() {
            return new HttpResponseContext(this);
        }
    }

    /**
     * Create response context from Montoya API data
     */
    public static HttpResponseContext fromMontoya(String method, URL url, Map<String, String> headers,
                                                String body, int statusCode, String toolSource, Integer requestBodyHash) {
        return builder()
                .method(method)
                .url(url)
                .headers(headers)
                .body(body)
                .statusCode(statusCode)
                .toolSource(toolSource)
                .requestBodyHash(requestBodyHash)
                .build();
    }

    @Override
    public String toString() {
        return "HttpResponseContext{" +
                "method='" + method + '\'' +
                ", url=" + url +
                ", statusCode=" + statusCode +
                ", headersCount=" + headers.size() +
                ", bodyLength=" + (body != null ? body.length() : 0) +
                ", toolSource='" + toolSource + '\'' +
                ", hasError=" + hasError() +
                '}';
    }
}
