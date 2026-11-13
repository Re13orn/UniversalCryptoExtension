package com.universal.crypto.handler;

import java.net.URL;
import java.util.Map;

/**
 * HTTP request context for processing
 */
public class HttpRequestContext extends HttpContextBase {

    private HttpRequestContext(Builder builder) {
        super(builder);
    }

    /**
     * Create a new context with modified body
     */
    public HttpRequestContext withBody(String newBody) {
        if (java.util.Objects.equals(this.body, newBody)) return this;
        return new Builder()
                .method(this.method)
                .url(this.url)
                .headers(getHeaders()) // Use getter to get defensive copy
                .requestHeaders(getRequestHeaders())
                .body(newBody)
                .toolSource(this.toolSource)
                .errorMessage(this.errorMessage)
                .messageId(this.messageId)
                .build();
    }

    public HttpRequestContext withBodyBytes(byte[] bytes) {
        if (java.util.Arrays.equals(this.bodyBytes, bytes)) return this;
        return new Builder()
                .method(this.method)
                .url(this.url)
                .headers(getHeaders()) // Use getter to get defensive copy
                .requestHeaders(getRequestHeaders())
                .bodyBytes(bytes)
                .toolSource(this.toolSource)
                .errorMessage(this.errorMessage)
                .messageId(this.messageId)
                .build();
    }


    /**
     * Create a new context with added/modified header
     */
    public HttpRequestContext withHeader(String name, String value) {
        return new Builder()
                .method(this.method)
                .url(this.url)
                .headers(getHeaders()) // Use getter to get defensive copy
                .requestHeaders(getRequestHeaders())
                .addHeader(name, value)
                .bodyBytes(this.bodyBytes)
                .toolSource(this.toolSource)
                .errorMessage(this.errorMessage)
                .messageId(this.messageId)
                .build();
    }

    public HttpRequestContext withHeaders(Map<String, String> headers) {
        if (this.headers.equals(headers)) return this;
        return new Builder()
                .method(this.method)
                .url(this.url)
                .headers(headers)
                .requestHeaders(getRequestHeaders())
                .bodyBytes(this.bodyBytes)
                .toolSource(this.toolSource)
                .errorMessage(this.errorMessage)
                .messageId(this.messageId)
                .build();
    }

    /**
     * Create a new context with error message
     */
    public HttpRequestContext withError(String errorMessage) {
        return new Builder()
                .method(this.method)
                .url(this.url)
                .headers(getHeaders()) // Use getter to get defensive copy
                .requestHeaders(getRequestHeaders())
                .bodyBytes(this.bodyBytes)
                .toolSource(this.toolSource)
                .errorMessage(errorMessage)
                .messageId(this.messageId)
                .build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends HttpContextBase.Builder<Builder> {

        @Override
        protected Builder self() {
            return this;
        }

        public HttpRequestContext build() {
            return new HttpRequestContext(this);
        }
    }

    /**
     * Create request context from Montoya API data
     */
    public static HttpRequestContext fromMontoya(String method, URL url, Map<String, String> headers,
                                               String body, String toolSource) {
        return builder()
                .method(method)
                .url(url)
                .headers(headers)
                .body(body)
                .toolSource(toolSource)
                .build();
    }
}
