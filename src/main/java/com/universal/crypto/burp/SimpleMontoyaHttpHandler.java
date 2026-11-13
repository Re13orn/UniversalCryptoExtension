package com.universal.crypto.burp;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.universal.crypto.handler.HttpInterceptor;
import com.universal.crypto.handler.HttpRequestContext;
import com.universal.crypto.handler.HttpResponseContext;
import com.universal.crypto.model.Constants;
import com.universal.crypto.util.Logger;

import java.util.Map;
import java.util.Objects;

/**
 * Montoya API HTTP handler with real request/response mapping and differential write-back
 * Maps real Montoya objects to context models, processes through interceptor, and applies changes back
 */
public class SimpleMontoyaHttpHandler implements HttpHandler {

    private static final Logger logger = Logger.getInstance();
    private final HttpInterceptor interceptor;

    public SimpleMontoyaHttpHandler(HttpInterceptor interceptor) {
        this.interceptor = interceptor;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            // 1) Montoya → 自定义上下文
            HttpRequestContext before = toRequestContext(requestToBeSent);

            // 2) 调用拦截器
            HttpRequestContext after = interceptor.processRequest(before);

            // 3) 检查错误
            if (after.hasError()) {
                logger.error("Request processing error: " + sanitizeForLog(after.getErrorMessage()));
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            // 4) 将差异写回 Montoya 请求
            HttpRequest updated = applyRequestChanges(requestToBeSent, before, after);

            return RequestToBeSentAction.continueWith(updated);
        } catch (Exception e) {
            logger.error("Request pipeline error: " + sanitizeForLog(e.getMessage()), e);
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            // 1) Montoya → 自定义上下文
            HttpResponseContext before = toResponseContext(responseReceived);

            // 2) 调用拦截器
            HttpResponseContext after = interceptor.processResponse(before);

            // 3) 检查错误
            if (after.hasError()) {
                logger.error("Response processing error: " + sanitizeForLog(after.getErrorMessage()));
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            // 4) 将差异写回 Montoya 响应
            HttpResponse updated = applyResponseChanges(responseReceived, before, after);

            return ResponseReceivedAction.continueWith(updated);
        } catch (Exception e) {
            logger.error("Response pipeline error: " + sanitizeForLog(e.getMessage()), e);
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }

    /**
     * Convert Montoya request to our context
     */
    private HttpRequestContext toRequestContext(HttpRequestToBeSent req) {
        return HttpContextMapper.request(req, HttpContextMapper.toolSource(req.toolSource(), Constants.ToolSource.PROXY), req.messageId());
    }

    /**
     * Convert Montoya response to our context
     */
    private HttpResponseContext toResponseContext(HttpResponseReceived resp) {
        return HttpContextMapper.response(resp.initiatingRequest(), resp,
                HttpContextMapper.toolSource(resp.toolSource(), Constants.ToolSource.PROXY), resp.messageId());
    }

    /**
     * Apply request changes with differential update
     */
    private HttpRequest applyRequestChanges(HttpRequestToBeSent req, HttpRequestContext before, HttpRequestContext after) {
        HttpRequest updated = req;
        if (!java.util.Arrays.equals(before.getBodyBytes(), after.getBodyBytes()))
            updated = updated.withBody(burp.api.montoya.core.ByteArray.byteArray(after.getBodyBytes()));
        Map<String, String> headers = com.universal.crypto.util.HttpFraming.headers(before, after);
        for (String name : before.getHeaders().keySet())
            if (!headers.containsKey(name)) updated = updated.withRemovedHeader(name);
        for (var header : headers.entrySet()) {
            String previous = before.getHeaderIgnoreCase(header.getKey());
            if (!Objects.equals(previous, header.getValue())) updated = updated.withHeader(header.getKey(), header.getValue());
        }
        return updated;
    }

    private HttpResponse applyResponseChanges(HttpResponseReceived resp, HttpResponseContext before, HttpResponseContext after) {
        HttpResponse updated = resp;
        if (!java.util.Arrays.equals(before.getBodyBytes(), after.getBodyBytes()))
            updated = updated.withBody(burp.api.montoya.core.ByteArray.byteArray(after.getBodyBytes()));
        Map<String, String> headers = com.universal.crypto.util.HttpFraming.headers(before, after);
        for (String name : before.getHeaders().keySet())
            if (!headers.containsKey(name)) updated = updated.withRemovedHeader(name);
        for (var header : headers.entrySet()) {
            String previous = before.getHeaderIgnoreCase(header.getKey());
            if (!Objects.equals(previous, header.getValue())) updated = previous == null
                    ? updated.withAddedHeader(header.getKey(), header.getValue()) : updated.withUpdatedHeader(header.getKey(), header.getValue());
        }
        return updated;
    }

    /**
     * Sanitize content for logging to prevent sensitive data exposure
     */
    private String sanitizeForLog(String content) {
        if (content == null) {
            return null;
        }

        // Basic sanitization - replace potentially sensitive patterns
        return content
            .replaceAll("(?i)\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b", "[EMAIL]")
            .replaceAll("(?i)\\b(?:password|pwd|pass|token|key|secret|auth)\\s*[=:]\\s*[^\\s&]+", "[SENSITIVE]")
            .replaceAll("(?i)\\b\\d{13,19}\\b", "[CREDIT_CARD]")
            .replaceAll("(?i)\\b\\d{3}-\\d{2}-\\d{4}\\b", "[SSN]")
            .replaceAll("(?i)bearer\\s+[a-zA-Z0-9._-]+", "Bearer [TOKEN]")
            .replaceAll("(?i)basic\\s+[a-zA-Z0-9+/=]+", "Basic [CREDENTIALS]");
    }
}
