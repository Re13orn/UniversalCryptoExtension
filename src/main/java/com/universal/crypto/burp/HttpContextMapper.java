package com.universal.crypto.burp;

import burp.api.montoya.core.ToolSource;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.universal.crypto.handler.HttpRequestContext;
import com.universal.crypto.handler.HttpResponseContext;

import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;

/** One Montoya-to-domain mapping boundary shared by wire handlers and message editors. */
public final class HttpContextMapper {
    private HttpContextMapper() {}

    public static String toolSource(ToolSource source, String fallback) {
        return source == null || source.toolType() == null ? fallback : source.toolType().name();
    }

    public static HttpRequestContext request(HttpRequest request, String source, Integer id) {
        var builder = HttpRequestContext.builder().method(request.method()).url(url(request))
                .headers(headers(request.headers())).toolSource(source).messageId(id);
        if (request.body() != null) builder.bodyBytes(request.body().getBytes());
        else builder.body(request.bodyToString());
        return builder.build();
    }

    public static HttpResponseContext response(HttpRequest initiatingRequest, HttpResponse response, String source, Integer id) {
        var builder = HttpResponseContext.builder().method(initiatingRequest == null ? "GET" : initiatingRequest.method())
                .url(initiatingRequest == null ? null : url(initiatingRequest)).headers(headers(response.headers()))
                .requestHeaders(initiatingRequest == null ? null : headers(initiatingRequest.headers()))
                .toolSource(source).messageId(id).statusCode(response.statusCode());
        if (response.body() != null) builder.bodyBytes(response.body().getBytes());
        else builder.body(response.bodyToString());
        return builder.build();
    }

    public static URL url(HttpRequest request) {
        try {
            String provided = request.url();
            if (provided != null && !provided.isBlank()) return new URL(provided);
            var service = request.httpService();
            if (service == null) return null;
            return new URL(service.secure() ? "https" : "http", service.host(), service.port(),
                    request.path() == null ? "/" : request.path());
        } catch (Exception error) {
            return null;
        }
    }

    /** Single-value rule API: last duplicate wins consistently, irrespective of casing. */
    public static Map<String, String> headers(Iterable<? extends HttpHeader> source) {
        Map<String, String> values = new LinkedHashMap<>();
        if (source == null) return values;
        for (var header : source) {
            if (header == null || header.name() == null) continue;
            String previous = values.keySet().stream().filter(header.name()::equalsIgnoreCase).findFirst().orElse(null);
            if (previous != null) values.remove(previous);
            values.put(header.name(), header.value());
        }
        return values;
    }
}
