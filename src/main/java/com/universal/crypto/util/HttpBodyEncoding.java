package com.universal.crypto.util;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Pattern;

/** Shared text encoding for HTTP contexts, editor pipelines and step previews. */
public final class HttpBodyEncoding {
    private static final Pattern CHARSET = Pattern.compile("(?i)charset\\s*=\\s*[\"']?([^;\\s\"']+)");
    private HttpBodyEncoding() { }
    public static Charset charset(Map<String,String> headers) {
        if (headers != null) for (var header : headers.entrySet()) {
            if ("Content-Type".equalsIgnoreCase(header.getKey()) && header.getValue() != null) {
                var matcher = CHARSET.matcher(header.getValue());
                return matcher.find() ? Charset.forName(matcher.group(1)) : StandardCharsets.UTF_8;
            }
        }
        return StandardCharsets.UTF_8;
    }
}
