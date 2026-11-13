package com.universal.crypto.util;

import com.universal.crypto.handler.HttpContextBase;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Normalize framing only when this plugin changes body bytes or framing headers. */
public final class HttpFraming {
    private HttpFraming() {}

    public static Map<String, String> headers(HttpContextBase before, HttpContextBase after) {
        var headers = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
        headers.putAll(after.getHeaders());
        boolean bodyChanged = !Arrays.equals(before.getBodyBytes(), after.getBodyBytes());
        boolean changed = bodyChanged
                || !Objects.equals(before.getHeaderIgnoreCase("Content-Length"), after.getHeaderIgnoreCase("Content-Length"))
                || !Objects.equals(before.getHeaderIgnoreCase("Transfer-Encoding"), after.getHeaderIgnoreCase("Transfer-Encoding"));
        // HEAD/304 may describe a representation length without carrying those body bytes.
        if (!bodyChanged && after instanceof com.universal.crypto.handler.HttpResponseContext response
                && ("HEAD".equalsIgnoreCase(after.getMethod()) || response.getStatusCode() == 304)) {
            if (!Objects.equals(before.getHeaderIgnoreCase("Transfer-Encoding"), after.getHeaderIgnoreCase("Transfer-Encoding"))
                    && isChunked(headers.get("Transfer-Encoding"))) headers.remove("Content-Length");
            return headers;
        }
        return changed ? forBodyWrite(headers, after.getBodyBytes().length) : headers;
    }

    public static Map<String,String> forBodyWrite(Map<String,String> source, int length) {
        var headers = new TreeMap<String,String>(String.CASE_INSENSITIVE_ORDER);
        headers.putAll(source);
        if (isChunked(headers.get("Transfer-Encoding"))) headers.remove("Content-Length");
        else headers.put("Content-Length", Integer.toString(length));
        return headers;
    }

    private static boolean isChunked(String transfer) {
        return transfer != null && Arrays.stream(transfer.split(","))
                .anyMatch(token -> "chunked".equalsIgnoreCase(token.trim()));
    }
}
