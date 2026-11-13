package com.universal.crypto.ui.editor;

import com.universal.crypto.engine.RuleProcessingService.ProcessingOutcome;
import com.universal.crypto.burp.HttpContextMapper;
import com.universal.crypto.util.HttpFraming;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/** Validation shared by request and response plaintext write-back. */
final class EditorMessageSupport {
    private static final String TOKEN = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
    private EditorMessageSupport() {}

    static byte[] ciphertext(ProcessingOutcome outcome, byte[] plaintext, java.util.Map<String,String> headers) {
        if (!outcome.isSuccess() || !outcome.isMatched() || !outcome.hasBodyEncryption())
            throw new IllegalArgumentException(outcome.getError() == null ? "No body encryption was applied; original ciphertext retained." : outcome.getError());
        byte[] output = outcome.getBodyBytes();
        if (output == null && outcome.getContent() != null) {
            var finalHeaders = new java.util.TreeMap<String,String>(String.CASE_INSENSITIVE_ORDER);
            finalHeaders.putAll(headers);
            finalHeaders.putAll(outcome.getModifiedHeaders());
            output = outcome.getContent().getBytes(com.universal.crypto.util.HttpBodyEncoding.charset(finalHeaders));
        }
        if (output == null || output.length == 0 || java.util.Arrays.equals(output, plaintext))
            throw new IllegalArgumentException("Encryption produced no ciphertext change.");
        return output;
    }

    static HttpRequest normalizeFraming(HttpRequest request) {
        if (request.body() == null) return request; // Cannot derive length from an unavailable body.
        var before = HttpContextMapper.headers(request.headers());
        var after = HttpFraming.forBodyWrite(before, request.body().getBytes().length);
        String length = after.get("Content-Length");
        if (length == null) return hasLength(before) ? request.withRemovedHeader("Content-Length") : request;
        return length.equals(length(before)) ? request : request.withHeader("Content-Length", length);
    }

    static HttpResponse normalizeFraming(HttpResponse response) {
        if (response.body() == null) return response;
        var before = HttpContextMapper.headers(response.headers());
        var after = HttpFraming.forBodyWrite(before, response.body().getBytes().length);
        String length = after.get("Content-Length");
        if (length == null) return hasLength(before) ? response.withRemovedHeader("Content-Length") : response;
        if (length.equals(length(before))) return response;
        return hasLength(before) ? response.withUpdatedHeader("Content-Length", length) : response.withAddedHeader("Content-Length", length);
    }

    private static boolean hasLength(java.util.Map<String,String> headers) { return length(headers) != null; }
    private static String length(java.util.Map<String,String> headers) {
        return headers.entrySet().stream().filter(entry -> "Content-Length".equalsIgnoreCase(entry.getKey()))
                .map(java.util.Map.Entry::getValue).findFirst().orElse(null);
    }

    static void validatePrefix(String prefix, boolean response) {
        String[] lines = prefix.replace("\r\n", "\n").split("\n");
        String pattern = response ? "HTTP/(?:1\\.[01]|2(?:\\.0)?) [1-5][0-9]{2}(?: [^\\r\\n]*)?"
                : TOKEN + " [^\\s]+ HTTP/(?:1\\.[01]|2(?:\\.0)?)";
        if (lines.length == 0 || !lines[0].matches(pattern))
            throw new IllegalArgumentException(response ? "Invalid HTTP status line." : "Invalid HTTP request line.");
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon <= 0 || !lines[i].substring(0, colon).matches(TOKEN))
                throw new IllegalArgumentException("Invalid HTTP header at line " + (i+1) + ".");
        }
    }
}
