package com.universal.crypto.ui.editor;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.IOException;

/** Adds only whitespace outside strings; never serializes keys, escapes or numbers. */
final class JsonPresentation {
    private static final JsonFactory FACTORY = new JsonFactory();

    static String pretty(String raw) {
        try (JsonParser parser = FACTORY.createParser(raw)) {
            JsonToken first = parser.nextToken();
            if (first != JsonToken.START_OBJECT && first != JsonToken.START_ARRAY) return null;
            parser.skipChildren();
            if (parser.nextToken() != null) return null;
        } catch (IOException | RuntimeException e) { return null; }
        StringBuilder out = new StringBuilder(raw.length());
        int depth = 0;
        boolean string = false, escape = false;
        char previous = 0;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (string) {
                out.append(c);
                if (escape) escape = false;
                else if (c == '\\') escape = true;
                else if (c == '"') string = false;
                continue;
            }
            if (Character.isWhitespace(c)) continue;
            if (c == '"') { string = true; out.append(c); }
            else if (c == '{' || c == '[') {
                out.append(c); depth++;
                int next = i + 1;
                while (next < raw.length() && Character.isWhitespace(raw.charAt(next))) next++;
                if (next < raw.length() && raw.charAt(next) != '}' && raw.charAt(next) != ']') newline(out, depth);
            } else if (c == '}' || c == ']') {
                depth--;
                if (previous != '{' && previous != '[') newline(out, depth);
                out.append(c);
            } else if (c == ',') { out.append(c); newline(out, depth); }
            else if (c == ':') out.append(": ");
            else out.append(c);
            previous = c;
        }
        return out.toString();
    }

    private static void newline(StringBuilder out, int depth) {
        out.append('\n');
        out.append("  ".repeat(depth));
    }
}
