package com.universal.crypto.ui;

import java.util.Map;
import java.util.TreeMap;

/** Parse the editable header lists used by offline previews. */
final class HeaderText {
    private HeaderText() { }
    static Map<String,String> parse(String text) {
        var headers = new TreeMap<String,String>(String.CASE_INSENSITIVE_ORDER);
        if (text != null) for (String line : text.split("\\R")) {
            if (line.isBlank()) continue;
            int colon = line.indexOf(':');
            if (colon <= 0) throw new IllegalArgumentException("Invalid header line: " + line);
            headers.put(line.substring(0, colon).trim(), line.substring(colon + 1).trim());
        }
        return headers;
    }
}
