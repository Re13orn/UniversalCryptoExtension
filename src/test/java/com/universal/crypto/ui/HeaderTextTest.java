package com.universal.crypto.ui;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class HeaderTextTest {
    @Test void parsesRealLineBreaksAndCaseInsensitiveHeaderNames() {
        var result = HeaderText.parse("Content-Type: application/json\r\nX-Nonce: a:b\nX-Probe: one\rX-probe: two\n");
        assertEquals(3,result.size()); assertEquals("application/json",result.get("content-type"));
        assertEquals("a:b",result.get("X-Nonce")); assertEquals("two",result.get("X-PROBE"));
    }
    @Test void malformedLinesFailInsteadOfQuietlyLosingHeaders() {
        assertThrows(IllegalArgumentException.class,() -> HeaderText.parse("X-Nonce: a\nmissing-colon"));
    }
}
