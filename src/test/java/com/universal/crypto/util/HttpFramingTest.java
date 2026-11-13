package com.universal.crypto.util;

import com.universal.crypto.handler.*;
import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class HttpFramingTest {
    @Test void changedBodiesUseByteLengthAndPreserveOriginalRequestHeaders() {
        var before = HttpResponseContext.builder().headers(Map.of("Content-Type","text/plain; charset=GBK","Content-Length","2"))
                .requestHeaders(Map.of("X-Nonce","original")).body("x").statusCode(200).build();
        var after = before.withBody("中文");
        var normalized = after.withHeaders(HttpFraming.headers(before,after));
        assertEquals("4",normalized.getHeaderIgnoreCase("Content-Length"));
        assertEquals("original",normalized.getOriginalHeader("x-nonce"));
        assertArrayEquals(after.getBodyBytes(),normalized.getBodyBytes());
        assertSame(before,before.withHeaders(HttpFraming.headers(before,before)));
    }
    @Test void chunkedIsAnExactTokenAndFramingHeaderOnlyChangesAreNormalized() {
        var before = HttpRequestContext.builder().headers(Map.of("Content-Length","4")).body("body").build();
        var chunked = before.withHeader("Transfer-Encoding","gzip, CHUNKED");
        assertFalse(HttpFraming.headers(before,chunked).containsKey("Content-Length"));
        var notChunked = before.withHeader("Transfer-Encoding","not-chunked");
        assertEquals("4",HttpFraming.headers(before,notChunked).get("Content-Length"));
        assertEquals("4",HttpFraming.headers(before,before.withHeader("Content-Length","999")).get("Content-Length"));
    }
    @Test void headerOnlyHeadAnd304EditsRetainRepresentationLength() {
        for (boolean head : new boolean[]{true,false}) {
            var before=HttpResponseContext.builder().method(head?"HEAD":"GET").statusCode(head?200:304)
                    .headers(Map.of("Content-Length","123")).body("").build();
            assertEquals("456",HttpFraming.headers(before,before.withHeader("Content-Length","456")).get("Content-Length"));
        }
    }
    @Test void unrelatedHeaderChangesPreserveUnchangedTransportFraming() {
        var before = HttpRequestContext.builder().headers(Map.of("Content-Length","999","Transfer-Encoding","chunked")).body("body").build();
        var after = before.withHeader("X-Sign","signature");
        assertEquals("999",HttpFraming.headers(before,after).get("Content-Length"));
        assertEquals("chunked",HttpFraming.headers(before,after).get("Transfer-Encoding"));
    }
}
