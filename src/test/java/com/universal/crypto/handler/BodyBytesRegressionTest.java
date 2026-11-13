package com.universal.crypto.handler;
import org.junit.jupiter.api.Test;
import java.nio.charset.Charset;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
class BodyBytesRegressionTest {
    @Test void binaryBodySurvivesHeaderOnlyChange() {
        byte[] gzip = {31, (byte)139, 8, 0, (byte)255, (byte)254, 0, 1};
        HttpRequestContext request = HttpRequestContext.builder().bodyBytes(gzip).build();
        assertArrayEquals(gzip, request.withHeader("X-Test", "1").getBodyBytes());
        assertArrayEquals(gzip, request.withBody(request.getBody()).getBodyBytes());
        byte[] copy = request.getBodyBytes(); copy[0] = 0;
        assertArrayEquals(gzip, request.getBodyBytes());
        HttpResponseContext response = HttpResponseContext.builder().bodyBytes(gzip).build();
        assertArrayEquals(gzip, response.withHeader("X-Test", "1").getBodyBytes());
    }
    @Test void declaredCharsetControlsActualBytes() {
        Charset gbk = Charset.forName("GBK");
        HttpRequestContext request = HttpRequestContext.builder().headers(Map.of("Content-Type", "text/plain; charset=GBK")).bodyBytes("中文".getBytes(gbk)).build();
        assertEquals("中文", request.getBody());
        assertArrayEquals("改写".getBytes(gbk), request.withBody("改写").getBodyBytes());
    }
}
