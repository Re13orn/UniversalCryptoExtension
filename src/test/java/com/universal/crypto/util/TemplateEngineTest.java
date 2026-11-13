package com.universal.crypto.util;

import com.universal.crypto.processor.ProcessorContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TemplateEngineTest {

    @Test
    void testCanonicalizeJsonOutput() {
        String template = "${canonicalize:json:json:sign}";
        String body = "{\"b\": 2, \"a\": 1, \"sign\": \"s\", \"c\": 3}";
        ProcessorContext context = ProcessorContext.builder().build();
        
        String result = TemplateEngine.process(template, context, body);
        // Expected: sorted keys a, b, c. sign excluded.
        // Note: Jackson's default serialization for numbers might be strict on spaces. 
        // 1 becomes 1. 
        assertEquals("{\"a\":1,\"b\":2,\"c\":3}", result);
    }

    @Test
    void testCanonicalizeUrlParams() {
        String template = "${canonicalize:json:&:=:sign}";
        String body = "{\"b\": 2, \"a\": 1, \"sign\": \"s\"}";
        ProcessorContext context = ProcessorContext.builder().build();
        
        String result = TemplateEngine.process(template, context, body);
        assertEquals("a=1&b=2", result);
    }
    
    @Test
    void testCanonicalizeNestedPath() {
        // Test json.data syntax
        String template = "${canonicalize:json.data:json:sign}";
        String body = "{\"data\": {\"b\": 2, \"a\": 1, \"sign\": \"s\"}}";
        ProcessorContext context = ProcessorContext.builder().build();
        
        String result = TemplateEngine.process(template, context, body);
        assertEquals("{\"a\":1,\"b\":2}", result);
    }

    @Test
    void testCanonicalizeMethodPath() throws java.net.MalformedURLException {
        // Test combination
        String template = "${method}|${path}|${canonicalize:json:json:sign}";
        String body = "{\"b\":1,\"sign\":\"x\",\"a\":2}";
        ProcessorContext context = ProcessorContext.builder()
                .method("POST")
                .url(new java.net.URL("http://example.com/api")) // path is /api
                .build();
        
        String result = TemplateEngine.process(template, context, body);
        assertEquals("POST|/api|{\"a\":2,\"b\":1}", result);
    }

    @Test
    void testStableJsonPayloadUsesQueryForGet() throws java.net.MalformedURLException {
        String template = "${stablejson:payload}";
        ProcessorContext context = ProcessorContext.builder()
                .method("GET")
                .url(new java.net.URL("https://example.com/api?b=2&a=1&a=3"))
                .build();

        String result = TemplateEngine.process(template, context, "");
        assertEquals("{\"a\":[\"1\",\"3\"],\"b\":\"2\"}", result);
    }

    @Test
    void testStableJsonPayloadUsesBodyForPostAndStringifiesScalars() throws java.net.MalformedURLException {
        String template = "${stablejson:payload}";
        String body = "{\"resourceType\":11,\"locations\":[0],\"empty\":{},\"keep\":[],\"flag\":true}";
        ProcessorContext context = ProcessorContext.builder()
                .method("POST")
                .url(new java.net.URL("https://example.com/api"))
                .build();

        String result = TemplateEngine.process(template, context, body);
        assertEquals("{\"flag\":\"true\",\"keep\":[],\"locations\":[\"0\"],\"resourceType\":\"11\"}", result);
    }

    @Test
    void testTemplateCombinesHeaderAndSortedQuery() throws java.net.MalformedURLException {
        var context = com.universal.crypto.processor.ProcessorContext.builder()
                .method("GET")
                .url(new java.net.URL("https://api.example.test/demo?z=2&a=1"))
                .headers(java.util.Map.of("X-Request-Id", "demo"))
                .build();

        assertEquals("demo:{\"a\":\"1\",\"z\":\"2\"}",
                TemplateEngine.process("${header.X-Request-Id}:${stablejson:payload}", context, ""));
    }
}
