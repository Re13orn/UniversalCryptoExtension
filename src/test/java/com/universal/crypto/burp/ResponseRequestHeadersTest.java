package com.universal.crypto.burp;

import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ByteArray;
import com.universal.crypto.handler.HttpResponseContext;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class ResponseRequestHeadersTest {
    private <T> T stub(Class<T> type, Map<String,Object> values) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class[]{type}, (p,m,a) -> values.get(m.getName())));
    }
    @Test void initiatingHeadersAreIndependentAndAbsentRequestIsSupported() throws Exception {
        var requestHeader = stub(HttpHeader.class, Map.of("name", "Content-Type", "value", "request/type"));
        var responseHeader = stub(HttpHeader.class, Map.of("name", "Content-Type", "value", "response/type"));
        var request = stub(HttpRequest.class, Map.of("method", "POST", "headers", List.of(requestHeader)));
        var bytes = stub(ByteArray.class, Map.of("getBytes", new byte[]{1,2,3}));
        var converter = SimpleMontoyaHttpHandler.class.getDeclaredMethod("toResponseContext", HttpResponseReceived.class);
        converter.setAccessible(true);
        var handler = new SimpleMontoyaHttpHandler(null);
        for (boolean available : new boolean[]{true, false}) {
            var values = new java.util.HashMap<String,Object>(Map.of("headers", List.of(responseHeader), "body", bytes, "statusCode", (short)200, "messageId", 7));
            if (available) values.put("initiatingRequest", request);
            var context = (HttpResponseContext)converter.invoke(handler, stub(HttpResponseReceived.class, values));
            assertEquals("response/type", context.getHeaderIgnoreCase("Content-Type"));
            assertEquals(available ? "request/type" : null, context.getOriginalHeader("content-type"));
            assertEquals(available ? "POST" : "GET", context.getMethod());
            assertEquals(7, context.getMessageId());
        }
    }
}
