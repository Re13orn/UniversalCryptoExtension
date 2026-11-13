package com.universal.crypto.burp;

import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import com.universal.crypto.handler.HttpRequestContext;
import com.universal.crypto.handler.HttpResponseContext;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class HttpHandlerHeaderPreservationTest {
    private HttpHeader header(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(HttpHeader.class.getClassLoader(), new Class[]{HttpHeader.class},
                (p,m,a) -> Map.of("name",name,"value",value).get(m.getName()));
    }

    @Test void unchangedAndUnrelatedHeaderChangesPreserveDuplicateRequestAndResponseHeaders() throws Exception {
        var source = List.of(header("Set-Cookie","a=1"), header("Set-Cookie","b=2"),
                header("X-Duplicate","first"), header("x-duplicate","second"), header("X-Target","old"));
        var handler = new SimpleMontoyaHttpHandler(null);
        for (boolean response : new boolean[]{false,true}) {
            var writes = new ArrayList<String>();
            Class<?> type = response ? HttpResponseReceived.class : HttpRequestToBeSent.class;
            Object message = Proxy.newProxyInstance(type.getClassLoader(), new Class[]{type}, (p,m,a) -> {
                if (m.getName().equals("headers")) return source;
                if (m.getName().startsWith("with")) { writes.add(m.getName()+":"+a[0]+"="+a[1]); return p; }
                return null;
            });
            if (response) {
                var before = HttpResponseContext.builder().headers(HttpContextMapper.headers(source)).body("unchanged").build();
                var apply = SimpleMontoyaHttpHandler.class.getDeclaredMethod("applyResponseChanges", type, HttpResponseContext.class, HttpResponseContext.class);
                apply.setAccessible(true);
                assertSame(message, apply.invoke(handler,message,before,before));
                assertTrue(writes.isEmpty(), "No rules or noChange must not rewrite duplicate headers");
                apply.invoke(handler,message,before,before.withHeader("X-Target","new"));
                assertEquals(List.of("withUpdatedHeader:X-Target=new"),writes);
            } else {
                var before = HttpRequestContext.builder().headers(HttpContextMapper.headers(source)).body("unchanged").build();
                var apply = SimpleMontoyaHttpHandler.class.getDeclaredMethod("applyRequestChanges", type, HttpRequestContext.class, HttpRequestContext.class);
                apply.setAccessible(true);
                assertSame(message, apply.invoke(handler,message,before,before));
                assertTrue(writes.isEmpty(), "No rules or noChange must not rewrite duplicate headers");
                apply.invoke(handler,message,before,before.withHeader("X-Target","new"));
                assertEquals(List.of("withHeader:X-Target=new"),writes);
            }
        }
    }
}
