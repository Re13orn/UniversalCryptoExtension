package com.universal.crypto.ui.editor;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Proxy;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class EditorFramingTest {
    private <T> T stub(Class<T> type,Map<String,Object> values) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(),new Class[]{type},(p,m,a)->values.get(m.getName())));
    }
    private <T> T message(Class<T> type,boolean chunked,AtomicInteger updates) {
        var body=stub(ByteArray.class,Map.of("getBytes",new byte[]{0,(byte)255,1,2}));
        var length=stub(HttpHeader.class,Map.of("name","content-length","value","999"));
        var transfer=stub(HttpHeader.class,Map.of("name","Transfer-Encoding","value","gzip, CHUNKED"));
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(),new Class[]{type},(p,m,a)->{
            if(m.getName().equals("body"))return body;
            if(m.getName().equals("headers"))return chunked?List.of(length,transfer):List.of(length);
            if(m.getName().startsWith("with")) {
                assertEquals("Content-Length",a[0]);
                if(chunked)assertEquals("withRemovedHeader",m.getName());else assertEquals("4",a[1]);
                updates.incrementAndGet();return p;
            }
            return null;
        }));
    }
    @Test void generatedLengthHeaderCannotOverrideActualCiphertextByteLength() {
        var requestChanges=new AtomicInteger();var responseChanges=new AtomicInteger();
        var request=message(HttpRequest.class,false,requestChanges);var response=message(HttpResponse.class,false,responseChanges);
        assertSame(request,EditorMessageSupport.normalizeFraming(request));assertSame(response,EditorMessageSupport.normalizeFraming(response));
        assertEquals(1,requestChanges.get());assertEquals(1,responseChanges.get());
    }
    @Test void chunkedWriteBackRemovesConflictingLengthInBothEditors() {
        var requestChanges=new AtomicInteger();var responseChanges=new AtomicInteger();
        EditorMessageSupport.normalizeFraming(message(HttpRequest.class,true,requestChanges));
        EditorMessageSupport.normalizeFraming(message(HttpResponse.class,true,responseChanges));
        assertEquals(1,requestChanges.get());assertEquals(1,responseChanges.get());
    }
}
