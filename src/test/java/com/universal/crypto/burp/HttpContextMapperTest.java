package com.universal.crypto.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Proxy;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class HttpContextMapperTest {
    private <T> T stub(Class<T> type,Map<String,Object> values) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(),new Class[]{type},(p,m,a)->values.get(m.getName())));
    }
    private HttpHeader header(String name,String value) { return stub(HttpHeader.class,Map.of("name",name,"value",value)); }
    @Test void mappingUsesRawBytesAndConsistentlyCollapsesHeaderNamesByCase() {
        byte[] body="中文".getBytes(Charset.forName("GBK"));
        var request=stub(HttpRequest.class,Map.of("method","POST","url","https://example.test/demo",
                "body",stub(ByteArray.class,Map.of("getBytes",body)),"bodyToString","wrong-decoding",
                "headers",List.of(header("Content-Type","text/plain; charset=GBK"),header("X-Key","old"),header("x-key","new"))));
        var context=HttpContextMapper.request(request,"REPEATER",9);
        assertArrayEquals(body,context.getBodyBytes());assertEquals("中文",context.getBody());
        assertEquals("new",context.getHeaderIgnoreCase("X-Key"));assertEquals(2,context.getHeaders().size());assertEquals(9,context.getMessageId());
        assertEquals("ANY",HttpContextMapper.toolSource(stub(ToolSource.class,Map.of()),"ANY"));
    }
}
