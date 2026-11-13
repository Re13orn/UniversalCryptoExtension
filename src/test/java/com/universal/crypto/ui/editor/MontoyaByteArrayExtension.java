package com.universal.crypto.ui.editor;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;

/** Offline replacement for the byte-array factory normally supplied by Burp. */
final class MontoyaByteArrayExtension implements BeforeEachCallback, AfterEachCallback {
    private MontoyaObjectFactory previous;

    public void beforeEach(ExtensionContext context) {
        previous = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = (MontoyaObjectFactory) Proxy.newProxyInstance(
                MontoyaObjectFactory.class.getClassLoader(), new Class[]{MontoyaObjectFactory.class}, (p,m,a) -> {
                    if (m.getName().equals("byteArray") && a[0] instanceof byte[] bytes) return bytes(bytes);
                    if (previous != null) return m.invoke(previous, a);
                    throw new UnsupportedOperationException("Unexpected offline factory call: " + m.getName());
                });
    }

    public void afterEach(ExtensionContext context) { ObjectFactoryLocator.FACTORY = previous; }

    static ByteArray bytes(byte[] source) {
        byte[] value = source.clone();
        return (ByteArray) Proxy.newProxyInstance(ByteArray.class.getClassLoader(), new Class[]{ByteArray.class}, (p,m,a) -> switch (m.getName()) {
            case "getBytes" -> value.clone();
            case "length" -> value.length;
            case "toString" -> new String(value, StandardCharsets.ISO_8859_1);
            default -> throw new UnsupportedOperationException(m.getName());
        });
    }

    static String text(Object body) {
        return body instanceof ByteArray bytes ? new String(bytes.getBytes(), StandardCharsets.UTF_8) : (String) body;
    }
}
