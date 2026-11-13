package com.universal.crypto.burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class UniversalCryptoExtensionTest {

    @Test void initializationFailureNeverInstallsAMockCryptoClient() throws Exception {
        var client=UniversalCryptoExtension.createApiClient(()->{throw new IllegalArgumentException("invalid timeout");});
        org.junit.jupiter.api.Assertions.assertNull(client);
        assertInternalAvailableAndExternalRejected(client);
    }

    @Test void unavailableExternalClientDoesNotDisableRealInternalAlgorithms() throws Exception {
        assertInternalAvailableAndExternalRejected(new com.universal.crypto.processor.impl.CryptoProcessor.ApiClient() {
            public boolean isAvailable() { return false; }
            public com.universal.crypto.processor.impl.CryptoProcessor.ApiResponse processRequest(com.universal.crypto.processor.impl.CryptoProcessor.ApiRequest request) {
                throw new AssertionError("Unavailable service must never be called");
            }
        });
    }

    private void assertInternalAvailableAndExternalRejected(com.universal.crypto.processor.impl.CryptoProcessor.ApiClient client) throws Exception {
        var processors=com.universal.crypto.processor.ProcessorFactory.createDefaultProcessorManager(client);
        var context=com.universal.crypto.processor.ProcessorContext.builder().build();
        var encode=new com.universal.crypto.model.ProcessingAction("encrypt","body","crypto");
        encode.setConfig(java.util.Map.of("algorithm","Base64","keySource","none","cryptoProvider","internal"));
        org.junit.jupiter.api.Assertions.assertEquals("aGVsbG8=",processors.process(encode,"hello",context).getProcessedContent());
        var sign=new com.universal.crypto.model.ProcessingAction("sign","header","signature");sign.setTargetName("X-Sign");
        sign.setConfig(java.util.Map.of("algorithm","HmacSHA256","keySource","static","keyValue","key","cryptoProvider","internal","signContent","body"));
        var mac=javax.crypto.Mac.getInstance("HmacSHA256");mac.init(new javax.crypto.spec.SecretKeySpec("key".getBytes(java.nio.charset.StandardCharsets.UTF_8),"HmacSHA256"));
        String expected=java.util.HexFormat.of().formatHex(mac.doFinal("hello".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        org.junit.jupiter.api.Assertions.assertEquals(expected,processors.process(sign,"hello",context).getProcessedContent());
        encode.setConfig(java.util.Map.of("algorithm","AES-CBC","keySource","static","keyValue","key","cryptoProvider","external"));
        var cryptoResult=processors.process(encode,"hello",context);assertFalse(cryptoResult.isSuccess());org.junit.jupiter.api.Assertions.assertTrue(cryptoResult.getErrorMessage().contains("unavailable"));
        sign.setConfig("cryptoProvider","external");
        var signResult=processors.process(sign,"hello",context);assertFalse(signResult.isSuccess());org.junit.jupiter.api.Assertions.assertTrue(signResult.getErrorMessage().contains("unavailable"));
    }

    @Test
    void extensionDescriptionIsGenericAndShowsAuthor() {
        String description = UniversalCryptoExtension.getDescription();

        assertFalse(description.contains("外部密钥查找"));
        assertFalse(description.contains("时间戳 HMAC"));
        assertEquals("Yao", UniversalCryptoExtension.getAuthor());
    }
}
