package com.universal.crypto.processor.impl;

import com.universal.crypto.model.*;
import com.universal.crypto.processor.*;
import org.junit.jupiter.api.Test;
import java.util.HashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class ScriptSafetyRegressionTest {
    private ProcessorResult execute(String script, ProcessorContext context) throws ProcessorException {
        ProcessingAction action = new ProcessingAction();
        action.setActionType("process");
        action.setConfig(new HashMap<>());
        action.getConfig().put(Constants.ConfigKey.SCRIPT_CODE, script);
        return new ScriptProcessor().process(action, "original", context);
    }
    private ProcessorResult execute(String script) throws ProcessorException { return execute(script, ProcessorContext.builder().build()); }
    @Test void absentReturnPreservesInput() throws Exception {
        for (String code : new String[]{"var x = 1;", "return undefined;", "return null;"}) {
            ProcessorResult result = execute(code);
            assertEquals("original", result.getProcessedContent());
            assertEquals("true", result.getMetadata().get("noChange"));
        }
    }
    @Test void binaryBase64IsLossless() throws Exception {
        String encoded = "rVwmCclwt4i6Cgktfhyol44iVXq6bfG8kZm+VIrTIt0=";
        assertEquals(encoded, execute("return Base64.encodeBytes(Base64.decodeBytes('" + encoded + "')); ").getProcessedContent());
    }
    @Test void cryptoRoundtripAndAuthentication() throws Exception {
        String prefix = "var k=Crypto.pbkdf2('password',Bytes.utf8('salt'),1,256);var iv=Bytes.utf8('012345678901');var aad=Bytes.utf8('header');var c=Crypto.aesGcmEncrypt(k,iv,Bytes.utf8(content),aad);";
        assertEquals("original", execute(prefix + "return Bytes.text(Crypto.aesGcmDecrypt(k,iv,c,aad));").getProcessedContent());
        assertThrows(ProcessorException.class, () -> execute(prefix + "c[0]^=1;return Bytes.text(Crypto.aesGcmDecrypt(k,iv,c,aad));"));
        assertEquals("Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs=", execute("return Bytes.toBase64(Crypto.pbkdf2('password',Bytes.utf8('salt'),1,256));").getProcessedContent());
    }
    @Test void javaAndReflectionAreInaccessible() throws Exception {
        assertEquals("undefined|undefined|undefined", execute("return typeof Packages+'|'+typeof java+'|'+typeof request.getClass;").getProcessedContent());
        assertThrows(ProcessorException.class, () -> execute("return Packages.java.nio.file.Files.readAllBytes('x');"));
        assertThrows(ProcessorException.class, () -> execute("return request.getClass().forName('java.lang.Runtime');"));
    }
    @Test void timeoutCannotBeSwallowedByScript() {
        assertThrows(ProcessorException.class, () -> execute("try { while(true){} } catch(e) { return 'swallowed'; }"));
    }
    @Test void freshScopeAndCaseInsensitiveHeaders() throws Exception {
        execute("Object.prototype.leak='bad'; return content;");
        assertEquals("undefined", execute("return typeof ({}).leak;").getProcessedContent());
        ProcessorContext context = ProcessorContext.builder().headers(Map.of("Content-Type", "application/json")).build();
        assertEquals("application/json", execute("return request.getHeaders()['content-type'];", context).getProcessedContent());
        assertFalse(new ScriptProcessor().canHandle("sing"));
    }
}
