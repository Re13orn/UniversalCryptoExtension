package com.universal.crypto.processor.impl;

import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.Constants;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.processor.ProcessorResult;
import org.junit.jupiter.api.Test;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class ScriptProcessorTest {

    @Test
    public void testBasicScriptExecution() throws Exception {
        ScriptProcessor processor = new ScriptProcessor();
        
        ProcessingAction action = new ProcessingAction();
        action.setActionType("execute");
        action.setConfig(new HashMap<>());
        action.getConfig().put(Constants.ConfigKey.SCRIPT_CODE, "return 'Hello ' + content;");
        
        ProcessorContext context = ProcessorContext.builder().build();
        ProcessorResult result = processor.process(action, "World", context);
        
        assertTrue(result.isSuccess());
        assertEquals("Hello World", result.getProcessedContent());
    }

    @Test
    public void testHelpersAvailable() throws Exception {
        ScriptProcessor processor = new ScriptProcessor();
        
        ProcessingAction action = new ProcessingAction();
        action.setActionType("execute");
        action.setConfig(new HashMap<>());
        // Test Base64 helper
        action.getConfig().put(Constants.ConfigKey.SCRIPT_CODE, "return Base64.encode(content);");
        
        ProcessorContext context = ProcessorContext.builder().build();
        ProcessorResult result = processor.process(action, "test", context);
        
        assertTrue(result.isSuccess());
        assertEquals("dGVzdA==", result.getProcessedContent()); // Base64("test")
    }

    @Test
    public void testHmacHelperAvailable() throws Exception {
        ScriptProcessor processor = new ScriptProcessor();

        ProcessingAction action = new ProcessingAction();
        action.setActionType("execute");
        action.setConfig(new HashMap<>());
        action.getConfig().put(Constants.ConfigKey.SCRIPT_CODE, "return String(Hash.hmacSha256(content, 'secret')).length;");

        ProcessorContext context = ProcessorContext.builder().build();
        ProcessorResult result = processor.process(action, "abc", context);

        assertTrue(result.isSuccess());
        assertEquals("64", result.getProcessedContent());
    }


    @Test
    public void testContextAccess() throws Exception {
        ScriptProcessor processor = new ScriptProcessor();
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "TestAgent");
        
        ProcessorContext context = ProcessorContext.builder()
                .headers(headers)
                .build();
        
        ProcessingAction action = new ProcessingAction();
        action.setActionType("execute");
        action.setConfig(new HashMap<>());
        action.getConfig().put(Constants.ConfigKey.SCRIPT_CODE, "return request.getHeader('User-Agent');");
        
        ProcessorResult result = processor.process(action, "", context);
        
        assertTrue(result.isSuccess());
        assertEquals("TestAgent", result.getProcessedContent());
    }

    @Test
    public void testRequestUrlHelpers() throws Exception {
        ScriptProcessor processor = new ScriptProcessor();

        ProcessingAction action = new ProcessingAction();
        action.setActionType("execute");
        action.setConfig(new HashMap<>());
        action.getConfig().put(Constants.ConfigKey.SCRIPT_CODE,
                "return request.getHost() + '|' + request.getPath() + '|' + request.getQueryParam('a') + '|' + request.getQuery();");

        ProcessorContext context = ProcessorContext.builder()
                .url(new URL("https://api.example.com/api/order?a=1&b=hello%20world"))
                .build();

        ProcessorResult result = processor.process(action, "", context);

        assertTrue(result.isSuccess());
        assertEquals("api.example.com|/api/order|1|a=1&b=hello%20world", result.getProcessedContent());
    }

    @Test
    public void testScriptCanFallbackForSignAction() throws Exception {
        ScriptProcessor processor = new ScriptProcessor();

        ProcessingAction action = new ProcessingAction();
        action.setActionType(Constants.ActionType.SIGN);
        action.setConfig(new HashMap<>());
        action.getConfig().put(Constants.ConfigKey.SCRIPT_CODE, "return Hash.sha256(content);");

        ProcessorContext context = ProcessorContext.builder().build();
        ProcessorResult result = processor.process(action, "abc", context);

        assertTrue(result.isSuccess());
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", result.getProcessedContent());
    }

    @Test
    public void testInfiniteLoopTimeout() {
        ScriptProcessor processor = new ScriptProcessor();
        
        ProcessingAction action = new ProcessingAction();
        action.setActionType("execute");
        action.setConfig(new HashMap<>());
        // A loop that never ends
        action.getConfig().put(Constants.ConfigKey.SCRIPT_CODE, "while(true) {}");
        
        ProcessorContext context = ProcessorContext.builder().build();
        
        // This should throw an Error or Exception due to timeout
        assertThrows(com.universal.crypto.processor.ProcessorException.class, () -> {
            processor.process(action, "test", context);
        });
    }
}
