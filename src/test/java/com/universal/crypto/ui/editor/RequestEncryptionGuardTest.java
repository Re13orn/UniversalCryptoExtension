package com.universal.crypto.ui.editor;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.extension.*;
import com.universal.crypto.engine.*;
import com.universal.crypto.model.*;
import com.universal.crypto.processor.ProcessorFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.SwingUtilities;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

@org.junit.jupiter.api.extension.ExtendWith(MontoyaByteArrayExtension.class)
class RequestEncryptionGuardTest {
    @TempDir Path temp;
    private static final String PREFIX="POST /demo HTTP/1.1\r\nHost: example.test\r\n\r\n";
    private <T> T stub(Class<T> type,Map<String,Object> values) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(),new Class[]{type},(p,m,a)->values.get(m.getName())));
    }
    private HttpRequest request(String body) {
        var bytes=stub(ByteArray.class,Map.of("getBytes",(PREFIX+body).getBytes(StandardCharsets.ISO_8859_1)));
        var service=stub(HttpService.class,Map.of("secure",true,"host","example.test","port",443));
        var values=Map.<String,Object>of("method","POST","url","https://example.test/demo","path","/demo","httpService",service,
                "headers",List.of(),"bodyToString",body,"toByteArray",bytes,"bodyOffset",PREFIX.length());
        return (HttpRequest)Proxy.newProxyInstance(HttpRequest.class.getClassLoader(),new Class[]{HttpRequest.class},
                (p,m,a)->m.getName().equals("withBody") ? request(MontoyaByteArrayExtension.text(a[0])) : values.get(m.getName()));
    }
    private ProcessingRule rule(ProcessingAction encryption) {
        var rule=new ProcessingRule("guard","Guard",true,1);rule.setCondition(new RuleCondition());
        var display=new ProcessingAction("decrypt","body","script");
        display.setConfig(Map.of("executionPhase","display","scriptCode","return '{\"value\":1}';"));rule.addRequestAction(display);
        if(encryption!=null)rule.addRequestAction(encryption);return rule;
    }
    private ProcessingAction encrypt(String code) {
        var action=new ProcessingAction("encrypt","body","script");action.setConfig(Map.of("executionPhase","editor-send","scriptCode",code));return action;
    }
    private RuleManager manager(ProcessingRule rule) {
        var manager=new RuleManager(new RuleConfigStorage(temp.toString()));manager.addRule(rule);return manager;
    }
    private PlaintextHttpRequestEditor editor(RuleManager manager,HttpRequest original,EditorMode mode) {
        var editor=new PlaintextHttpRequestEditor(null,new RuleProcessingService(manager,new RuleMatchEngine(),ProcessorFactory.createDefaultProcessorManager(null)),
                stub(EditorCreationContext.class,mode==null?Map.of():Map.of("editorMode",mode)));
        editor.setRequestResponse(stub(HttpRequestResponse.class,Map.of("request",original)));return editor;
    }
    @Test void displayOnlyRuleCannotWriteEditedPlaintextBack() throws Exception {
        var manager=manager(rule(null));var original=request("ciphertext");
        SwingUtilities.invokeAndWait(()->{
            var editor=editor(manager,original,null);var view=(PlaintextMessageView)editor.uiComponent();
            assertFalse(view.textArea().isEditable());assertTrue(view.textArea().getToolTipText().contains("editor-send"));
            view.textArea().append(" programmatic edit");assertSame(original,editor.getRequest());assertFalse(editor.isModified());
        });
    }
    @Test void noChangeEncryptionCannotWritePlaintextBack() throws Exception {
        var manager=manager(rule(encrypt("return null;")));var original=request("ciphertext");
        SwingUtilities.invokeAndWait(()->{
            var editor=editor(manager,original,null);var view=(PlaintextMessageView)editor.uiComponent();assertTrue(view.textArea().isEditable());
            int at=view.textArea().getText().lastIndexOf('1');view.textArea().replaceRange("2",at,at+1);
            assertSame(original,editor.getRequest());assertTrue(editor.isModified());
            assertTrue(view.textArea().getToolTipText().contains("No body encryption"));
        });
    }
    @Test void preparedCiphertextIsInvalidatedAfterRuleUpdateAndRuleRemoval() throws Exception {
        var encryption=new ProcessingAction("encrypt","body","crypto");
        encryption.setConfig(Map.of("algorithm","Hex","keySource","none","cryptoProvider","internal","executionPhase","editor-send"));
        var rule=rule(encryption);var manager=manager(rule);var original=request("ciphertext");
        SwingUtilities.invokeAndWait(()->{
            var editor=editor(manager,original,null);var view=(PlaintextMessageView)editor.uiComponent();
            int at=view.textArea().getText().lastIndexOf('1');view.textArea().replaceRange("2",at,at+1);
            String plaintext=view.bodyText();var first=editor.getRequest();
            assertEquals(HexFormat.of().formatHex(plaintext.getBytes(StandardCharsets.UTF_8)),first.bodyToString());assertSame(first,editor.getRequest());
            manager.setRuleEnabled(rule.getId(),false);assertSame(original,editor.getRequest());assertTrue(editor.isModified());
            manager.setRuleEnabled(rule.getId(),true);var reenabled=editor.getRequest();assertNotSame(first,reenabled);assertEquals(first.bodyToString(),reenabled.bodyToString());
            var changed=rule.clone();changed.getRequestActions().get(1).setConfig("algorithm","Base64");manager.updateRule(changed);
            var second=editor.getRequest();assertNotSame(first,second);assertEquals(Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8)),second.bodyToString());
            manager.removeRule(rule.getId());assertSame(original,editor.getRequest());assertTrue(editor.isModified());
        });
    }
    @Test void readOnlyModeCannotBeBypassedByProgrammaticDocumentChange() throws Exception {
        var manager=manager(rule(encrypt("return 'encrypted:'+content;")));var original=request("ciphertext");
        SwingUtilities.invokeAndWait(()->{
            var editor=editor(manager,original,EditorMode.READ_ONLY);var view=(PlaintextMessageView)editor.uiComponent();
            view.textArea().append(" edited");assertFalse(view.textArea().isEditable());assertFalse(editor.isModified());assertSame(original,editor.getRequest());
        });
    }
}
