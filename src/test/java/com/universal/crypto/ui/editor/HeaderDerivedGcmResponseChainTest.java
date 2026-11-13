package com.universal.crypto.ui.editor;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import com.universal.crypto.engine.RuleConfigStorage;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.engine.RuleMatchEngine;
import com.universal.crypto.engine.RuleProcessingService;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleSerializer;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.processor.impl.ScriptProcessor;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.SwingUtilities;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cross-boundary probe for a synthetic header-derived AES-256-GCM response protocol.
 *
 * <p>Unlike the fixture replay harness, this test drives the real
 * {@link PlaintextHttpResponseEditor} write-back chain, so it exercises
 * {@code ActionPipeline.bodyEncryptionApplied()} and
 * {@code EditorMessageSupport.ciphertext()} — the gate that the fixture
 * harness never reaches.
 *
 * <p>All ciphertext verification uses plain JCE, independent of the plugin's
 * Rhino helper surface. The synthetic rule is bundled with the tests, so the importer whitelists are exercised
 * without a user download or vendor deployment file. No deployed vendor compatibility is claimed.
 */
@org.junit.jupiter.api.extension.ExtendWith(MontoyaByteArrayExtension.class)
class HeaderDerivedGcmResponseChainTest {

    // ---- synthetic GCM protocol constants (independent re-implementation) ----
    private static final String METHOD = "POST";
    private static final String PATH = "/api/user/info";
    private static final String HOST = "api.example.test";
    private static final String VERSION = "test-1.0";
    private static final String USER_ID = "u_8871";
    private static final String MACHINE_ID = "machine-abc123";
    private static final String TIMESTAMP = "1791616284";
    private static final String SALT_PREFIX = "uce:test:gcm:v1:";
    private static final int IV_LEN = 12, TAG_LEN = 16, ITERATIONS = 50000, KEY_BITS = 256;

    private static final String RESP_PLAIN =
            "{\"code\":0,\"msg\":\"success\",\"data\":{\"userId\":\"u_8871\",\"expire\":1791616284}}";

    // ---- stubs ----

    @SuppressWarnings("unchecked")
    private static <T> T stub(Class<T> type, Map<String, Object> values) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class[]{type},
                (p, m, a) -> values.get(m.getName())));
    }

    private static HttpHeader header(String name, String value) {
        return stub(HttpHeader.class, Map.of("name", name, "value", value));
    }

    private static HttpResponse response(String body, Map<String, String> headers) {
        return buildResponse(body, new LinkedHashMap<>(headers));
    }

    private static HttpResponse buildResponse(String body, Map<String, String> all) {
        var effective = new LinkedHashMap<>(all);
        effective.put("Content-Length", Integer.toString(body.getBytes(StandardCharsets.UTF_8).length));
        var prefix = new StringBuilder("HTTP/1.1 200 OK\r\n");
        effective.forEach((n, v) -> prefix.append(n).append(": ").append(v).append("\r\n"));
        prefix.append("\r\n");
        var bytes = stub(ByteArray.class, Map.of("getBytes", body.getBytes(StandardCharsets.UTF_8)));
        var raw = stub(ByteArray.class, Map.of("getBytes", (prefix + body).getBytes(StandardCharsets.UTF_8)));
        var values = Map.<String, Object>of(
                "headers", effective.entrySet().stream().map(e -> header(e.getKey(), e.getValue())).toList(),
                "statusCode", (short) 200, "body", bytes, "bodyToString", body, "toByteArray", raw,
                "bodyOffset", prefix.length(), "httpVersion", "HTTP/1.1", "reasonPhrase", "OK");
        return (HttpResponse) Proxy.newProxyInstance(HttpResponse.class.getClassLoader(),
                new Class[]{HttpResponse.class}, (p, m, a) -> {
                    switch (m.getName()) {
                        case "withBody": return buildResponse(MontoyaByteArrayExtension.text(a[0]), all);
                        case "hasHeader":
                            return all.keySet().stream().anyMatch(n -> n.equalsIgnoreCase((String) a[0]));
                        case "withAddedHeader":
                        case "withUpdatedHeader":
                        case "withHeader": {
                            var next = new LinkedHashMap<>(all); next.put((String) a[0], (String) a[1]);
                            return buildResponse(body, next);
                        }
                        case "withRemovedHeader": {
                            var next = new LinkedHashMap<>(all);
                            next.keySet().removeIf(n -> n.equalsIgnoreCase((String) a[0]));
                            return buildResponse(body, next);
                        }
                        default: return values.get(m.getName());
                    }
                });
    }

    private static HttpRequest request(Map<String, String> headers) {
        var values = Map.<String, Object>of(
                "method", METHOD,
                "url", "https://" + HOST + PATH,
                "path", PATH,
                "headers", headers.entrySet().stream().map(e -> header(e.getKey(), e.getValue())).toList());
        return (HttpRequest) Proxy.newProxyInstance(HttpRequest.class.getClassLoader(),
                new Class[]{HttpRequest.class}, (p, m, a) -> values.get(m.getName()));
    }

    private static Map<String, String> requestHeaders() {
        var headers = new LinkedHashMap<String, String>();
        headers.put("X-Encrypt", "true");
        headers.put("X-Version", VERSION);
        headers.put("X-User-Id", USER_ID);
        headers.put("X-Machine-Id", MACHINE_ID);
        headers.put("X-Timestamp", TIMESTAMP);
        return headers;
    }

    // ---- independent JCE implementation of the synthetic GCM envelope ----

    private static byte[] key() throws Exception {
        var password = USER_ID + "_" + MACHINE_ID;
        var salt = (SALT_PREFIX + VERSION + ":" + MACHINE_ID).getBytes(StandardCharsets.UTF_8);
        var spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] aad() {
        return String.join("|", METHOD, PATH, VERSION, USER_ID, MACHINE_ID, TIMESTAMP)
                .getBytes(StandardCharsets.UTF_8);
    }

    /** @return base64(iv[12] || ct || tag[16]) */
    private static String encrypt(String plaintext) throws Exception {
        var iv = new byte[IV_LEN];
        new SecureRandom().nextBytes(iv);
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key(), "AES"), new GCMParameterSpec(128, iv));
        cipher.updateAAD(aad());
        var ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        var out = Arrays.copyOf(iv, IV_LEN + ct.length);
        System.arraycopy(ct, 0, out, IV_LEN, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    private static String decrypt(String envelope) throws Exception {
        var raw = Base64.getDecoder().decode(envelope.replaceAll("\\s+", ""));
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key(), "AES"),
                new GCMParameterSpec(128, Arrays.copyOfRange(raw, 0, IV_LEN)));
        cipher.updateAAD(aad());
        return new String(cipher.doFinal(Arrays.copyOfRange(raw, IV_LEN, raw.length)), StandardCharsets.UTF_8);
    }

    /** Wire length of the re-encrypted body: base64 of iv+ct+tag where |ct| == |plain|. */
    private static int expectedBase64Length(String plaintext) {
        return 4 * (int) Math.ceil((IV_LEN + plaintext.getBytes(StandardCharsets.UTF_8).length + TAG_LEN) / 3.0);
    }

    // ---- harness ----

    private static List<ProcessingRule> importRules() throws Exception {
        try (var input = HeaderDerivedGcmResponseChainTest.class.getResourceAsStream("/protocol/header-derived-gcm.rules.json")) {
            assertNotNull(input, "The synthetic protocol fixture must be present in the checkout");
            return RuleSerializer.importRules(new String(input.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    private static ProcessingRule responseRule(List<ProcessingRule> rules) {
        return rules.stream().filter(r -> r.hasResponseActions() && !r.getResponseActions().isEmpty())
                .findFirst().orElseThrow(() -> new AssertionError("no response rule in file"));
    }

    private static RuleManager manager(ProcessingRule rule) {
        var manager = new RuleManager(new RuleConfigStorage() {
            public List<ProcessingRule> loadRules() { return List.of(); }
            public void saveRules(List<ProcessingRule> rules) { }
        });
        rule.setEnabled(true);
        manager.addRule(rule);
        return manager;
    }

    private static RuleProcessingService service(RuleManager manager) {
        var processors = new ProcessorManager();
        processors.registerProcessor(new ScriptProcessor());
        return new RuleProcessingService(manager, new RuleMatchEngine(), processors);
    }

    private static PlaintextHttpResponseEditor editor(RuleManager manager, HttpRequestResponse pair) {
        return new PlaintextHttpResponseEditor(null, service(manager),
                stub(EditorCreationContext.class, Map.of("editorMode", EditorMode.DEFAULT)),
                prefix -> buildResponse("", Map.of("Content-Type", "application/json")));
    }

    private static String headerValue(HttpResponse response, String name) {
        return response.headers().stream()
                .filter(h -> name.equalsIgnoreCase(h.name()))
                .map(HttpHeader::value).findFirst().orElse(null);
    }

    /**
     * Edits the integer value of {@code "code"} inside the displayed body and returns the
     * resulting plaintext. The text area may pretty-print JSON, so the helper locates the
     * key first and then edits the digit that follows it.
     */
    private static String editCode(PlaintextMessageView view) {
        var text = view.textArea().getText();
        int key = text.indexOf("\"code\"");
        assertTrue(key >= 0, "anchor not found in editor text");
        int at = text.indexOf(':', key) + 1;
        assertTrue(at > 0, "no value after \"code\"");
        while (at < text.length() && Character.isWhitespace(text.charAt(at))) at++;
        assertTrue(at < text.length() && text.charAt(at) == '0',
                "expected a 0 immediately after \"code\": but the text was: " + text);
        view.textArea().replaceRange("5", at, at + 1);
        var edited = view.bodyText();
        assertTrue(edited.replaceAll("\\s+", "").contains("\"code\":5"),
                "edit was not applied to the body: " + edited);
        return edited;
    }

    // ---- tests ----

    @Test
    void syntheticRuleFilePassesTheImporterWhitelists() throws Exception {
        var rules = importRules();
        assertEquals(2, rules.size(), "synthetic fixture must contain the request and response rules");
        for (var rule : rules) {
            assertFalse(rule.isEnabled(), "imported rules must arrive disabled");
            var actions = new ArrayList<ProcessingAction>();
            if (rule.getRequestActions() != null) actions.addAll(rule.getRequestActions());
            if (rule.getResponseActions() != null) actions.addAll(rule.getResponseActions());
            assertFalse(actions.isEmpty(), "rule without actions: " + rule.getName());
            for (var action : actions) {
                assertTrue(List.of("crypto", "signature", "field", "script").contains(action.getProcessor()),
                        "processor not whitelisted: " + action.getProcessor());
                assertTrue(Constants.ExecutionPhase.VALUES.contains(
                                action.getConfigString(Constants.ConfigKey.EXECUTION_PHASE)),
                        "phase not whitelisted: " + action.getConfigString(Constants.ConfigKey.EXECUTION_PHASE));
                assertNotEquals("execute", action.getActionType(),
                        "legacy 'execute' label would disable editor write-back; encrypt must be used");
            }
        }
        var response = responseRule(rules);
        assertEquals(3, response.getResponseActions().size());
        assertEquals("decrypt", response.getResponseActions().get(0).getActionType());
        assertEquals(Constants.ExecutionPhase.RESPONSE_DISPLAY,
                response.getResponseActions().get(0).getConfigString(Constants.ConfigKey.EXECUTION_PHASE));
        assertEquals("encrypt", response.getResponseActions().get(1).getActionType());
        assertEquals(Constants.ExecutionPhase.RESPONSE_EDITOR_SEND,
                response.getResponseActions().get(1).getConfigString(Constants.ConfigKey.EXECUTION_PHASE));
        assertEquals("replace", response.getResponseActions().get(2).getActionType());
    }

    @Test
    void bundledSyntheticRuleFixtureRoundTripsWithoutMachineLocalFiles() throws Exception {
        var imported = importRules();
        var replay = RuleSerializer.importRules(RuleSerializer.exportRules(imported));
        assertEquals(RuleSerializer.toJson(imported), RuleSerializer.toJson(replay));
        assertEquals(2, replay.size());
        replay.forEach(rule -> assertFalse(rule.isEnabled()));
    }

    @Test
    void editedResponseIsReEncryptedAndReframed() throws Exception {
        var rule = responseRule(importRules());
        var manager = manager(rule);
        var original = response(encrypt(RESP_PLAIN), Map.of("Content-Type", "application/json"));
        var pair = stub(HttpRequestResponse.class,
                Map.of("request", request(requestHeaders()), "response", original));

        SwingUtilities.invokeAndWait(() -> {
            try {
                var editor = editor(manager, pair);
                editor.setRequestResponse(pair);
                var view = (PlaintextMessageView) editor.uiComponent();

                assertEquals(RESP_PLAIN, view.bodyText(), "display phase must decrypt the response");
                assertTrue(view.textArea().isEditable(), "an encrypt/body/response-editor-send action must open editing");

                var edited = editCode(view);
                assertNotEquals(RESP_PLAIN, edited);

                var out = editor.getResponse();
                assertNotSame(original, out, "an edited response must not fall back to the original");
                assertTrue(editor.isModified());

                var wire = out.bodyToString();
                var roundTripped = decrypt(wire);
                assertNotEquals(edited, wire, "plaintext must never be written back");
                assertEquals(edited.trim(), roundTripped, "written-back body must be a valid synthetic GCM envelope");

                var declared = headerValue(out, "Content-Length");
                assertEquals(Integer.toString(wire.getBytes(StandardCharsets.UTF_8).length), declared,
                        "Content-Length must match the ciphertext byte length");
                assertEquals(Integer.toString(expectedBase64Length(roundTripped)), declared,
                        "ciphertext base64 length must follow 4*ceil((12+len+16)/3)");
            } catch (Exception error) {
                throw new AssertionError(error);
            }
        });
    }

    @Test
    void legacyExecuteLabelKeepsTheResponseReadOnly() throws Exception {
        var changed = responseRule(importRules()).clone();
        changed.getResponseActions().get(1).setActionType("execute");
        var manager = manager(changed);
        var original = response(encrypt(RESP_PLAIN), Map.of("Content-Type", "application/json"));
        var pair = stub(HttpRequestResponse.class,
                Map.of("request", request(requestHeaders()), "response", original));

        SwingUtilities.invokeAndWait(() -> {
            var editor = editor(manager, pair);
            editor.setRequestResponse(pair);
            var view = (PlaintextMessageView) editor.uiComponent();
            assertFalse(view.textArea().isEditable(), "an 'execute' label must not open editor write-back");
            assertNotNull(view.textArea().getToolTipText());
            assertTrue(view.textArea().getToolTipText().contains("encrypt"),
                    "tooltip should tell the user which label is required");
            assertSame(original, editor.getResponse());
        });
    }

    @Test
    void failClosedPathsRetainOriginalCiphertext() throws Exception {
        var original = response(encrypt(RESP_PLAIN), Map.of("Content-Type", "application/json"));
        var plainRule = responseRule(importRules());
        var nonJsonRule = responseRule(importRules()).clone();
        nonJsonRule.getResponseActions().get(0).setConfig("scriptCode", "return 'not-a-json-body';");
        var envelope = encrypt(RESP_PLAIN);
        var untouched = response(envelope, Map.of("Content-Type", "application/json"));

        // (a) X-Encrypt: false marks the message as plain on the wire, so the rule leaves
        //     BOTH directions alone: the editor shows the raw ciphertext and every
        //     write-back attempt is refused.
        SwingUtilities.invokeAndWait(() -> {
            var headers = requestHeaders();
            headers.put("X-Encrypt", "false");
            var pair = stub(HttpRequestResponse.class,
                    Map.of("request", request(headers), "response", untouched));
            var editor = editor(manager(plainRule), pair);
            editor.setRequestResponse(pair);
            var view = (PlaintextMessageView) editor.uiComponent();
            assertEquals(envelope, view.bodyText(),
                    "X-Encrypt:false must skip decryption and show the ciphertext verbatim");
            assertSame(untouched, editor.getResponse(), "an unedited response must never be rewritten");
            if (!view.textArea().isEditable()) return;
            view.textArea().append("x");
            assertSame(untouched, editor.getResponse(),
                    "X-Encrypt:false must not write anything back even though the editor is offered");
            assertTrue(view.textArea().getToolTipText().contains("original ciphertext retained"),
                    "the refusal must be visible: " + view.textArea().getToolTipText());
        });

        // (b) A non-JSON body fails the rule's shape gate, so the byte comparison must
        //     leave hasBodyEncryption() false and the write-back must be refused.
        SwingUtilities.invokeAndWait(() -> {
            var pair = stub(HttpRequestResponse.class,
                    Map.of("request", request(requestHeaders()), "response", original));
            var editor = editor(manager(nonJsonRule), pair);
            editor.setRequestResponse(pair);
            var view = (PlaintextMessageView) editor.uiComponent();
            assertEquals("not-a-json-body", view.bodyText());
            assertTrue(view.textArea().isEditable(), "the encrypt action still matches, so editing stays open");
            view.textArea().append(" ");
            assertSame(original, editor.getResponse(), "a body the rule refuses must never be written back as plaintext");
            assertTrue(editor.isModified(), "the dirty flag must survive a refused write-back");
            assertNotNull(view.textArea().getToolTipText());
            assertTrue(view.textArea().getToolTipText().contains("original ciphertext retained"),
                    "the failure must be visible in the editor: " + view.textArea().getToolTipText());
        });
    }

    @Test
    void contentLengthActionIsRedundantWithPluginFraming() throws Exception {
        var rule = responseRule(importRules());
        var withoutLengthAction = rule.clone();
        var removed = withoutLengthAction.getResponseActions().removeIf(
                a -> "header".equalsIgnoreCase(a.getTargetType()));
        assertTrue(removed, "the synthetic rule is expected to carry one header action");

        var manager = manager(withoutLengthAction);
        var original = response(encrypt(RESP_PLAIN), Map.of("Content-Type", "application/json"));
        var pair = stub(HttpRequestResponse.class,
                Map.of("request", request(requestHeaders()), "response", original));

        SwingUtilities.invokeAndWait(() -> {
            try {
                var editor = editor(manager, pair);
                editor.setRequestResponse(pair);
                var view = (PlaintextMessageView) editor.uiComponent();
                var edited = editCode(view);
                var out = editor.getResponse();
                assertNotSame(original, out);
                var wire = out.bodyToString();
                var roundTripped = decrypt(wire);
                assertEquals(edited.trim(), roundTripped);
                assertEquals(Integer.toString(expectedBase64Length(roundTripped)), headerValue(out, "Content-Length"),
                        "plugin framing normalization alone must produce the correct Content-Length");
            } catch (Exception error) {
                throw new AssertionError(error);
            }
        });
    }
}
