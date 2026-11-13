package com.universal.crypto.processor.impl;

import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.Constants.ProcessorType;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.AbstractProcessor;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.processor.ProcessorResult;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.mozilla.javascript.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Processor that executes custom JavaScript using Mozilla Rhino.
 * <p>
 * The script environment exposes the following objects:
 * <ul>
 *     <li><b>content</b>: The input string content (or request body/parameter value).</li>
 *     <li><b>Base64</b>: Helper for Base64 encoding/decoding. Methods: {@code encode(str)}, {@code decode(str)}.</li>
 *     <li><b>Hex</b>: Helper for Hex encoding/decoding. Methods: {@code encode(str)}, {@code decode(str)}.</li>
 *     <li><b>Hash</b>: Helper for digest/HMAC. Methods: {@code md5(str)}, {@code sha256(str)}, {@code sha1(str)}, {@code hmacSha256(data,key)}.</li>
 *     <li><b>request</b>: Access to current request details. Methods: {@code getMethod()}, {@code getUrl()}, {@code getPath()}, {@code getQuery()}, {@code getQueryParam(name)}, {@code getHeaders()}, {@code getHeader(name)}, {@code getOriginalHeader(name)}, {@code getOriginalHeaders()}.</li>
 *     <li><b>ctx</b>: Access to processor context (shared variables). Methods: {@code isRequest()}, {@code getSharedData(key)}, {@code setSharedData(key, val)}.</li>
 * </ul>
 * <p>
 * Scripts may return text or unsigned byte arrays. Null/undefined preserves the message.
 * Java classes are not exposed; helper methods are plain JS functions.
 */
public class ScriptProcessor extends AbstractProcessor {

    private static final int SCRIPT_TIMEOUT_SECONDS = 5;

    // Custom ContextFactory to enforce timeouts
    private static class SafeContextFactory extends ContextFactory {
        @Override
        protected Context makeContext() {
            Context cx = super.makeContext();
            cx.setLanguageVersion(Context.VERSION_ES6);
            cx.setClassShutter(name -> false);
            cx.setInstructionObserverThreshold(10000); // Check every 10k instructions
            return cx;
        }

        @Override
        protected void observeInstructionCount(Context cx, int instructionCount) {
            long startTime = (long) cx.getThreadLocal("startTime");
            long currentTime = System.nanoTime();
            if ((currentTime - startTime) > (SCRIPT_TIMEOUT_SECONDS * 1000000000L)) {
                throw new TimeoutSignal();
            }
        }
    }

    private static final class TimeoutSignal extends Error {}
    public static final class ScriptTimeoutException extends RuntimeException {
        public ScriptTimeoutException() { super("Script execution timed out (> 5s)"); }
    }
    private static final Map<String, Script> compiled = java.util.Collections.synchronizedMap(
            new java.util.LinkedHashMap<String, Script>(128, .75f, true) {
                protected boolean removeEldestEntry(Map.Entry<String, Script> entry) { return size() > 128; }
            });

    public static void validateScript(String code) {
        Context cx = safeFactory.enterContext();
        try { cx.setOptimizationLevel(-1); cx.compileString("(function(){\n" + code + "\n})();", "RuleValidation", 1, null); }
        finally { Context.exit(); }
    }

    private static final SafeContextFactory safeFactory = new SafeContextFactory();

    public static void runSelfTest() {
        try {
            ProcessingAction action = new ProcessingAction();
            action.setActionType("process");
            action.setConfig(new HashMap<>());
            action.getConfig().put(ConfigKey.SCRIPT_CODE, "var key=Crypto.pbkdf2('test',Bytes.utf8('salt'),1000,256); var iv=Bytes.utf8('012345678901'); return Bytes.text(Crypto.aesGcmDecrypt(key,iv,Crypto.aesGcmEncrypt(key,iv,Bytes.utf8(content),null),null));");
            ProcessorResult result = new ScriptProcessor().process(action, "self-test", ProcessorContext.builder().build());
            if (!result.isSuccess() || !"self-test".equals(result.getProcessedContent())) throw new IllegalStateException("Round trip failed");
            com.universal.crypto.util.Logger.getInstance().info("Rhino 1.8.1 crypto self-test passed; Java " + System.getProperty("java.version"));
        } catch (Exception e) { com.universal.crypto.util.Logger.getInstance().error("Script engine self-test failed", e); }
    }

    public ScriptProcessor() {
        super(ProcessorType.SCRIPT, Set.of("process")); // Generic action "process"
    }

    @Override
    public Map<String, String> getRequiredParameters() {
        Map<String, String> params = new HashMap<>();
        params.put(ConfigKey.SCRIPT_CODE, "JavaScript code to execute. The input content is available as variable 'content'.");
        return params;
    }

    @Override
    public boolean canHandle(String actionType) {
        // Script is the final fallback processor. If a rule explicitly selects script,
        // the action name should not prevent it from running.
        return Set.of("process", "execute", "encrypt", "decrypt", "sign", "verify", "replace", "add", "remove").contains(actionType == null ? "" : actionType);
    }

    @Override
    protected boolean validateSpecificConfiguration(ProcessingAction action) {
        String script = getConfigString(action, ConfigKey.SCRIPT_CODE);
        return script != null && !script.trim().isEmpty();
    }

    @Override
    protected ProcessorResult processInternal(ProcessingAction action, String content, ProcessorContext context) throws Exception {
        String scriptCode = getConfigString(action, ConfigKey.SCRIPT_CODE);
        
        Context cx = safeFactory.enterContext();
        cx.putThreadLocal("startTime", System.nanoTime());
        // Force interpreted mode for accurate instruction counting if needed,
        // or -1 for interpreted. 0 is compiled but without optimizations.
        // Rhino docs vary, but usually interpreted mode is safer for strict timeouts.
        cx.setOptimizationLevel(-1); 
        
        try {
            Scriptable scope = cx.initSafeStandardObjects();

            // Inject content
            Object wrappedContent = content;
            ScriptableObject.putProperty(scope, "content", wrappedContent);

            Object rawBody = context == null ? null : context.getBodyBytes();
            ScriptableObject.putProperty(scope, "bodyBytes", toScript(cx, scope, rawBody instanceof byte[] ? rawBody : (content == null ? "" : content).getBytes(StandardCharsets.UTF_8)));

            // Inject helpers
            ScriptableObject.putProperty(scope, "Base64", bridge(cx, scope, new Base64Helper()));
            ScriptableObject.putProperty(scope, "Hex", bridge(cx, scope, new HexHelper()));
            ScriptableObject.putProperty(scope, "Hash", bridge(cx, scope, new HashHelper()));

            // Inject context objects
            ScriptableObject.putProperty(scope, "request", bridge(cx, scope, new RequestHelper(context)));
            ScriptableObject.putProperty(scope, "ctx", bridge(cx, scope, new ContextHelper(context)));

            
            ScriptableObject.putProperty(scope, "Bytes", bridge(cx, scope, new BytesHelper()));
            ScriptableObject.putProperty(scope, "Crypto", bridge(cx, scope, new CryptoHelper()));

            // Wrap script in a function to allow 'return' statements
            String wrappedScript = "(function() {\n" + scriptCode + "\n})();";
            
            // Execute
            Script script;
            synchronized (compiled) {
                script = compiled.get(scriptCode);
                if (script == null) {
                    script = cx.compileString(wrappedScript, "ScriptAction", 1, null);
                    compiled.put(scriptCode, script);
                }
            }
            Object result = script.exec(cx, scope);
            if (result == null || Undefined.isUndefined(result)) {
                return ProcessorResult.success(content).addMetadata("noChange", "true").build();
            }
            if (result instanceof NativeArray) {
                NativeArray array = (NativeArray) result;
                byte[] bytes = new byte[Math.toIntExact(array.getLength())];
                for (int i = 0; i < bytes.length; i++) {
                    double n = Context.toNumber(array.get(i, array));
                    if (!Double.isFinite(n) || n != Math.rint(n) || n < 0 || n > 255) throw new IllegalArgumentException("Invalid byte value");
                    bytes[i] = (byte) ((int) n);
                }
                return ProcessorResult.success(new String(bytes, StandardCharsets.UTF_8)).processedBytes(bytes).addMetadata("engine", "rhino").build();
            }
            if (result instanceof Scriptable) throw new IllegalArgumentException("Script must return text; encode byte arrays with Bytes.toBase64 or Bytes.text");
            
            String resultStr = Context.toString(result);
            return ProcessorResult.success(resultStr)
                    .addMetadata("engine", "rhino")
                    .build();

        } catch (TimeoutSignal timeout) {
            throw new ScriptTimeoutException();
        } finally {
            Context.exit();
        }
    }
    
    // Only declared helper methods cross the boundary. No Java object or Class is exposed.
    private static Scriptable bridge(Context cx, Scriptable scope, Object helper) {
        Scriptable object = cx.newObject(scope);
        for (java.lang.reflect.Method method : helper.getClass().getDeclaredMethods()) {
            if (!java.lang.reflect.Modifier.isPublic(method.getModifiers())) continue;
            BaseFunction function = new BaseFunction(scope, ScriptableObject.getFunctionPrototype(scope)) {
                public Object call(Context c, Scriptable sc, Scriptable self, Object[] args) {
                    try {
                        Class<?>[] types = method.getParameterTypes();
                        if (args.length != types.length) throw new IllegalArgumentException("Expected " + types.length + " arguments");
                        Object[] values = new Object[args.length];
                        for (int i = 0; i < args.length; i++) {
                            if (types[i] == byte[].class) {
                                if (args[i] == null || Undefined.isUndefined(args[i])) { values[i] = null; continue; }
                                if (!(args[i] instanceof NativeArray)) throw new IllegalArgumentException("Expected unsigned byte array");
                                NativeArray a = (NativeArray) args[i];
                                byte[] b = new byte[Math.toIntExact(a.getLength())];
                                for (int j = 0; j < b.length; j++) {
                                    double n = Context.toNumber(a.get(j, a));
                                    if (!Double.isFinite(n) || n != Math.rint(n) || n < 0 || n > 255) throw new IllegalArgumentException("Invalid byte value");
                                    b[j] = (byte) ((int) n);
                                }
                                values[i] = b;
                            } else values[i] = Context.jsToJava(args[i], types[i]);
                        }
                        return toScript(c, scope, method.invoke(helper, values));
                    } catch (java.lang.reflect.InvocationTargetException e) {
                        throw Context.throwAsScriptRuntimeEx(e.getCause());
                    } catch (Exception e) { throw Context.throwAsScriptRuntimeEx(e); }
                }
            };
            ScriptableObject.putProperty(object, method.getName(), function);
        }
        return object;
    }

    private static Object toScript(Context cx, Scriptable scope, Object value) {
        if (value instanceof byte[]) {
            byte[] bytes = (byte[]) value;
            Object[] array = new Object[bytes.length];
            for (int i = 0; i < bytes.length; i++) array[i] = bytes[i] & 255;
            return cx.newArray(scope, array);
        }
        if (value instanceof Map) {
            NativeObject object = new NativeObject() {
                public Object get(String name, Scriptable start) {
                    Object found = super.get(name, start);
                    if (found != NOT_FOUND) return found;
                    for (Object id : getIds()) if (id instanceof String && name.equalsIgnoreCase((String) id)) return super.get((String) id, start);
                    return NOT_FOUND;
                }
            };
            object.setParentScope(scope);
            object.setPrototype(ScriptableObject.getObjectPrototype(scope));
            ((Map<?, ?>) value).forEach((k, v) -> object.put(k.toString(), object, toScript(cx, scope, v)));
            object.sealObject();
            return object;
        }
        if (value == null || value instanceof String || value instanceof Number || value instanceof Boolean || value instanceof Scriptable) return value;
        throw new IllegalArgumentException("Unsupported shared value type");
    }

    public static class BytesHelper {
        public byte[] utf8(String text) { return text.getBytes(StandardCharsets.UTF_8); }
        public String text(byte[] bytes) { return new String(bytes, StandardCharsets.UTF_8); }
        public String toBase64(byte[] bytes) { return java.util.Base64.getEncoder().encodeToString(bytes); }
        public byte[] fromBase64(String text) { return java.util.Base64.getDecoder().decode(text); }
        public byte[] concat(byte[] a, byte[] b) {
            byte[] out = java.util.Arrays.copyOf(a, Math.addExact(a.length, b.length));
            System.arraycopy(b, 0, out, a.length, b.length); return out;
        }
        public byte[] slice(byte[] bytes, int off, int len) {
            java.util.Objects.checkFromIndexSize(off, len, bytes.length);
            return java.util.Arrays.copyOfRange(bytes, off, off + len);
        }
    }

    public static class CryptoHelper {
        public byte[] pbkdf2(String password, byte[] salt, int iterations, int bits) throws Exception {
            if (iterations < 1 || iterations > 1000000 || bits < 8 || bits > 4096 || bits % 8 != 0) throw new IllegalArgumentException("Invalid PBKDF2 parameters");
            javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, iterations, bits);
            try { return javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(); }
            finally { spec.clearPassword(); }
        }
        public byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key, "HmacSHA256")); return mac.doFinal(data);
        }
        public byte[] aesGcmEncrypt(byte[] key, byte[] iv, byte[] plaintext, byte[] aad) throws Exception { return gcm(javax.crypto.Cipher.ENCRYPT_MODE, key, iv, plaintext, aad); }
        public byte[] aesGcmDecrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] aad) throws Exception { return gcm(javax.crypto.Cipher.DECRYPT_MODE, key, iv, ciphertext, aad); }
        private byte[] gcm(int mode, byte[] key, byte[] iv, byte[] data, byte[] aad) throws Exception {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new javax.crypto.spec.GCMParameterSpec(128, iv));
            if (aad != null) cipher.updateAAD(aad); return cipher.doFinal(data);
        }
        public byte[] randomBytes(int n) {
            if (n < 0 || n > 1048576) throw new IllegalArgumentException("Invalid byte count");
            byte[] bytes = new byte[n]; new java.security.SecureRandom().nextBytes(bytes); return bytes;
        }
    }

    // Helpers exposed to JS
    public static class Base64Helper {
        public byte[] decodeBytes(String data) { return java.util.Base64.getDecoder().decode(data); }
        public String encodeBytes(byte[] data) { return java.util.Base64.getEncoder().encodeToString(data); }
        public String encode(String data) {
            return Base64.encodeBase64String(data.getBytes(StandardCharsets.UTF_8));
        }
        public String decode(String data) {
            return new String(Base64.decodeBase64(data), StandardCharsets.UTF_8);
        }
    }

    public static class HexHelper {
        public String encode(String data) {
            return Hex.encodeHexString(data.getBytes(StandardCharsets.UTF_8));
        }
        public String decode(String data) throws Exception {
            return new String(Hex.decodeHex(data), StandardCharsets.UTF_8);
        }
    }

    public static class HashHelper {
        public String md5(String data) { return DigestUtils.md5Hex(data); }
        public String sha256(String data) { return DigestUtils.sha256Hex(data); }
        public String sha1(String data) { return DigestUtils.sha1Hex(data); }
        public String hmacSha1(String data, String key) throws Exception { return hmacHex("HmacSHA1", data, key); }
        public String hmacSha256(String data, String key) throws Exception { return hmacHex("HmacSHA256", data, key); }
        public String hmacSha512(String data, String key) throws Exception { return hmacHex("HmacSHA512", data, key); }
        public String hmacSha256Base64(String data, String key) throws Exception {
            return Base64.encodeBase64String(hmacBytes("HmacSHA256", data, key));
        }

        private String hmacHex(String algorithm, String data, String key) throws Exception {
            return Hex.encodeHexString(hmacBytes(algorithm, data, key));
        }

        private byte[] hmacBytes(String algorithm, String data, String key) throws Exception {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(nullToEmpty(key).getBytes(StandardCharsets.UTF_8), algorithm));
            return mac.doFinal(nullToEmpty(data).getBytes(StandardCharsets.UTF_8));
        }

        private String nullToEmpty(String value) {
            return value == null ? "" : value;
        }
    }

    public static class RequestHelper {
        private final ProcessorContext context;

        public RequestHelper(ProcessorContext context) {
            this.context = context;
        }

        public String getMethod() {
            return context != null && context.getMethod() != null ? context.getMethod() : "";
        }

        public String getUrl() {
            return context != null && context.getUrl() != null ? context.getUrl().toString() : "";
        }

        public String getPath() {
            return context != null && context.getPath() != null ? context.getPath() : "";
        }

        public String getQuery() {
            return context != null && context.getUrl() != null && context.getUrl().getQuery() != null
                    ? context.getUrl().getQuery()
                    : "";
        }

        public String getQueryParam(String name) {
            if (name == null || name.isEmpty()) {
                return "";
            }
            String query = getQuery();
            if (query.isEmpty()) {
                return "";
            }
            for (String pair : query.split("&")) {
                int idx = pair.indexOf('=');
                String rawKey = idx >= 0 ? pair.substring(0, idx) : pair;
                String rawValue = idx >= 0 ? pair.substring(idx + 1) : "";
                if (name.equals(urlDecode(rawKey))) {
                    return urlDecode(rawValue);
                }
            }
            return "";
        }

        public String getHost() {
            return context != null && context.getHost() != null ? context.getHost() : "";
        }

        public Map<String, String> getHeaders() {
            return context != null ? context.getHeaders() : Map.of();
        }

        public String getHeader(String name) {
            String value = context != null ? context.getHeader(name) : null;
            return value != null ? value : "";
        }

        public Map<String, String> getOriginalHeaders() {
            return context != null ? context.getOriginalHeaders() : Map.of();
        }

        public String getOriginalHeader(String name) {
            String value = context != null ? context.getOriginalHeader(name) : null;
            return value != null ? value : "";
        }

        private String urlDecode(String value) {
            try {
                return URLDecoder.decode(value, StandardCharsets.UTF_8);
            } catch (Exception e) {
                return value;
            }
        }
    }

    public static class ContextHelper {
        private final ProcessorContext context;

        public ContextHelper(ProcessorContext context) {
            this.context = context;
        }

        public boolean isRequest() {
            return context.isRequest();
        }

        public Object getSharedData(String key) {
            return context.getSharedData(key);
        }
        
        public void setSharedData(String key, Object value) {
            context.setSharedData(key, value);
        }
    }
}
