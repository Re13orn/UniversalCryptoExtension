package com.universal.crypto.model;

/**
 * Constants for processing rules to avoid magic strings
 */
public final class Constants {

    private Constants() {
        // Utility class
    }

    /**
     * Action types for processing actions
     */
    public static final class ActionType {
        public static final String DECRYPT = "decrypt";
        public static final String ENCRYPT = "encrypt";
        public static final String SIGN = "sign";
        public static final String VERIFY = "verify";
        public static final String REPLACE = "replace";
        public static final String ADD = "add";
        public static final String REMOVE = "remove";

        private ActionType() {}
    }

    /**
     * Target types for processing actions
     */
    public static final class TargetType {
        public static final String BODY = "body";
        public static final String HEADER = "header";
        public static final String FIELD = "field";
        public static final String VARIABLE = "variable";

        private TargetType() {}
    }

    /**
     * Processor types for processing actions
     */
    public static final class ProcessorType {
        public static final String CRYPTO = "crypto";
        public static final String SIGNATURE = "signature";
        public static final String FIELD = "field";
        public static final String SCRIPT = "script";

        private ProcessorType() {}
    }

    /**
     * Tool sources for rule conditions
     */
    public static final class ToolSource {
        public static final String PROXY = "PROXY";
        public static final String SCANNER = "SCANNER";
        public static final String INTRUDER = "INTRUDER";
        public static final String REPEATER = "REPEATER";
        public static final String SEQUENCER = "SEQUENCER";
        public static final String DECODER = "DECODER";
        public static final String COMPARER = "COMPARER";
        public static final String EXTENSIONS = "EXTENSIONS";
        public static final String ANY = "ANY";

        private ToolSource() {}
    }

    /**
     * HTTP methods commonly used in rules
     */
    public static final class HttpMethod {
        public static final String GET = "GET";
        public static final String POST = "POST";
        public static final String PUT = "PUT";
        public static final String DELETE = "DELETE";
        public static final String PATCH = "PATCH";
        public static final String HEAD = "HEAD";
        public static final String OPTIONS = "OPTIONS";

        private HttpMethod() {}
    }

    /**
     * Common content types
     */
    public static final class ContentType {
        public static final String APPLICATION_JSON = "application/json";
        public static final String APPLICATION_XML = "application/xml";
        public static final String APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded";
        public static final String MULTIPART_FORM_DATA = "multipart/form-data";
        public static final String TEXT_PLAIN = "text/plain";

        private ContentType() {}
    }

    /**
     * Configuration keys for crypto operations
     */
    public static final class ConfigKey {
        public static final String ALGORITHM = "algorithm";
        public static final String KEY_SOURCE = "keySource";
        public static final String KEY_VALUE = "keyValue";
        public static final String LOOKUP_METHOD = "lookupMethod";
        public static final String LOOKUP_ENDPOINT = "lookupEndpoint";
        public static final String INPUT_SOURCE = "inputSource";
        public static final String EDITOR_ONLY = "editorOnly";
        public static final String RESPONSE_KEY_PATH = "responseKeyPath";
        public static final String FALLBACK_LOOKUP = "fallbackLookup";
        public static final String SIGN_CONTENT = "signContent";
        public static final String TIMESTAMP_HEADER = "timestampHeader";
        public static final String CRYPTO_PROVIDER = "cryptoProvider";
        public static final String KEY_FORMAT = "keyFormat";
        public static final String PAYLOAD_FORMAT = "payloadFormat";
        public static final String CIPHER_FIELD = "cipherField";
        public static final String PLAIN_FIELD = "plainField";
        public static final String IV_FIELD = "ivField";
        public static final String IV_LITERAL_VALUE = "ivLiteralValue";
        public static final String IV_FORMAT = "ivFormat";
        public static final String CIPHER_FORMAT = "cipherFormat";
        public static final String PLAIN_FORMAT = "plainFormat";
        public static final String CHARSET = "charset";
        public static final String AES_MODE = "aesMode";
        public static final String PADDING = "padding";
        public static final String GCM_TAG_LENGTH = "gcmTagLength";
        public static final String RSA_PUBLIC_KEY = "rsaPublicKey";
        public static final String RSA_PRIVATE_KEY = "rsaPrivateKey";
        public static final String RSA_PADDING = "rsaPadding";
        public static final String RSA_MODE = "rsaMode";
        // External API customization
        public static final String API_REQUEST_TEMPLATE = "apiRequestTemplate";
        public static final String API_RESPONSE_PATH = "apiResponsePath";
        public static final String API_FIELD_MAP = "apiFieldMap";
        public static final String API_HEADERS = "apiHeaders";
        public static final String API_CONTENT_TYPE = "apiContentType";
        public static final String LOOKUP_HTTP_METHOD = "lookupHttpMethod";
        // Per-action external endpoint/method overrides
        public static final String ENCRYPT_ENDPOINT = "encryptEndpoint";
        public static final String ENCRYPT_METHOD = "encryptMethod";
        public static final String DECRYPT_ENDPOINT = "decryptEndpoint";
        public static final String DECRYPT_METHOD = "decryptMethod";
        public static final String SIGN_ENDPOINT = "signEndpoint";
        public static final String SIGN_METHOD = "signMethod";
        public static final String VERIFY_ENDPOINT = "verifyEndpoint";
        public static final String VERIFY_METHOD = "verifyMethod";
        public static final String OPERATION = "operation";
        public static final String FIELD_PATH = "fieldPath";
        public static final String FROM = "from";
        public static final String TO = "to";
        public static final String EXECUTION_PHASE = "executionPhase";
        public static final String MAX_CONTENT_LENGTH = "maxContentLength";
        public static final String EXPECTED_SIGNATURE = "expectedSignature";
        public static final String SIGNATURE_HEADER = "signatureHeader";
        public static final String SIGNATURE_SOURCE = "signatureSource";
        public static final String SIGNATURE_FIELD_PATH = "signatureFieldPath";
        public static final String SIGNATURE_QUERY_PARAM = "signatureQueryParam";
        public static final String CUSTOM_SIGN_TEMPLATE = "customSignTemplate";
        public static final String TIMESTAMP_FORMAT = "timestampFormat";
        public static final String OVERWRITE = "overwrite";
        public static final String IGNORE_NOT_FOUND = "ignoreNotFound";
        
        // Canonicalization
        public static final String SORT_KEYS = "sortKeys";
        public static final String PAIR_SEPARATOR = "pairSeparator";
        public static final String KV_SEPARATOR = "kvSeparator";
        public static final String URL_ENCODE_VALUES = "urlEncodeValues";
        public static final String HASH_KEY_PLACEMENT = "hashKeyPlacement";
        public static final String SIGNATURE_HEX_CASE = "signatureHexCase";
        public static final String HEADER_TEMPLATES = "headerTemplates";
        
        // Scripting
        public static final String SCRIPT_CODE = "scriptCode";
        public static final String SCRIPT_ENGINE = "scriptEngine";

        // Variable Pipeline
        public static final String INPUT_NAME = "inputName";
        public static final String VARIABLE_NAME = "variableName"; // For naming the output variable

        private ConfigKey() {}
    }

    /**
     * Execution phases control when processing actions run.
     * Values are comma-separated tokens to allow multiple phases (e.g., "display,send").
     */
    public static final class ExecutionPhase {
        public static final String DISPLAY = "display";
        public static final String SEND = "send";
        public static final String RESPONSE_DISPLAY = "response-display";
        public static final String RESPONSE_SEND = "response-send";
        public static final String RESPONSE_EDITOR_SEND = "response-editor-send";
        public static final String EDITOR_SEND = "editor-send";
        public static final String ALWAYS = "always";

        public static final java.util.Set<String> VALUES = java.util.Set.of(
                DISPLAY, SEND, RESPONSE_DISPLAY, RESPONSE_SEND, EDITOR_SEND, RESPONSE_EDITOR_SEND, ALWAYS);

        public static boolean matches(String configured, String required, String fallback) {
            String value = configured == null || configured.isBlank() ? fallback : configured;
            String phase = required == null ? fallback : required.toLowerCase(java.util.Locale.ROOT);
            return java.util.Arrays.stream(value.split(",")).map(String::trim)
                    .map(token -> token.toLowerCase(java.util.Locale.ROOT))
                    .anyMatch(token -> token.equals(phase) || (token.equals(ALWAYS) && !RESPONSE_EDITOR_SEND.equals(phase)));
        }

        private ExecutionPhase() {}
    }

    /**
     * Key source types
     */
    public static final class KeySource {
        public static final String STATIC = "static";
        public static final String LOOKUP = "lookup";
        public static final String CACHED = "cached";

        private KeySource() {}
    }

    /**
     * Algorithms
     */
    public static final class Algorithm {
        public static final String AES_GCM = "aes-gcm";
        public static final String AES_256 = "aes-256";
        public static final String HMAC_SHA256 = "hmac-sha256";

        private Algorithm() {}
    }

    /**
     * Lookup methods
     */
    public static final class LookupMethod {
        public static final String MD5_HASH = "md5-hash";

        private LookupMethod() {}
    }

    /**
     * Input sources
     */
    public static final class InputSource {
        public static final String REQUEST_BODY = "request-body";
        public static final String RESPONSE_BODY = "response-body";
        public static final String HEADER = "header";
        public static final String VARIABLE = "variable";

        private InputSource() {}
    }


}
