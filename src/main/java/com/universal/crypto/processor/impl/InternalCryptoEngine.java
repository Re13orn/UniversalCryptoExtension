package com.universal.crypto.processor.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorException;
import com.universal.crypto.util.LanguageManager;
import com.universal.crypto.util.BouncyCastleSupport;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Internal crypto engine providing built-in AES/DES/3DES/RSA/SM2/SM4/Hash/codec helpers.
 */
public final class InternalCryptoEngine {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    


    private enum FieldSpecType {
        DIRECT,
        REGEX
    }

    private static class FieldSpec {
        final FieldSpecType type;
        final String raw;
        final Pattern pattern;

        FieldSpec(FieldSpecType type, String raw, Pattern pattern) {
            this.type = type;
            this.raw = raw;
            this.pattern = pattern;
        }
    }

    private record FieldResult(String fieldName, String value) {
    }

    private static class IvInfo {
        final byte[] bytes;
        final String fieldName;
        final String encodedValue;

        IvInfo(byte[] bytes, String fieldName, String encodedValue) {
            this.bytes = bytes;
            this.fieldName = fieldName;
            this.encodedValue = encodedValue;
        }
    }

    private InternalCryptoEngine() {
    }

    public static InternalResult process(ProcessingAction action,
                                         String actionType,
                                         String inputContent,
                                         String key) throws ProcessorException {

        String algorithm = getConfigString(action, Constants.ConfigKey.ALGORITHM);
        if (algorithm == null || algorithm.isBlank()) {
            throw new ProcessorException(LanguageManager.getInstance().getString("error.engine.algorithm_required"));
        }

        String normalized = algorithm.trim().toLowerCase(Locale.ROOT);
        
        // Handle Hash algorithms (MD5, SHA, SM3)
        if (isHashAlgorithm(normalized)) {
            return handleHash(action, normalized, inputContent);
        }

        return switch (normalized) {
            case "aes-gcm", "aes-cbc", "aes-ecb", "aes" ->
                    handleSymmetric(action, actionType, inputContent, key, "AES", normalized);
            case "des-cbc", "des-ecb", "des" ->
                    handleSymmetric(action, actionType, inputContent, key, "DES", normalized);
            case "3des-cbc", "3des-ecb", "3des", "triple-des", "desede", "desede-cbc", "desede-ecb" ->
                    handleSymmetric(action, actionType, inputContent, key, "DESede", normalized);
            case "sm4-cbc", "sm4-ecb", "sm4" ->
                    handleSymmetric(action, actionType, inputContent, key, "SM4", normalized);
            case "base64", "base64-encode", "base64-decode" ->
                    handleCodec(action, actionType, inputContent, normalized, Codec.BASE64);
            case "hex", "hex-encode", "hex-decode" ->
                    handleCodec(action, actionType, inputContent, normalized, Codec.HEX);
            case "url", "url-encode", "url-decode", "urlencode", "urldecode" ->
                    handleCodec(action, actionType, inputContent, normalized, Codec.URL);
            case "rsa", "rsa-ecb", "rsa-oaep" ->
                    handleAsymmetric(action, actionType, inputContent, key, "RSA");
            case "sm2" ->
                    handleAsymmetric(action, actionType, inputContent, key, "SM2");
            default -> {
                String msg = java.text.MessageFormat.format(LanguageManager.getInstance().getString("error.engine.unsupported_algorithm"), algorithm);
                throw new ProcessorException(msg);
            }
        };
    }
    
    private static boolean isHashAlgorithm(String algo) {
        return Set.of("md5", "sha1", "sha-1", "sha256", "sha-256", "sha512", "sha-512", "sm3").contains(algo);
    }

    private static InternalResult handleHash(ProcessingAction action, String algo, String content) throws ProcessorException {
        // Simple hash of content
        try {
            String javaAlgoName = mapHashAlgorithmName(algo);
            MessageDigest digest = MessageDigest.getInstance(javaAlgoName, BouncyCastleSupport.getProvider());
            
            String charsetName = getConfigString(action, Constants.ConfigKey.CHARSET, StandardCharsets.UTF_8.name());
            Charset charset = Charset.forName(charsetName);
            
            byte[] inputBytes = content.getBytes(charset);
            byte[] hashBytes = digest.digest(inputBytes);
            
            String outputFormat = getConfigString(action, Constants.ConfigKey.CIPHER_FORMAT, "hex");
            String result = encodeBytes(hashBytes, outputFormat);
            
            // If payload format is JSON, allow putting hash into a field
            String payloadFormat = getConfigString(action, Constants.ConfigKey.PAYLOAD_FORMAT, "raw").toLowerCase(Locale.ROOT);
            if ("json".equals(payloadFormat)) {
                JsonNode root = parseJson(content);
                if (root instanceof ObjectNode obj) {
                    String targetField = getConfigString(action, Constants.ConfigKey.CIPHER_FIELD, "hash");
                    obj.put(targetField, result);
                    return new InternalResult(stringifyJson(obj), Map.of("algorithm", javaAlgoName));
                }
            }

            return new InternalResult(result, Map.of("algorithm", javaAlgoName));
        } catch (Exception e) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.hash_failed", e.getMessage()), e);
        }
    }
    
    private static String mapHashAlgorithmName(String shortName) {
        return switch (shortName) {
            case "sha1", "sha-1" -> "SHA-1";
            case "sha256", "sha-256" -> "SHA-256";
            case "sha512", "sha-512" -> "SHA-512";
            case "md5" -> "MD5";
            case "sm3" -> "SM3";
            default -> shortName.toUpperCase();
        };
    }

    private enum Codec {
        BASE64,
        HEX,
        URL
    }

    private static InternalResult handleCodec(ProcessingAction action,
                                              String actionType,
                                              String content,
                                              String normalizedAlgorithm,
                                              Codec codec) throws ProcessorException {

        String payloadFormat = getConfigString(action, Constants.ConfigKey.PAYLOAD_FORMAT, "raw").toLowerCase(Locale.ROOT);
        String charsetName = getConfigString(action, Constants.ConfigKey.CHARSET, StandardCharsets.UTF_8.name());
        Charset charset = Charset.forName(charsetName);

        String cipherField = getConfigString(action, Constants.ConfigKey.CIPHER_FIELD, "ciphertext");
        String plainField = getConfigString(action, Constants.ConfigKey.PLAIN_FIELD, cipherField);
        String plainFormat = getConfigString(action, Constants.ConfigKey.PLAIN_FORMAT, "plain");

        String resultContent;
        Map<String, Object> metadata = new HashMap<>();

        boolean isDecode = codecOperationIsDecode(actionType, normalizedAlgorithm);

        if ("json".equals(payloadFormat)) {
            JsonNode root = parseJson(content);
            if (!(root instanceof ObjectNode obj)) {
                throw new ProcessorException(LanguageManager.getInstance().format("error.engine.provider_json_required", codecName(codec)));
            }

            String valueField = isDecode ? cipherField : plainField;
            String value = getRequiredText(obj, valueField);

            String processed = isDecode
                    ? decodeCodecValue(value, codec, plainFormat, charset)
                    : encodeCodecValue(value, codec, plainFormat, charset);

            String targetField = isDecode ? plainField : cipherField;
            obj.put(targetField, processed);
            resultContent = stringifyJson(obj);
        } else {
            if (isDecode) {
                resultContent = decodeCodecValue(content, codec, plainFormat, charset);
            } else {
                resultContent = encodeCodecValue(content, codec, plainFormat, charset);
            }
        }

        metadata.put("provider", "internal");
        metadata.put("algorithm", codecName(codec));
        metadata.put("operation", isDecode ? "decode" : "encode");

        return new InternalResult(resultContent, metadata);
    }

    private static InternalResult handleSymmetric(ProcessingAction action,
                                            String actionType,
                                            String content,
                                            String key,
                                            String algorithmFamily,
                                            String fullAlgorithmName) throws ProcessorException {

        String payloadFormat = getConfigString(action, Constants.ConfigKey.PAYLOAD_FORMAT, "json").toLowerCase(Locale.ROOT);
        if (!"json".equals(payloadFormat)) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.provider_json_required", algorithmFamily));
        }

        JsonNode root = parseJson(content);
        if (!(root instanceof ObjectNode obj)) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.provider_json_required", algorithmFamily));
        }

        boolean decrypt = Constants.ActionType.DECRYPT.equalsIgnoreCase(actionType);

        FieldSpec cipherSpec = parseFieldSpec(getConfigString(action, Constants.ConfigKey.CIPHER_FIELD, "ciphertext_b64"));
        FieldSpec plainSpec = parseFieldSpec(getConfigString(action, Constants.ConfigKey.PLAIN_FIELD, getConfigString(action, Constants.ConfigKey.CIPHER_FIELD, "ciphertext_b64")));
        FieldSpec ivSpec = parseFieldSpec(getConfigString(action, Constants.ConfigKey.IV_FIELD, "iv_b64"));

        String cipherFormat = getConfigString(action, Constants.ConfigKey.CIPHER_FORMAT, "base64");
        String plainFormat = getConfigString(action, Constants.ConfigKey.PLAIN_FORMAT, "plain");
        String ivFormat = getConfigString(action, Constants.ConfigKey.IV_FORMAT, "base64");
        String keyFormat = getConfigString(action, Constants.ConfigKey.KEY_FORMAT, "base64");
        String charsetName = getConfigString(action, Constants.ConfigKey.CHARSET, StandardCharsets.UTF_8.name());
        Charset charset = Charset.forName(charsetName);

        // Determine Mode and Padding
        String mode = "CBC"; // Default
        if (fullAlgorithmName.contains("gcm")) mode = "GCM";
        else if (fullAlgorithmName.contains("ecb")) mode = "ECB";
        
        mode = getConfigString(action, Constants.ConfigKey.AES_MODE, mode).toUpperCase(Locale.ROOT);
        
        String paddingDefault = "PKCS5Padding";
        if ("GCM".equals(mode)) paddingDefault = "NoPadding";
        
        String padding = getConfigString(action, Constants.ConfigKey.PADDING, paddingDefault);
        int gcmTagLength = getConfigInteger(action, Constants.ConfigKey.GCM_TAG_LENGTH, 128);

        byte[] keyBytes = decodeForKey(key, keyFormat);

        String ivLiteral = getConfigString(action, Constants.ConfigKey.IV_LITERAL_VALUE);
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("provider", "internal");
        metadata.put("algorithm", algorithmFamily + "/" + mode);
        metadata.put("operation", actionType);

        if (decrypt) {
            FieldResult cipherField = resolveField(obj, cipherSpec, true, "cipher field");
            FieldResult plainField = resolveField(obj, plainSpec, false, "plain field");

            IvInfo ivInfo = resolveIv(obj, ivSpec, ivLiteral, true, algorithmFamily, mode, ivFormat, metadata, "ECB".equals(mode));

            byte[] inputBytes = decodeBytes(cipherField.value(), cipherFormat);
            byte[] resultBytes = performSymmetricOperation(algorithmFamily, mode, padding, gcmTagLength, keyBytes, ivInfo != null ? ivInfo.bytes : null, true, inputBytes);
            String outputValue = decodeBytesToString(resultBytes, plainFormat, charset);

            String targetField = determineTargetFieldName(plainSpec, plainField, cipherField.fieldName(), "plain field");
            if (targetField == null) {
                throw new ProcessorException(LanguageManager.getInstance().getString("error.engine.plain_target_invalid"));
            }
            obj.put(targetField, outputValue);

            String updated = stringifyJson(obj);
            return new InternalResult(updated, metadata);
        } else {
            FieldResult plainField = resolveField(obj, plainSpec, true, "plain field");
            FieldResult cipherFieldExisting = resolveField(obj, cipherSpec, false, "cipher field");

            IvInfo ivInfo = resolveIv(obj, ivSpec, ivLiteral, false, algorithmFamily, mode, ivFormat, metadata, "ECB".equals(mode));

            byte[] inputBytes = encodePlain(plainFormat, plainField.value(), charset);
            byte[] resultBytes = performSymmetricOperation(algorithmFamily, mode, padding, gcmTagLength, keyBytes, ivInfo != null ? ivInfo.bytes : null, false, inputBytes);
            String cipherValue = encodeBytes(resultBytes, cipherFormat);

            String targetField = determineTargetFieldName(cipherSpec, cipherFieldExisting, plainField.fieldName(), "cipher field");
            if (targetField == null) {
                throw new ProcessorException(LanguageManager.getInstance().getString("error.engine.cipher_target_invalid"));
            }
            obj.put(targetField, cipherValue);

            if (ivInfo != null && ivInfo.fieldName != null && ivInfo.encodedValue != null) {
                obj.put(ivInfo.fieldName, ivInfo.encodedValue);
            }

            String updated = stringifyJson(obj);
            return new InternalResult(updated, metadata);
        }
    }

    private static InternalResult handleAsymmetric(ProcessingAction action,
                                            String actionType,
                                            String content,
                                            String key,
                                            String algorithmFamily) throws ProcessorException {

        boolean decrypt = Constants.ActionType.DECRYPT.equalsIgnoreCase(actionType);

        String payloadFormat = getConfigString(action, Constants.ConfigKey.PAYLOAD_FORMAT, "json").toLowerCase(Locale.ROOT);
        String cipherField = getConfigString(action, Constants.ConfigKey.CIPHER_FIELD, "ciphertext_b64");
        String plainField = getConfigString(action, Constants.ConfigKey.PLAIN_FIELD, cipherField);
        String cipherFormat = getConfigString(action, Constants.ConfigKey.CIPHER_FORMAT, "base64");
        String plainFormat = getConfigString(action, Constants.ConfigKey.PLAIN_FORMAT, "plain");
        String charsetName = getConfigString(action, Constants.ConfigKey.CHARSET, StandardCharsets.UTF_8.name());
        Charset charset = Charset.forName(charsetName);

        String rsaMode = getConfigString(action, Constants.ConfigKey.RSA_MODE, "ECB");
        String padding = getConfigString(action, Constants.ConfigKey.RSA_PADDING, "PKCS1Padding");
        
        // Construct transformation string (e.g., RSA/ECB/PKCS1Padding or SM2)
        String transformation;
        if ("SM2".equals(algorithmFamily)) {
            transformation = "SM2"; // BouncyCastle SM2 default
        } else {
            transformation = algorithmFamily + "/" + rsaMode + "/" + padding;
        }

        Key asymKey = decrypt
                ? loadPrivateKey(action, key, algorithmFamily)
                : loadPublicKey(action, key, algorithmFamily);

        byte[] inputBytes;
        String outputValue;
        String resultContent;

        try {
            Cipher cipher = Cipher.getInstance(transformation, BouncyCastleSupport.getProvider());
            cipher.init(decrypt ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, asymKey);

            if ("json".equals(payloadFormat)) {
                JsonNode root = parseJson(content);
                if (!(root instanceof ObjectNode obj)) {
                    throw new ProcessorException(LanguageManager.getInstance().format("error.engine.provider_json_required", algorithmFamily));
                }

                String valueField = decrypt ? cipherField : plainField;
                String value = getRequiredText(obj, valueField);

                inputBytes = decrypt
                        ? decodeBytes(value, cipherFormat)
                        : encodePlain(plainFormat, value, charset);

                byte[] resultBytes = cipher.doFinal(inputBytes);

                outputValue = decrypt
                        ? decodeBytesToString(resultBytes, plainFormat, charset)
                        : encodeBytes(resultBytes, cipherFormat);

                String targetField = decrypt ? plainField : cipherField;
                obj.put(targetField, outputValue);
                resultContent = stringifyJson(obj);
            } else {
                inputBytes = decrypt
                        ? decodeBytes(content, cipherFormat)
                        : encodePlain(plainFormat, content, charset);

                byte[] resultBytes = cipher.doFinal(inputBytes);
                resultContent = decrypt
                        ? decodeBytesToString(resultBytes, plainFormat, charset)
                        : encodeBytes(resultBytes, cipherFormat);
            }
        } catch (ProcessorException e) {
            throw e;
        } catch (Exception e) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.operation_failed", algorithmFamily, e.getMessage()), e);
        }

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("provider", "internal");
        metadata.put("algorithm", algorithmFamily);
        metadata.put("operation", actionType);

        return new InternalResult(resultContent, metadata);
    }

    private static byte[] performSymmetricOperation(String algo,
                                              String mode,
                                              String padding,
                                              int gcmTagLength,
                                              byte[] keyBytes,
                                              byte[] ivBytes,
                                              boolean decrypt,
                                              byte[] inputBytes) throws ProcessorException {
        try {
            String transformation = algo + "/" + mode + "/" + padding;
            // Use BouncyCastle for SM4 compatibility
            Cipher cipher = Cipher.getInstance(transformation, BouncyCastleSupport.getProvider());
            Key secretKey = new SecretKeySpec(keyBytes, algo);
            AlgorithmParameterSpec params = null;

            if (!"ECB".equalsIgnoreCase(mode)) {
                if ("GCM".equalsIgnoreCase(mode)) {
                    params = new GCMParameterSpec(gcmTagLength, ivBytes);
                } else {
                    params = new IvParameterSpec(ivBytes);
                }
            }

            if (params != null) {
                cipher.init(decrypt ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, secretKey, params);
            } else {
                cipher.init(decrypt ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, secretKey);
            }
            
            return cipher.doFinal(inputBytes);
        } catch (Exception e) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.operation_failed", algo, e.getMessage()), e);
        }
    }

    private static byte[] decodeForKey(String key, String keyFormat) throws ProcessorException {
        if (key == null || key.isBlank()) {
            throw new ProcessorException(LanguageManager.getInstance().getString("error.engine.key_required"));
        }
        return switch (keyFormat.toLowerCase(Locale.ROOT)) {
            case "base64" -> Base64.getDecoder().decode(key);
            case "hex" -> hexToBytes(key);
            case "plain" -> key.getBytes(StandardCharsets.UTF_8);
            default -> throw new ProcessorException(LanguageManager.getInstance().format("error.engine.unsupported_key_format", keyFormat));
        };
    }

    private static FieldSpec parseFieldSpec(String spec) throws ProcessorException {
        if (spec == null || spec.trim().isEmpty()) {
            return null;
        }
        String trimmed = spec.trim();
        if (trimmed.startsWith("regex:")) {
            String patternText = trimmed.substring("regex:".length());
            try {
                Pattern pattern = Pattern.compile(patternText);
                return new FieldSpec(FieldSpecType.REGEX, patternText, pattern);
            } catch (Exception e) {
                throw new ProcessorException(LanguageManager.getInstance().format("error.engine.invalid_regex", patternText), e);
            }
        }
        return new FieldSpec(FieldSpecType.DIRECT, trimmed, null);
    }

    private static FieldResult resolveField(ObjectNode obj,
                                            FieldSpec spec,
                                            boolean required,
                                            String description) throws ProcessorException {
        if (spec == null) {
            if (required) {
                throw new ProcessorException(LanguageManager.getInstance().getString("error.engine.missing_field") + description + " is not configured");
            }
            return null;
        }

        switch (spec.type) {
            case DIRECT -> {
                if (obj.has(spec.raw)) {
                    JsonNode node = obj.get(spec.raw);
                    return new FieldResult(spec.raw, node.isNull() ? null : node.asText());
                }
                if (required) {
                    throw new ProcessorException(LanguageManager.getInstance().format("error.engine.missing_field", description, spec.raw));
                }
                return null;
            }
            case REGEX -> {
                Iterator<Map.Entry<String, JsonNode>> iterator = obj.fields();
                while (iterator.hasNext()) {
                    Map.Entry<String, JsonNode> entry = iterator.next();
                    if (spec.pattern.matcher(entry.getKey()).matches()) {
                        JsonNode node = entry.getValue();
                        return new FieldResult(entry.getKey(), node.isNull() ? null : node.asText());
                    }
                }
                if (required) {
                    throw new ProcessorException(LanguageManager.getInstance().format("error.engine.no_field_match", spec.raw, description));
                }
                return null;
            }
            default -> {
                return null;
            }
        }
    }

    private static String determineTargetFieldName(FieldSpec spec,
                                                   FieldResult existing,
                                                   String fallback,
                                                   String description) throws ProcessorException {
        if (spec == null) {
            return fallback;
        }

        if (spec.type == FieldSpecType.DIRECT) {
            return spec.raw;
        }

        if (existing != null) {
            return existing.fieldName();
        }

        throw new ProcessorException(LanguageManager.getInstance().format("error.engine.field_lookup_failed", description, spec.raw));
    }

    private static IvInfo resolveIv(ObjectNode obj,
                                    FieldSpec ivSpec,
                                    String literalValue,
                                    boolean decrypt,
                                    String algorithmFamily,
                                    String mode,
                                    String ivFormat,
                                    Map<String, Object> metadata,
                                    boolean isECB) throws ProcessorException {
        if (isECB) return null;

        String literal = literalValue != null && !literalValue.trim().isEmpty() ? literalValue.trim() : null;
        FieldResult existing = ivSpec != null ? resolveField(obj, ivSpec, literal == null && decrypt, "IV field") : null;

        if (literal != null) {
            byte[] ivBytes = decodeBytes(literal, ivFormat);
            String fieldName = determineTargetFieldName(ivSpec, existing, existing != null ? existing.fieldName() : null, "IV field");
            metadata.put("ivSource", "literal");
            return new IvInfo(ivBytes, fieldName, literal);
        }

        if (existing != null && existing.value() != null) {
            byte[] ivBytes = decodeBytes(existing.value(), ivFormat);
            metadata.put("ivSource", "payload");
            return new IvInfo(ivBytes, existing.fieldName(), existing.value());
        }

        if (decrypt) {
            throw new ProcessorException(LanguageManager.getInstance().getString("error.engine.iv_missing"));
        }

        int length = defaultIvLength(algorithmFamily, mode);
        byte[] generated = new byte[length];
        SECURE_RANDOM.nextBytes(generated);
        String encoded = encodeBytes(generated, ivFormat);

        String fieldName = determineTargetFieldName(ivSpec, existing,
                ivSpec != null && ivSpec.type == FieldSpecType.DIRECT ? ivSpec.raw : (existing != null ? existing.fieldName() : null),
                "IV field");
        metadata.put("ivSource", "generated");
        return new IvInfo(generated, fieldName, encoded);
    }

    private static boolean codecOperationIsDecode(String actionType, String normalizedAlgorithm) {
        if (normalizedAlgorithm != null) {
            if (normalizedAlgorithm.endsWith("-decode") || "urldecode".equals(normalizedAlgorithm)) {
                return true;
            }
            if (normalizedAlgorithm.endsWith("-encode") || "urlencode".equals(normalizedAlgorithm)) {
                return false;
            }
        }
        return Constants.ActionType.DECRYPT.equalsIgnoreCase(actionType);
    }

    private static String encodeCodecValue(String value,
                                           Codec codec,
                                           String plainFormat,
                                           Charset charset) throws ProcessorException {
        if (codec == Codec.URL) {
            String plain = decodeBytesToString(encodePlain(plainFormat, value, charset), "plain", charset);
            return URLEncoder.encode(plain, charset);
        }
        byte[] bytes = encodePlain(plainFormat, value, charset);
        return switch (codec) {
            case BASE64 -> Base64.getEncoder().encodeToString(bytes);
            case HEX -> bytesToHex(bytes);
            case URL -> throw new IllegalStateException("URL handled above");
        };
    }

    private static String decodeCodecValue(String value,
                                           Codec codec,
                                           String plainFormat,
                                           Charset charset) throws ProcessorException {
        if (codec == Codec.URL) {
            String decoded = URLDecoder.decode(value, charset);
            if ("plain".equalsIgnoreCase(plainFormat)) {
                return decoded;
            }
            return decodeBytesToString(decoded.getBytes(charset), plainFormat, charset);
        }
        byte[] bytes = switch (codec) {
            case BASE64 -> decodeBytes(value, "base64");
            case HEX -> decodeBytes(value, "hex");
            case URL -> throw new IllegalStateException("URL handled above");
        };
        return decodeBytesToString(bytes, plainFormat, charset);
    }

    private static String codecName(Codec codec) {
        return switch (codec) {
            case BASE64 -> "base64";
            case HEX -> "hex";
            case URL -> "url";
        };
    }

    private static int defaultIvLength(String algorithmFamily, String mode) {
        if ("GCM".equalsIgnoreCase(mode)) {
            return 12;
        }
        if ("DES".equalsIgnoreCase(algorithmFamily) || "DESede".equalsIgnoreCase(algorithmFamily)) {
            return 8;
        }
        return 16;
    }

    private static String decodeBytesToString(byte[] bytes,
                                              String format,
                                              Charset charset) throws ProcessorException {
        return switch (format.toLowerCase(Locale.ROOT)) {
            case "base64" -> Base64.getEncoder().encodeToString(bytes);
            case "hex" -> bytesToHex(bytes);
            case "plain" -> new String(bytes, charset);
            default -> throw new ProcessorException(LanguageManager.getInstance().format("error.engine.unsupported_plain_format", format));
        };
    }

    private static byte[] encodePlain(String format,
                                       String value,
                                       Charset charset) throws ProcessorException {
        return switch (format.toLowerCase(Locale.ROOT)) {
            case "plain" -> value.getBytes(charset);
            case "hex" -> hexToBytes(value);
            case "base64" -> Base64.getDecoder().decode(value);
            default -> throw new ProcessorException(LanguageManager.getInstance().format("error.engine.unsupported_plain_format", format));
        };
    }

    private static byte[] decodeBytes(String value, String format) throws ProcessorException {
        try {
            return switch (format.toLowerCase(Locale.ROOT)) {
                case "base64" -> Base64.getDecoder().decode(value);
                case "hex" -> hexToBytes(value);
                case "plain" -> value.getBytes(StandardCharsets.UTF_8);
                default -> throw new ProcessorException("Unsupported format: " + format);
            };
        } catch (IllegalArgumentException e) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.decode_failed", format, e.getMessage()), e);
        }
    }

    private static String encodeBytes(byte[] bytes, String format) throws ProcessorException {
        return switch (format.toLowerCase(Locale.ROOT)) {
            case "base64" -> Base64.getEncoder().encodeToString(bytes);
            case "hex" -> bytesToHex(bytes);
            case "plain" -> new String(bytes, StandardCharsets.UTF_8);
            default -> throw new ProcessorException(LanguageManager.getInstance().format("error.engine.unsupported_format", format));
        };
    }

    private static String stringifyJson(ObjectNode node) throws ProcessorException {
        try {
            return OBJECT_MAPPER.writeValueAsString(node);
        } catch (Exception e) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.json_serialize_failed", e.getMessage()), e);
        }
    }

    private static JsonNode parseJson(String content) throws ProcessorException {
        try {
            return OBJECT_MAPPER.readTree(content);
        } catch (Exception e) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.json_parse_failed", e.getMessage()), e);
        }
    }

    private static String getRequiredText(ObjectNode node, String fieldName) throws ProcessorException {
        JsonNode field = node.get(fieldName);
        if (field == null || field.isNull()) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.missing_json_field", fieldName));
        }
        return field.asText();
    }

    private static String getConfigString(ProcessingAction action, String key) {
        Object value = action.getConfig(key);
        return value != null ? value.toString() : null;
    }

    private static String getConfigString(ProcessingAction action, String key, String defaultValue) {
        String value = getConfigString(action, key);
        return value != null ? value : defaultValue;
    }

    private static Key loadPublicKey(ProcessingAction action, String fallbackKey, String algo) throws ProcessorException {
        String configured = getConfigString(action, Constants.ConfigKey.RSA_PUBLIC_KEY);
        String keyValue = selectKeyValue(fallbackKey, configured);
        byte[] keyBytes = decodePemOrBase64(keyValue);
        try {
            // SM2 keys are encoded as EC (sm2p256v1); BC has no "SM2" KeyFactory alias.
            KeyFactory keyFactory = KeyFactory.getInstance("SM2".equals(algo) ? "EC" : algo, BouncyCastleSupport.getProvider());
            return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.public_key_parse_failed", algo, e.getMessage()), e);
        }
    }

    private static Key loadPrivateKey(ProcessingAction action, String fallbackKey, String algo) throws ProcessorException {
        String configured = getConfigString(action, Constants.ConfigKey.RSA_PRIVATE_KEY);
        String keyValue = selectKeyValue(fallbackKey, configured);
        byte[] keyBytes = decodePemOrBase64(keyValue);
        try {
             // Use the same EC factory for PKCS#8 SM2 private keys.
            KeyFactory keyFactory = KeyFactory.getInstance("SM2".equals(algo) ? "EC" : algo, BouncyCastleSupport.getProvider());
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.private_key_parse_failed", algo, e.getMessage()), e);
        }
    }

    private static String selectKeyValue(String primary, String fallback) throws ProcessorException {
        if (primary != null && !primary.trim().isEmpty()) {
            return primary.trim();
        }
        if (fallback != null && !fallback.trim().isEmpty()) {
            return fallback.trim();
        }
        throw new ProcessorException(LanguageManager.getInstance().getString("error.engine.key_missing"));
    }

    private static byte[] decodePemOrBase64(String keyValue) throws ProcessorException {
        String normalized = keyValue
                .replaceAll("-----(BEGIN|END) [A-Z ]+ KEY-----", "")
                .replaceAll("\\s", "");

        try {
            return Base64.getDecoder().decode(normalized);
        } catch (IllegalArgumentException e) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.key_decode_failed", e.getMessage()), e);
        }
    }

    private static int getConfigInteger(ProcessingAction action, String key, int defaultValue) {
        Object value = action.getConfig(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public record InternalResult(String content, Map<String, Object> metadata) {
    }
}
