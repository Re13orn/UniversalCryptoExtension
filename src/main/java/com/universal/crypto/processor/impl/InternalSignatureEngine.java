package com.universal.crypto.processor.impl;

import com.universal.crypto.model.Constants.ConfigKey;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorException;
import com.universal.crypto.util.LanguageManager;
import com.universal.crypto.util.BouncyCastleSupport;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * Internal engine for generating signatures (HMAC, SM3, etc.) locally.
 */
public class InternalSignatureEngine {
    


    public static String sign(ProcessingAction action, String dataToSign, String key) throws ProcessorException {
        String algorithm = getConfigString(action, ConfigKey.ALGORITHM);
        if (algorithm == null || algorithm.isEmpty()) {
            throw new ProcessorException(LanguageManager.getInstance().getString("error.engine.signature_algo_required"));
        }

        // Normalize algorithm name
        String algo = normalizeAlgorithm(algorithm);
        
        try {
            byte[] signatureBytes;
            
            if (algo.toUpperCase().startsWith("HMAC")) {
                byte[] keyBytes = (key != null ? key : "").getBytes(StandardCharsets.UTF_8);
                byte[] dataBytes = dataToSign.getBytes(StandardCharsets.UTF_8);
                signatureBytes = hmac(algo, keyBytes, dataBytes);
            } else if (algo.toUpperCase().endsWith("WITHRSA") || algo.toUpperCase().contains("RSA")) {
                // RSA Signature
                byte[] dataBytes = dataToSign.getBytes(StandardCharsets.UTF_8);
                signatureBytes = rsaSign(algo, key, dataBytes);
            } else {
                // Try as simple hash (Secret + Body) pattern
                // Many APIs use MD5(secret + body + secret) or similar, but here we assume Simple Hash(Content)
                // For signed hash, usually it's HMAC.
                // If the user selects "MD5" as signature algo, we might imply Hash(data + key) or similar? 
                // For strict signature, we usually stick to HMAC. 
                // However, let's support "Salted Hash" where key is appended.
                byte[] keyBytes = (key != null ? key : "").getBytes(StandardCharsets.UTF_8);
                byte[] dataBytes = dataToSign.getBytes(StandardCharsets.UTF_8);
                String keyPlacement = getConfigString(action, ConfigKey.HASH_KEY_PLACEMENT, "suffix");
                signatureBytes = hashWithKeyPlacement(algo, keyBytes, dataBytes, keyPlacement);
            }

            // Encoding
            String format = getConfigString(action, ConfigKey.CIPHER_FORMAT, "hex"); 
            String hexCase = getConfigString(action, ConfigKey.SIGNATURE_HEX_CASE, "lower");
            return encodeBytes(signatureBytes, format, hexCase);

        } catch (Exception e) {
            throw new ProcessorException(LanguageManager.getInstance().format("error.engine.signature_generation_failed", e.getMessage()), e);
        }
    }

    private static byte[] hmac(String algorithm, byte[] key, byte[] data) throws java.security.GeneralSecurityException {
        Mac mac = Mac.getInstance(algorithm, BouncyCastleSupport.getProvider());
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithm);
        mac.init(secretKeySpec);
        return mac.doFinal(data);
    }
    
    private static byte[] rsaSign(String algorithm, String privateKeyPem, byte[] data) throws Exception {
        java.security.Signature signature = java.security.Signature.getInstance(algorithm, BouncyCastleSupport.getProvider());
        java.security.PrivateKey key = parsePrivateKey(privateKeyPem);
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }

    private static java.security.PrivateKey parsePrivateKey(String key) throws Exception {
        // Strip headers/footers
        String privateKeyPEM = key
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replaceAll("\\s", ""); // Remove newlines and spaces

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA", BouncyCastleSupport.getProvider());
        java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }
    
    private static byte[] hashWithKeyPlacement(String algorithm, byte[] key, byte[] data, String placement)
            throws java.security.GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance(algorithm, BouncyCastleSupport.getProvider());
        String mode = placement != null ? placement.toLowerCase(Locale.ROOT) : "suffix";
        switch (mode) {
            case "none":
                digest.update(data);
                break;
            case "prefix":
                digest.update(key);
                digest.update(data);
                break;
            case "both":
                digest.update(key);
                digest.update(data);
                digest.update(key);
                break;
            case "suffix":
            default:
                digest.update(data);
                digest.update(key);
                break;
        }
        return digest.digest();
    }

    private static String normalizeAlgorithm(String input) {
        String upper = input.toUpperCase(Locale.ROOT).replace("-", "");
        return switch (upper) {
            case "HMACSHA256" -> "HmacSHA256";
            case "HMACSHA1" -> "HmacSHA1";
            case "HMACSHA512" -> "HmacSHA512";
            case "HMACMD5" -> "HmacMD5";
            case "HMACSM3", "SM3HMAC" -> "HmacSM3"; // BouncyCastle SM3 HMAC
            case "MD5" -> "MD5";
            case "SHA1" -> "SHA-1";
            case "SHA256" -> "SHA-256";
            case "SM3" -> "SM3";
            
            // RSA Algorithms
            case "SHA1WITHRSA" -> "SHA1withRSA";
            case "SHA256WITHRSA" -> "SHA256withRSA";
            case "SHA512WITHRSA" -> "SHA512withRSA";
            case "MD5WITHRSA" -> "MD5withRSA";
            
            default -> input;
        };
    }

    private static String encodeBytes(byte[] bytes, String format, String hexCase) {
        if ("base64".equalsIgnoreCase(format)) {
            return Base64.getEncoder().encodeToString(bytes);
        }
        if ("plain".equalsIgnoreCase(format)) {
            return new String(bytes, StandardCharsets.UTF_8);
        }
        // Default to hex
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        String hex = sb.toString();
        return "upper".equalsIgnoreCase(hexCase) ? hex.toUpperCase(Locale.ROOT) : hex;
    }

    private static String getConfigString(ProcessingAction action, String key) {
        Object val = action.getConfig(key);
        return val != null ? val.toString() : null;
    }
    
    private static String getConfigString(ProcessingAction action, String key, String def) {
        String val = getConfigString(action, key);
        return val != null ? val : def;
    }
}
