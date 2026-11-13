package com.universal.crypto.engine;

import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleSerializer;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import java.util.List;

/**
 * Factory class for creating default processing rules
 */
public class DefaultRuleFactory {

    public static List<ProcessingRule> getAllDefaultRules() {
        return verifiedExampleRules();
    }

    /** Packaged rules and fixtures use the same maintained sources as the portable Skill. */
    public static List<ProcessingRule> verifiedExampleRules() {
        String[] files = {"01-text-base64", "02-internal-aes-cbc", "03-pbkdf2-aes-gcm", "04-gcm-split-tag-aad",
                "05-binary-key-hmac", "06-internal-hmac-signature", "07-json-field", "08-raw-binary-gcm",
                "09-shared-wire-context", "10-response-editor-aad"};
        String[] names = {"Base64 文本编码（非加密）", "AES-CBC JSON 字段响应展示", "PBKDF2 + AES-GCM 请求明文编辑",
                "AES-GCM 分离 tag / AAD", "二进制密钥 HMAC 签名", "内置 HMAC 请求签名", "JSON 字段替换",
                "原始二进制 AES-GCM", "请求/响应共享上下文", "响应编辑重加密 + 原请求头 AAD / 签名"};
        List<ProcessingRule> rules = new ArrayList<>();
        for (int i = 0; i < files.length; i++) {
            try (InputStream input = DefaultRuleFactory.class.getResourceAsStream("/com/universal/crypto/presets/" + files[i] + ".rules.json")) {
                if (input == null) throw new IllegalStateException("Missing preset: " + files[i]);
                ProcessingRule rule = RuleSerializer.importRules(new String(input.readAllBytes(), StandardCharsets.UTF_8)).get(0);
                rule.setName(names[i]);
                rule.setCategory("可验证示例");
                rule.setEnabled(false);
                rule.setDescription((rule.getDescription() == null ? "" : rule.getDescription() + "\n")
                        + "合成协议样例：测试密钥、nonce、匹配地址和 AAD 必须替换；用对应 fixtures 验证行为。"
                        + "固定 nonce 仅用于离线向量，不用于真实流量。样例编号 " + files[i]);
                rules.add(rule);
            } catch (Exception ex) { throw new IllegalStateException("Cannot load preset " + files[i], ex); }
        }
        return rules;
    }

    /**
     * Get only the essential default rules.
     *
     * Preset rules must not be enabled automatically because they can modify
     * live traffic. Keep this method for compatibility, but return no
     * auto-enabled presets.
     *
     * @return empty list; users enable presets explicitly from the UI
     */
    public static List<ProcessingRule> getEssentialDefaultRules() {
        return List.of();
    }

    /**
     * Validate a rule for basic requirements
     *
     * @param rule rule to validate
     * @return true if rule is valid
     */
    public static boolean validateRule(ProcessingRule rule) {
        if (rule == null) {
            return false;
        }

        if (rule.getId() == null || rule.getId().trim().isEmpty()) {
            return false;
        }

        if (rule.getName() == null || rule.getName().trim().isEmpty()) {
            return false;
        }

        if (rule.getCondition() == null) {
            return false;
        }

        // Must have at least one action
        if (!rule.hasRequestActions() && !rule.hasResponseActions()) {
            return false;
        }

        // Validate actions
        if (rule.hasRequestActions()) {
            for (ProcessingAction action : rule.getRequestActions()) {
                if (!action.isValid()) {
                    return false;
                }
            }
        }

        if (rule.hasResponseActions()) {
            for (ProcessingAction action : rule.getResponseActions()) {
                if (!action.isValid()) {
                    return false;
                }
            }
        }

        return true;
    }


}
