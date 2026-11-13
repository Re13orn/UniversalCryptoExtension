package com.universal.crypto.ui;

import com.universal.crypto.model.*;
import com.universal.crypto.util.LanguageManager;
import java.util.*;
import java.util.stream.Collectors;

final class RuleActionDescriber {
    static String summarizeRule(ProcessingRule rule, LanguageManager lang) {
        List<String> summaries = new ArrayList<>();
        addActionSummaries(summaries, rule.getRequestActions(), false, lang, 2);
        addActionSummaries(summaries, rule.getResponseActions(), true, lang, 2);

        if (summaries.isEmpty()) {
            return zh(lang) ? "无动作" : "No actions";
        }

        int total = safeSize(rule.getRequestActions()) + safeSize(rule.getResponseActions());
        String text = String.join("; ", summaries);
        if (total > summaries.size()) {
            text += zh(lang) ? " +" + (total - summaries.size()) + " 个" : " +" + (total - summaries.size()) + " more";
        }
        return text;
    }

    static String describeRule(ProcessingRule rule, LanguageManager lang) {
        StringBuilder details = new StringBuilder();
        details.append(zh(lang) ? "步骤流:\n" : "Step flow:\n");

        appendActionDetails(details, rule.getRequestActions(), false, lang);
        appendActionDetails(details, rule.getResponseActions(), true, lang);

        if (details.toString().endsWith(":\n")) {
            details.append(zh(lang) ? "  无动作\n" : "  No actions\n");
        }
        return details.toString();
    }

    private static void addActionSummaries(List<String> summaries, List<ProcessingAction> actions,
                                           boolean response, LanguageManager lang, int maxPerSide) {
        if (actions == null || actions.isEmpty()) {
            return;
        }
        int count = 0;
        for (ProcessingAction action : actions) {
            if (action == null || count >= maxPerSide) {
                continue;
            }
            summaries.add(shortAction(action, response, lang));
            count++;
        }
    }

    private static void appendActionDetails(StringBuilder details, List<ProcessingAction> actions,
                                            boolean response, LanguageManager lang) {
        if (actions == null || actions.isEmpty()) {
            return;
        }
        String phaseName = response ? (zh(lang) ? "响应" : "Response") : (zh(lang) ? "请求" : "Request");
        details.append(phaseName).append(":\n");
        for (int i = 0; i < actions.size(); i++) {
            ProcessingAction action = actions.get(i);
            details.append("  ").append(i + 1).append(". ")
                .append(longAction(action, response, lang)).append('\n');
        }
    }

    private static String shortAction(ProcessingAction action, boolean response, LanguageManager lang) {
        return phaseLabel(action, response, lang) + " " + input(action, lang) + " -> " + verb(action, lang) + " -> " + target(action, lang);
    }

    private static String longAction(ProcessingAction action, boolean response, LanguageManager lang) {
        StringBuilder text = new StringBuilder(shortAction(action, response, lang));
        String algorithm = config(action, Constants.ConfigKey.ALGORITHM);
        String provider = config(action, Constants.ConfigKey.CRYPTO_PROVIDER);
        if (!algorithm.isEmpty() || !provider.isEmpty()) {
            text.append(" (");
            if (!algorithm.isEmpty()) {
                text.append(algorithm);
            }
            if (!provider.isEmpty()) {
                if (!algorithm.isEmpty()) {
                    text.append(", ");
                }
                text.append(provider);
            }
            text.append(")");
        }
        if (Boolean.parseBoolean(action.getConfigString(Constants.ConfigKey.EDITOR_ONLY, "false")))
            text.append(zh(lang) ? " [仅编辑器提交]" : " [editor submission only]");
        if (!action.isEnabled()) {
            text.append(zh(lang) ? " [已禁用]" : " [disabled]");
        }
        String description = action.getDescription();
        if (description != null && !description.trim().isEmpty()) {
            text.append(" - ").append(description.trim());
        }
        return text.toString();
    }

    static String category(ProcessingRule rule) {
        if (rule.getCategory() != null && !rule.getCategory().trim().isEmpty()) {
            return rule.getCategory();
        }
        List<ProcessingAction> all = new ArrayList<>();
        if (rule.getRequestActions() != null) {
            all.addAll(rule.getRequestActions());
        }
        if (rule.getResponseActions() != null) {
            all.addAll(rule.getResponseActions());
        }
        if (all.isEmpty()) {
            return "-";
        }
        return all.stream()
                .map(ProcessingAction::getProcessor)
                .filter(value -> value != null && !value.trim().isEmpty())
                .distinct()
                .collect(Collectors.joining(", "));
    }

    private static String phaseLabel(ProcessingAction action, boolean response, LanguageManager lang) {
        String phase = config(action, Constants.ConfigKey.EXECUTION_PHASE);
        if (phase.isEmpty()) {
            phase = response ? Constants.ExecutionPhase.RESPONSE_DISPLAY : Constants.ExecutionPhase.SEND;
        }

        return Arrays.stream(phase.split(","))
                .map(String::trim)
                .filter(token -> !token.isEmpty())
                .map(token -> singlePhaseLabel(token, lang))
                .collect(Collectors.joining("/"));
    }

    private static String singlePhaseLabel(String phase, LanguageManager lang) {
        boolean zh = zh(lang);
        String normalized = phase.toLowerCase(Locale.ROOT);
        switch (normalized) {
            case Constants.ExecutionPhase.DISPLAY:
                return zh ? "编辑器显示时" : "editor display";
            case Constants.ExecutionPhase.EDITOR_SEND:
                return zh ? "编辑器发送时" : "editor send";
            case Constants.ExecutionPhase.SEND:
                return zh ? "发送前" : "before send";
            case Constants.ExecutionPhase.RESPONSE_DISPLAY:
                return zh ? "响应显示时" : "response display";
            case Constants.ExecutionPhase.RESPONSE_EDITOR_SEND:
                return zh ? "响应编辑后发送时" : "after response edit";
            case Constants.ExecutionPhase.RESPONSE_SEND:
                return zh ? "响应发送时" : "response send";
            case Constants.ExecutionPhase.ALWAYS:
                return zh ? "始终" : "always";
            default:
                return phase;
        }
    }

    private static String verb(ProcessingAction action, LanguageManager lang) {
        boolean zh = zh(lang);
        String actionType = action.getActionType() != null ? action.getActionType().toLowerCase(Locale.ROOT) : "";
        switch (actionType) {
            case Constants.ActionType.DECRYPT:
                return zh ? "解密" : "decrypt";
            case Constants.ActionType.ENCRYPT:
                return zh ? "加密" : "encrypt";
            case Constants.ActionType.SIGN:
                return zh ? "签名写入" : "sign into";
            case Constants.ActionType.VERIFY:
                return zh ? "验签" : "verify";
            case Constants.ActionType.REPLACE:
                return zh ? "替换" : "replace";
            case Constants.ActionType.ADD:
                return zh ? "添加" : "add";
            case Constants.ActionType.REMOVE:
                return zh ? "移除" : "remove";
            default:
                return actionType.isEmpty() ? (zh ? "处理" : "process") : actionType;
        }
    }

    private static String target(ProcessingAction action, LanguageManager lang) {
        boolean zh = zh(lang);
        String targetType = action.getTargetType() != null ? action.getTargetType().toLowerCase(Locale.ROOT) : "";
        switch (targetType) {
            case Constants.TargetType.BODY:
                return "body";
            case Constants.TargetType.HEADER:
                return "header " + valueOr(action.getTargetName(), "*");
            case Constants.TargetType.FIELD:
                return "JSON " + valueOr(config(action, Constants.ConfigKey.FIELD_PATH), valueOr(action.getTargetName(), "*"));
            case Constants.TargetType.VARIABLE:
                return (zh ? "变量 " : "variable ") + valueOr(config(action, Constants.ConfigKey.VARIABLE_NAME), valueOr(action.getTargetName(), "*"));
            default:
                return targetType.isEmpty() ? "*" : targetType;
        }
    }

    private static String input(ProcessingAction action, LanguageManager lang) {
        boolean zh = zh(lang);
        String source = config(action, Constants.ConfigKey.INPUT_SOURCE);
        String name = config(action, Constants.ConfigKey.INPUT_NAME);
        if (!source.isEmpty()) {
            if (Constants.InputSource.HEADER.equalsIgnoreCase(source)) {
                return (zh ? "读 header " : "read header ") + valueOr(name, "*");
            }
            if (Constants.InputSource.VARIABLE.equalsIgnoreCase(source)) {
                return (zh ? "读变量 " : "read variable ") + valueOr(name, "*");
            }
            if (Constants.InputSource.RESPONSE_BODY.equalsIgnoreCase(source)) {
                return zh ? "读响应 body" : "read response body";
            }
            return zh ? "读请求 body" : "read request body";
        }

        String targetType = action.getTargetType() != null ? action.getTargetType().toLowerCase(Locale.ROOT) : "";
        if (Constants.TargetType.HEADER.equals(targetType)) {
            return (zh ? "读 header " : "read header ") + valueOr(action.getTargetName(), "*");
        }
        if (Constants.TargetType.VARIABLE.equals(targetType)) {
            return (zh ? "读变量 " : "read variable ") + valueOr(config(action, Constants.ConfigKey.VARIABLE_NAME), valueOr(action.getTargetName(), "*"));
        }
        return zh ? "读 body" : "read body";
    }

    static String listOrAny(List<String> values) {
        if (values == null || values.isEmpty()) {
            return "*";
        }
        return String.join(", ", values);
    }

    private static String config(ProcessingAction action, String key) {
        Map<String, Object> config = action.getConfig();
        if (config == null || !config.containsKey(key) || config.get(key) == null) {
            return "";
        }
        return String.valueOf(config.get(key));
    }

    private static String valueOr(String value, String fallback) {
        return value == null || value.trim().isEmpty() ? fallback : value.trim();
    }

    private static int safeSize(List<?> values) {
        return values != null ? values.size() : 0;
    }

    private static boolean zh(LanguageManager lang) {
        return lang.getCurrentLocale() != null && "zh".equalsIgnoreCase(lang.getCurrentLocale().getLanguage());
    }
}
