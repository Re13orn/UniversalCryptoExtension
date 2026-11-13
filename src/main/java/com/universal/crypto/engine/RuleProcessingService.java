package com.universal.crypto.engine;

import com.universal.crypto.handler.HttpRequestContext;
import com.universal.crypto.handler.HttpResponseContext;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.processor.ProcessorManager;

import java.util.ArrayList;
import java.util.List;

/**
 * Utility service that reuses the rule/processor pipeline for custom phases
 * such as rendering plaintext views inside Burp's message editor.
 */
public class RuleProcessingService {

    private final RuleManager ruleManager;
    private final RuleMatchEngine matchEngine;
    private final ProcessorManager processorManager;

    public RuleProcessingService(RuleManager ruleManager,
                                 RuleMatchEngine matchEngine,
                                 ProcessorManager processorManager) {
        this.ruleManager = ruleManager;
        this.matchEngine = matchEngine;
        this.processorManager = processorManager;
    }

    public long getRuleRevision() { return ruleManager == null ? 0 : ruleManager.getRevision(); }

    /**
     * Apply request-side actions that match the provided execution phase.
     *
     * @param context     request context
     * @param initialBody body to start with
     * @param executionPhase execution phase to run (e.g., display, send)
     * @return processing outcome with transformed body or error
     */
    public ProcessingOutcome processRequestForPhase(HttpRequestContext context,
                                                    String initialBody,
                                                    String executionPhase) {
        return processForPhase(context, initialBody, executionPhase, true);
    }

    /**
     * Lightweight check for whether any enabled rule matches the request and contains
     * at least one decrypt action intended for {@code display} inside the message editor.
     * This is used to decide whether to show the plaintext request editor tab without
     * invoking external crypto services.
     */
    public boolean shouldProvidePlaintextRequestEditor(HttpRequestContext context) {
        if (context == null) {
            return false;
        }

        RuleMatchEngine.MatchContext matchContext = RuleMatchEngine.createRequestContext(
                context.getMethod(),
                context.getUrl(),
                context.getHeaders(),
                context.getBody(),
                context.getToolSource()
        );

        List<ProcessingRule> enabledRules = ruleManager.getEnabledRulesByPriority();
        List<ProcessingRule> matchingRules = matchEngine.findMatchingRules(enabledRules, matchContext);

        if (matchingRules.isEmpty()) {
            return false;
        }

        for (ProcessingRule rule : matchingRules) {
            if (!rule.isShowInEditor() || !rule.hasRequestActions()) {
                continue;
            }

            for (ProcessingAction action : rule.getRequestActions()) {
                if (!action.isEnabled()) {
                    continue;
                }

                if (!Constants.ActionType.DECRYPT.equalsIgnoreCase(action.getActionType())) {
                    continue;
                }

                if (!Constants.TargetType.BODY.equalsIgnoreCase(action.getTargetType())
                        && !Constants.TargetType.FIELD.equalsIgnoreCase(action.getTargetType())
                        && !Constants.TargetType.HEADER.equalsIgnoreCase(action.getTargetType())) {
                    continue;
                }

                if (phaseMatches(action, Constants.ExecutionPhase.DISPLAY)) {
                    return true;
                }
            }
        }

        return false;
    }

    /** Checks applicability without executing scripts or making external requests. */
    public boolean shouldProvidePlaintextResponseEditor(HttpResponseContext context) {
        if (context == null) return false;
        RuleMatchEngine.MatchContext match = RuleMatchEngine.createResponseContext(context.getMethod(), context.getUrl(), context.getHeaders(), context.getBody(), context.getToolSource());
        for (ProcessingRule rule : matchEngine.findMatchingRules(ruleManager.getEnabledRulesByPriority(), match)) {
            if (!rule.isShowInEditor() || !rule.hasResponseActions()) continue;
            for (ProcessingAction action : rule.getResponseActions()) {
                if (action.isEnabled() && phaseMatches(action, Constants.ExecutionPhase.RESPONSE_DISPLAY)) return true;
            }
        }
        return false;
    }

    public boolean canPrepareEditedRequest(HttpRequestContext context) {
        return canPrepareEdited(context, true, Constants.ExecutionPhase.EDITOR_SEND);
    }

    /** Checks explicit body encryption capability without executing any action. */
    public boolean canPrepareEditedResponse(HttpResponseContext context) {
        return canPrepareEdited(context, false, Constants.ExecutionPhase.RESPONSE_EDITOR_SEND);
    }

    private boolean canPrepareEdited(com.universal.crypto.handler.HttpContextBase context, boolean request, String phase) {
        if (context == null || ruleManager == null || matchEngine == null) return false;
        var match = request
                ? RuleMatchEngine.createRequestContext(context.getMethod(), context.getUrl(), context.getHeaders(), context.getBody(), context.getToolSource())
                : RuleMatchEngine.createResponseContext(context.getMethod(), context.getUrl(), context.getHeaders(), context.getBody(), context.getToolSource());
        for (var rule : matchEngine.findMatchingRules(ruleManager.getEnabledRulesByPriority(), match)) {
            var actions = request ? rule.getRequestActions() : rule.getResponseActions();
            if (actions == null) continue;
            for (var action : actions) {
                if (action != null && action.isEnabled() && Constants.ActionType.ENCRYPT.equalsIgnoreCase(action.getActionType())
                        && ActionPipeline.isBodyTarget(action) && phaseMatches(action, phase)) return true;
            }
        }
        return false;
    }

    /**
     * Apply response-side actions that match the provided execution phase.
     */
    public ProcessingOutcome processResponseForPhase(HttpResponseContext context,
                                                     String initialBody,
                                                     String executionPhase) {
        return processForPhase(context, initialBody, executionPhase, false);
    }

    /** Apply header-target actions to an editor-only HTTP prefix without changing wire data. */
    public HeaderDisplayOutcome processRequestHeadersForDisplay(HttpRequestContext context, String prefix) {
        return processHeadersForDisplay(context, prefix, true);
    }

    /** Apply header-target actions to an editor-only HTTP prefix without changing wire data. */
    public HeaderDisplayOutcome processResponseHeadersForDisplay(HttpResponseContext context, String prefix) {
        return processHeadersForDisplay(context, prefix, false);
    }

    private HeaderDisplayOutcome processHeadersForDisplay(com.universal.crypto.handler.HttpContextBase context,
                                                          String prefix,
                                                          boolean request) {
        if (context == null || prefix == null || prefix.isEmpty() || ruleManager == null
                || matchEngine == null || processorManager == null) {
            return HeaderDisplayOutcome.success(prefix, List.of());
        }
        String phase = request ? Constants.ExecutionPhase.DISPLAY : Constants.ExecutionPhase.RESPONSE_DISPLAY;
        var match = request
                ? RuleMatchEngine.createRequestContext(context.getMethod(), context.getUrl(), context.getHeaders(),
                        context.getBody(), context.getToolSource())
                : RuleMatchEngine.createResponseContext(context.getMethod(), context.getUrl(), context.getHeaders(),
                        context.getBody(), context.getToolSource());
        var processorContext = request
                ? ProcessorContext.forRequest(context.getMethod(), context.getUrl(), context.getHeaders(),
                        context.getToolSource()).build()
                : ProcessorContext.forResponse(context.getMethod(), context.getUrl(), context.getHeaders(),
                        context.getToolSource()).requestHeaders(context.getRequestHeaders()).build();

        String displayPrefix = prefix;
        List<String> executed = new ArrayList<>();
        for (var rule : matchEngine.findMatchingRules(ruleManager.getEnabledRulesByPriority(), match)) {
            var actions = request ? rule.getRequestActions() : rule.getResponseActions();
            if (actions == null) continue;
            for (var action : actions) {
                if (action == null || !action.isEnabled()
                        || !Constants.TargetType.HEADER.equalsIgnoreCase(action.getTargetType())
                        || !phaseMatches(action, phase)) continue;
                try {
                    displayPrefix = applyHeaderAction(displayPrefix, action, processorContext);
                    executed.add(rule.getId() + ":" + action.getActionType());
                } catch (Exception error) {
                    return HeaderDisplayOutcome.failure(error.getMessage(), prefix, executed);
                }
            }
        }
        return HeaderDisplayOutcome.success(displayPrefix, executed);
    }

    private String applyHeaderAction(String prefix, ProcessingAction action,
                                     ProcessorContext context) throws Exception {
        String lineSeparator = prefix.contains("\r\n") ? "\r\n" : "\n";
        String[] lines = prefix.split(java.util.regex.Pattern.quote(lineSeparator), -1);
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) continue;
            int colon = line.indexOf(':');
            String name = colon > 0 ? line.substring(0, colon) : "";
            String configuredName = action.getTargetName();
            if (configuredName == null || (!"*".equals(configuredName.trim())
                    && !configuredName.equalsIgnoreCase(name))) continue;
            String value = colon >= 0 ? line.substring(colon + 1) : line;
            var result = processorManager.process(action, value, context);
            if (!result.isSuccess()) throw new IllegalStateException(result.getErrorMessage());
            if (result.isNoChange()) continue;
            lines[i] = colon >= 0 ? name + ":" + result.getProcessedContent() : result.getProcessedContent();
        }
        return String.join(lineSeparator, lines);
    }

    private ProcessingOutcome processForPhase(com.universal.crypto.handler.HttpContextBase context,
                                              String initialBody, String phase, boolean request) {
        var match = request
                ? RuleMatchEngine.createRequestContext(context.getMethod(), context.getUrl(), context.getHeaders(), context.getBody(), context.getToolSource())
                : RuleMatchEngine.createResponseContext(context.getMethod(), context.getUrl(), context.getHeaders(), context.getBody(), context.getToolSource());
        var rules = matchEngine.findMatchingRules(ruleManager.getEnabledRulesByPriority(), match);
        var processorContext = request
                ? ProcessorContext.forRequest(context.getMethod(), context.getUrl(), context.getHeaders(), context.getToolSource()).build()
                : ProcessorContext.forResponse(context.getMethod(), context.getUrl(), context.getHeaders(), context.getToolSource())
                        .requestHeaders(context.getRequestHeaders()).build();
        var pipeline = new ActionPipeline(processorContext, initialBody,
                java.util.Objects.equals(initialBody, context.getBody()) ? context.getBodyBytes() : null);
        List<String> executed = new ArrayList<>();
        for (var rule : rules) {
            var actions = request ? rule.getRequestActions() : rule.getResponseActions();
            if (actions == null) continue;
            for (var action : actions) {
                if (action == null || !action.isEnabled() || !phaseMatches(action, phase)) continue;
                if (request && Constants.ExecutionPhase.SEND.equals(phase)
                        && Boolean.parseBoolean(action.getConfigString(Constants.ConfigKey.EDITOR_ONLY, "false"))) continue;
                try {
                    var result = pipeline.execute(processorManager, action);
                    if (!result.isSuccess()) return ProcessingOutcome.failure(result.getErrorMessage(), executed);
                    executed.add(rule.getId() + ":" + action.getActionType());
                } catch (Exception error) {
                    return ProcessingOutcome.failure(error.getMessage(), executed);
                }
            }
        }
        if (executed.isEmpty()) return ProcessingOutcome.noMatch();
        return ProcessingOutcome.success(pipeline.body(), pipeline.bodyBytes(), executed, pipeline.modifiedHeaders(), pipeline.bodyEncryptionApplied());
    }

    private boolean phaseMatches(ProcessingAction action, String requiredPhase) {
        return Constants.ExecutionPhase.matches(action.getConfigString(Constants.ConfigKey.EXECUTION_PHASE), requiredPhase,
                requiredPhase != null && requiredPhase.startsWith("response-")
                        ? Constants.ExecutionPhase.RESPONSE_DISPLAY : Constants.ExecutionPhase.SEND);
    }

    /**
     * Result wrapper describing processing outcome.
     */
    public static class ProcessingOutcome {
        private final boolean success;
        private final boolean matched;
        private final boolean bodyEncryptionApplied;
        private final String content;
        private final byte[] bodyBytes;
        private final String error;
        private final List<String> executedActions;
        private final java.util.Map<String, String> modifiedHeaders;

        private ProcessingOutcome(boolean success, boolean matched, String content, byte[] bodyBytes,
                                 String error, List<String> executedActions, java.util.Map<String, String> modifiedHeaders, boolean bodyEncryptionApplied) {
            this.success = success;
            this.bodyEncryptionApplied = bodyEncryptionApplied;
            this.matched = matched;
            this.content = content;
            this.bodyBytes = bodyBytes == null ? null : bodyBytes.clone();
            this.error = error;
            this.executedActions = executedActions != null ? List.copyOf(executedActions) : List.of();
            this.modifiedHeaders = modifiedHeaders != null ? java.util.Map.copyOf(modifiedHeaders) : java.util.Map.of();
        }

        public static ProcessingOutcome success(String content, List<String> executedActions, java.util.Map<String, String> headers) {
            return success(content, executedActions, headers, false);
        }

        public static ProcessingOutcome success(String content, List<String> executedActions,
                                                java.util.Map<String, String> headers, boolean bodyEncryptionApplied) {
            return success(content, null, executedActions, headers, bodyEncryptionApplied);
        }

        public static ProcessingOutcome success(String content, byte[] bodyBytes, List<String> executedActions,
                                                java.util.Map<String, String> headers, boolean bodyEncryptionApplied) {
            return new ProcessingOutcome(true, true, content, bodyBytes, null, executedActions, headers, bodyEncryptionApplied);
        }

        public boolean hasBodyEncryption() { return bodyEncryptionApplied; }

        public static ProcessingOutcome failure(String error, List<String> executedActions) {
            return new ProcessingOutcome(false, true, null, null, error, executedActions, null, false);
        }

        public static ProcessingOutcome noMatch() {
            return new ProcessingOutcome(true, false, null, null, null, List.of(), null, false);
        }
        
        public java.util.Map<String, String> getModifiedHeaders() {
            return modifiedHeaders;
        }

        public boolean isSuccess() {
            return success;
        }

        public boolean isMatched() {
            return matched;
        }

        public String getContent() {
            return content;
        }

        public byte[] getBodyBytes() { return bodyBytes == null ? null : bodyBytes.clone(); }

        public String getError() {
            return error;
        }

        public List<String> getExecutedActions() {
            return executedActions;
        }
    }

    public static class HeaderDisplayOutcome {
        private final boolean success;
        private final String content;
        private final String error;
        private final List<String> executedActions;

        private HeaderDisplayOutcome(boolean success, String content, String error,
                                     List<String> executedActions) {
            this.success = success;
            this.content = content;
            this.error = error;
            this.executedActions = executedActions == null ? List.of() : List.copyOf(executedActions);
        }

        public static HeaderDisplayOutcome success(String content, List<String> executedActions) {
            return new HeaderDisplayOutcome(true, content, null, executedActions);
        }

        public static HeaderDisplayOutcome failure(String error, String original, List<String> executedActions) {
            return new HeaderDisplayOutcome(false, original, error, executedActions);
        }

        public boolean isSuccess() { return success; }
        public String getContent() { return content; }
        public String getError() { return error; }
        public List<String> getExecutedActions() { return executedActions; }
    }
}
