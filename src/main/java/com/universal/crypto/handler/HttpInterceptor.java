package com.universal.crypto.handler;

import com.universal.crypto.engine.RuleMatchEngine;
import com.universal.crypto.engine.ActionPipeline;
import com.universal.crypto.engine.RuleManager;
import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.processor.ProcessorResult;
import com.universal.crypto.util.DebugUtil;
import com.universal.crypto.util.Logger;

import java.util.List;
import java.util.Map;

/**
 * Core HTTP interceptor that handles request/response processing
 * Integrates rule matching engine with processor manager
 */
public class HttpInterceptor {

    private static final Logger logger = Logger.getInstance();

    private final RuleManager ruleManager;
    private final RuleMatchEngine matchEngine;
    private final ProcessorManager processorManager;
    private final java.util.List<TrafficListener> listeners = new java.util.concurrent.CopyOnWriteArrayList<>();
    
    // Bounded by lifetime rather than silently evicting active exchanges at 1000 entries.
    private record CachedContext(long created, Map<String, Object> data) {}
    private final java.util.concurrent.ConcurrentMap<String, CachedContext> requestContextCache = new java.util.concurrent.ConcurrentHashMap<>();
    private static final long CONTEXT_TTL_MS = 10 * 60 * 1000L;
    private final java.util.concurrent.atomic.AtomicLong lastCacheCleanup = new java.util.concurrent.atomic.AtomicLong();

    public HttpInterceptor(RuleManager ruleManager, RuleMatchEngine matchEngine, ProcessorManager processorManager) {
        this.ruleManager = ruleManager;
        this.matchEngine = matchEngine;
        this.processorManager = processorManager;
    }
    
    public void addTrafficListener(TrafficListener listener) {
        listeners.add(listener);
    }
    
    public void removeTrafficListener(TrafficListener listener) {
        listeners.remove(listener);
    }
    
    private void notifyListeners(String method, String url, String status, String ruleInfo, HttpContextBase original, HttpContextBase modified) {
        for (TrafficListener listener : listeners) {
            try {
                listener.onTraffic(method, url, status, ruleInfo, original, modified);
            } catch (Exception e) {
                logger.error("Error notifying listener", e);
            }
        }
    }

    /**
     * Process HTTP request
     *
     * @param context HTTP request context
     * @return processed request context
     */
    public HttpRequestContext processRequest(HttpRequestContext context) {
        DebugUtil.traceEntry("HttpInterceptor", "processRequest",
                context != null && context.getUrl() != null ? context.getUrl().toString() : "null");
        DebugUtil.debugRequest(context, "BEFORE_PROCESSING");
        DebugUtil.startTiming("request_processing");
        DebugUtil.incrementCounter("requests_processed");

        try {
            // Create match context
            RuleMatchEngine.MatchContext matchContext = RuleMatchEngine.createRequestContext(
                    context.getMethod(),
                    context.getUrl(),
                    context.getHeaders(),
                    context.getBody(),
                    context.getToolSource()
            );

            // Find matching rules
            List<ProcessingRule> enabledRules = ruleManager.getEnabledRulesByPriority();
            List<ProcessingRule> matchingRules = matchEngine.findMatchingRules(enabledRules, matchContext).stream()
                    .filter(rule -> hasEnabledActions(rule.getRequestActions())).toList();

            logger.debug("Found " + matchingRules.size() + " matching rules out of " + enabledRules.size() + " enabled rules");

            if (matchingRules.isEmpty()) {
                DebugUtil.debug("No rules matched for request: " + context.getUrl());
                DebugUtil.incrementCounter("requests_no_match");
                long processingTime = DebugUtil.endTiming("request_processing");
                DebugUtil.traceExit("HttpInterceptor", "processRequest", "no_match(" + processingTime + "ms)");
                return context; // No rules match, return unchanged
            }

            DebugUtil.incrementCounter("requests_with_match");
            // Process with matching rules
            HttpRequestContext result = processRequestWithRules(context, matchingRules);
            result = result.withHeaders(com.universal.crypto.util.HttpFraming.headers(context, result));

            long processingTime = DebugUtil.endTiming("request_processing");
            DebugUtil.debugRequest(result, "AFTER_PROCESSING");
            DebugUtil.traceExit("HttpInterceptor", "processRequest", "success(" + processingTime + "ms)");
            notifyListeners(context.getMethod(), context.getUrl().toString(), "Request Processed", buildRuleTraceInfo(matchingRules, false), context, result);
            return result;

        } catch (Exception e) {
            // Log error but don't break the pipeline
            logger.error("Request processing error: " + e.getMessage(), e);
            DebugUtil.logException("HttpInterceptor.processRequest", e);
            DebugUtil.incrementCounter("requests_failed");
            DebugUtil.endTiming("request_processing");
            DebugUtil.traceExit("HttpInterceptor", "processRequest", "error");
            return context.withError("Request processing failed: " + e.getMessage());
        }
    }

    /**
     * Process HTTP response
     *
     * @param context HTTP response context
     * @return processed response context
     */
    public HttpResponseContext processResponse(HttpResponseContext context) {
        DebugUtil.traceEntry("HttpInterceptor", "processResponse",
                context != null && context.getUrl() != null ? context.getUrl().toString() : "null");
        DebugUtil.debugResponse(context, "BEFORE_PROCESSING");
        DebugUtil.startTiming("response_processing");
        DebugUtil.incrementCounter("responses_processed");

        try {
            // Create match context
            RuleMatchEngine.MatchContext matchContext = RuleMatchEngine.createResponseContext(
                    context.getMethod(),
                    context.getUrl(),
                    context.getHeaders(),
                    context.getBody(),
                    context.getToolSource()
            );

            // Find matching rules
            List<ProcessingRule> enabledRules = ruleManager.getEnabledRulesByPriority();
            List<ProcessingRule> matchingRules = matchEngine.findMatchingRules(enabledRules, matchContext).stream()
                    .filter(rule -> hasEnabledActions(rule.getResponseActions())).toList();

            logger.debug("Found " + matchingRules.size() + " matching rules for response from " + context.getUrl());

            if (matchingRules.isEmpty()) {
                DebugUtil.debug("No rules matched for response: " + context.getUrl());
                DebugUtil.incrementCounter("responses_no_match");
                long processingTime = DebugUtil.endTiming("response_processing");
                DebugUtil.traceExit("HttpInterceptor", "processResponse", "no_match(" + processingTime + "ms)");
                return context; // No rules match, return unchanged
            }

            DebugUtil.incrementCounter("responses_with_match");
            if (!hasExecutableResponseAction(matchingRules)) {
                long processingTime = DebugUtil.endTiming("response_processing");
                DebugUtil.debugResponse(context, "AFTER_PROCESSING_UNCHANGED");
                DebugUtil.traceExit("HttpInterceptor", "processResponse", "observed(" + processingTime + "ms)");
                notifyListeners(context.getMethod(), context.getUrl().toString(), "Response Observed", buildRuleTraceInfo(matchingRules, true), context, context);
                return context;
            }

            // Process with matching rules
            HttpResponseContext result = processResponseWithRules(context, matchingRules);
            result = result.withHeaders(com.universal.crypto.util.HttpFraming.headers(context, result));

            long processingTime = DebugUtil.endTiming("response_processing");
            DebugUtil.debugResponse(result, "AFTER_PROCESSING");
            DebugUtil.traceExit("HttpInterceptor", "processResponse", "success(" + processingTime + "ms)");
            notifyListeners(context.getMethod(), context.getUrl().toString(), "Response Processed", buildRuleTraceInfo(matchingRules, true), context, result);
            return result;

        } catch (Exception e) {
            // Log error but don't break the pipeline
            logger.error("Response processing error: " + e.getMessage(), e);
            DebugUtil.logException("HttpInterceptor.processResponse", e);
            DebugUtil.incrementCounter("responses_failed");
            DebugUtil.endTiming("response_processing");
            DebugUtil.traceExit("HttpInterceptor", "processResponse", "error");
            notifyListeners(context.getMethod(), context.getUrl().toString(), "Processing Error", e.getMessage(), context, null);
            return context.withError("Response processing failed: " + e.getMessage());
        } finally {
            requestContextCache.remove(generateCacheKey(context));
        }
    }

    private HttpRequestContext processRequestWithRules(HttpRequestContext context,
                                                      List<ProcessingRule> rules) {

        HttpRequestContext currentContext = context;
        ProcessorContext processorContext = ProcessorContext.forRequest(
                context.getMethod(),
                context.getUrl(),
                context.getHeaders(),
                context.getToolSource()
            ).build();

        var pipeline = new ActionPipeline(processorContext, context.getBody(), context.getBodyBytes());
        for (ProcessingRule rule : rules) {
            if (!rule.hasRequestActions()) {
                continue;
            }

            for (ProcessingAction action : rule.getRequestActions()) {
                if (!action.isEnabled()) {
                    continue;
                }

                if (!shouldExecuteRequestAction(action, context.getToolSource())) {
                    continue;
                }

                try {
                    ProcessorResult result = pipeline.execute(processorManager, action);
                    HttpRequestContext previous = currentContext;
                    currentContext = result.isSuccess() && !result.isNoChange() ? applyRequestResult(currentContext, pipeline) : currentContext;
                    notifyAction(context, previous, currentContext, rule, action, result);

                } catch (Exception e) {
                    logger.error(com.universal.crypto.util.LanguageManager.getInstance().format("error.request.action.failed", rule.getId(), action.getActionType(), e.getMessage()), e);
                    notifyListeners(context.getMethod(), String.valueOf(context.getUrl()), "Action Failed", rule.getId() + ":" + action.getActionType() + " " + e.getMessage(), currentContext, currentContext);
                }
            }
        }


        
        // Cache shared data for response processing
        if (!processorContext.getSharedData().isEmpty() && context.getMessageId() != null) {
            String cacheKey = generateCacheKey(context);
            long now = System.currentTimeMillis();
            long last = lastCacheCleanup.get();
            if (now - last > 60000 && lastCacheCleanup.compareAndSet(last, now))
                requestContextCache.entrySet().removeIf(e -> now - e.getValue().created() > CONTEXT_TTL_MS);
            requestContextCache.put(cacheKey, new CachedContext(now, processorContext.getSharedData()));
        }

        return currentContext;
    }

    private HttpResponseContext processResponseWithRules(HttpResponseContext context,
                                                        List<ProcessingRule> rules) {

        HttpResponseContext currentContext = context;
        ProcessorContext processorContext = ProcessorContext.forResponse(
                context.getMethod(),
                context.getUrl(),
                context.getHeaders(),
                context.getToolSource()
            )
                .requestHeaders(context.getRequestHeaders())
                .build();
            
        // Restore shared data from the initiating request.
        String cacheKey = generateCacheKey(context);
        CachedContext cached = requestContextCache.remove(cacheKey);
        Map<String, Object> cachedData = cached != null && System.currentTimeMillis() - cached.created() <= CONTEXT_TTL_MS ? cached.data() : null;
        if (cachedData != null) {
            cachedData.forEach(processorContext::setSharedData);
            requestContextCache.remove(cacheKey); // Invalidate to keep cache clean
        }

        var pipeline = new ActionPipeline(processorContext, context.getBody(), context.getBodyBytes());
        for (ProcessingRule rule : rules) {
            if (!rule.hasResponseActions()) {
                continue;
            }

            for (ProcessingAction action : rule.getResponseActions()) {
                if (!action.isEnabled()) {
                    continue;
                }

                if (!shouldExecuteResponseAction(action)) {
                    continue;
                }

                try {
                    ProcessorResult result = pipeline.execute(processorManager, action);
                    HttpResponseContext previous = currentContext;
                    currentContext = result.isSuccess() && !result.isNoChange() ? applyResponseResult(currentContext, pipeline) : currentContext;
                    notifyAction(context, previous, currentContext, rule, action, result);

                } catch (Exception e) {
                    logger.error(com.universal.crypto.util.LanguageManager.getInstance().format("error.response.action.failed", rule.getId(), action.getActionType(), e.getMessage()), e);
                    notifyListeners(context.getMethod(), String.valueOf(context.getUrl()), "Action Failed", rule.getId() + ":" + action.getActionType() + " " + e.getMessage(), currentContext, currentContext);
                }
            }
        }

        return currentContext;
    }

    private HttpRequestContext applyRequestResult(HttpRequestContext context, ActionPipeline pipeline) {
        for (var header : pipeline.modifiedHeaders().entrySet()) {
            if (!java.util.Objects.equals(context.getHeaderIgnoreCase(header.getKey()), header.getValue()))
                context = context.withHeader(header.getKey(), header.getValue());
        }
        return context.withBodyBytes(pipeline.bodyBytes());
    }

    private HttpResponseContext applyResponseResult(HttpResponseContext context, ActionPipeline pipeline) {
        for (var header : pipeline.modifiedHeaders().entrySet()) {
            if (!java.util.Objects.equals(context.getHeaderIgnoreCase(header.getKey()), header.getValue()))
                context = context.withHeader(header.getKey(), header.getValue());
        }
        return context.withBodyBytes(pipeline.bodyBytes());
    }

    private boolean shouldExecuteRequestAction(ProcessingAction action, String toolSource) {
        if (Boolean.parseBoolean(action.getConfigString(Constants.ConfigKey.EDITOR_ONLY, "false"))) return false;
        // Standard SEND phase check
        if (executionPhaseMatches(action, Constants.ExecutionPhase.SEND, Constants.ExecutionPhase.SEND)) {
            return true;
        }

        // Allow EDITOR_SEND if coming from Repeater
        if (Constants.ToolSource.REPEATER.equalsIgnoreCase(toolSource)) {
            return executionPhaseMatches(action, Constants.ExecutionPhase.EDITOR_SEND, Constants.ExecutionPhase.SEND);
        }

        return false;
    }

    private boolean hasEnabledActions(List<ProcessingAction> actions) {
        return actions != null && actions.stream().anyMatch(action -> action != null && action.isEnabled());
    }

    private boolean hasExecutableResponseAction(List<ProcessingRule> rules) {
        if (rules == null || rules.isEmpty()) {
            return false;
        }
        for (ProcessingRule rule : rules) {
            if (rule == null || !rule.hasResponseActions()) {
                continue;
            }
            for (ProcessingAction action : rule.getResponseActions()) {
                if (action != null && action.isEnabled() && shouldExecuteResponseAction(action)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean shouldExecuteResponseAction(ProcessingAction action) {
        // Viewing plaintext belongs to the editor; only explicitly selected wire phases mutate traffic.
        return executionPhaseMatches(action, Constants.ExecutionPhase.RESPONSE_SEND,
                Constants.ExecutionPhase.RESPONSE_DISPLAY);
    }

    private boolean executionPhaseMatches(ProcessingAction action, String phaseToken, String defaultPhase) {
        return Constants.ExecutionPhase.matches(action.getConfigString(Constants.ConfigKey.EXECUTION_PHASE), phaseToken, defaultPhase);
    }

    /**
     * Get processing statistics
     */
    public ProcessingStats getStats() {
        return new ProcessingStats(
                ruleManager.getRuleCount(),
                ruleManager.getEnabledRuleCount(),
                processorManager.getProcessorCount()
        );
    }

    /**
     * Processing statistics
     */
    public static class ProcessingStats {
        private final int totalRules;
        private final int enabledRules;
        private final int processors;

        public ProcessingStats(int totalRules, int enabledRules, int processors) {
            this.totalRules = totalRules;
            this.enabledRules = enabledRules;
            this.processors = processors;
        }

        public int getTotalRules() { return totalRules; }
        public int getEnabledRules() { return enabledRules; }
        public int getProcessors() { return processors; }

        @Override
        public String toString() {
            return String.format("ProcessingStats{rules=%d/%d, processors=%d}",
                    enabledRules, totalRules, processors);
        }
    }


    private void notifyAction(HttpContextBase context, HttpContextBase before, HttpContextBase after,
                              ProcessingRule rule, ProcessingAction action, ProcessorResult result) {
        boolean unchanged = java.util.Arrays.equals(before.getBodyBytes(), after.getBodyBytes()) && before.getHeaders().equals(after.getHeaders());
        notifyListeners(context.getMethod(), String.valueOf(context.getUrl()), result.isSuccess() ? (unchanged ? "Action Unchanged" : "Action Changed") : "Action Failed",
                rule.getId() + ":" + action.getActionType() + " bytes=" + before.getBodyBytes().length + "->" + after.getBodyBytes().length + " time=" + result.getProcessingTimeMs() + "ms" + (result.isSuccess() ? "" : " " + result.getErrorMessage()), before, after);
    }

    private String generateCacheKey(HttpContextBase context) {
        // "unpaired" is never stored: contexts without a transport ID do not share across messages.
        return context.getMessageId() != null ? "mid:" + context.getMessageId() : "unpaired";
    }

    private String buildRuleTraceInfo(List<ProcessingRule> rules, boolean response) {
        if (rules == null || rules.isEmpty()) {
            return "No rule";
        }

        ProcessingRule first = rules.get(0);
        StringBuilder info = new StringBuilder();
        info.append(first.getName() != null ? first.getName() : first.getId());

        List<ProcessingAction> actions = response ? first.getResponseActions() : first.getRequestActions();
        String actionSummary = summarizeActions(actions, response);
        if (!actionSummary.isEmpty()) {
            info.append(": ").append(actionSummary);
        }

        if (rules.size() > 1) {
            info.append(" +").append(rules.size() - 1).append(" more");
        }

        return info.toString();
    }

    private String summarizeActions(List<ProcessingAction> actions, boolean response) {
        if (actions == null || actions.isEmpty()) {
            return "";
        }

        StringBuilder summary = new StringBuilder();
        int shown = 0;
        for (ProcessingAction action : actions) {
            if (action == null || !action.isEnabled()) {
                continue;
            }
            if (shown > 0) {
                summary.append("; ");
            }
            summary.append(action.getActionType() != null ? action.getActionType() : "process")
                    .append(" ")
                    .append(actionTarget(action))
                    .append(" [")
                    .append(action.getConfigString(Constants.ConfigKey.EXECUTION_PHASE,
                            response ? Constants.ExecutionPhase.RESPONSE_DISPLAY : Constants.ExecutionPhase.SEND))
                    .append("]");
            shown++;
            if (shown >= 2) {
                break;
            }
        }

        long enabledCount = actions.stream().filter(action -> action != null && action.isEnabled()).count();
        if (enabledCount > shown) {
            summary.append(" +").append(enabledCount - shown).append(" more");
        }

        return summary.toString();
    }

    private String actionTarget(ProcessingAction action) {
        if (action.getTargetType() == null) {
            return "*";
        }
        switch (action.getTargetType()) {
            case Constants.TargetType.HEADER:
                return "header " + (action.getTargetName() != null ? action.getTargetName() : "*");
            case Constants.TargetType.FIELD:
                String fieldPath = action.getConfigString(Constants.ConfigKey.FIELD_PATH);
                return "JSON " + (fieldPath != null ? fieldPath : action.getTargetName());
            case Constants.TargetType.VARIABLE:
                String variableName = action.getConfigString(Constants.ConfigKey.VARIABLE_NAME);
                return "variable " + (variableName != null ? variableName : action.getTargetName());
            case Constants.TargetType.BODY:
                return "body";
            default:
                return action.getTargetType();
        }
    }
}
