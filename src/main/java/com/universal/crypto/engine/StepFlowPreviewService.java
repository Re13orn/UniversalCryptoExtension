package com.universal.crypto.engine;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.processor.ProcessorManager;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Dry-runs a processing action list and records what each step reads, produces,
 * and writes. This is intentionally close to RuleProcessingService's pipeline
 * semantics so UI previews do not drift from real request/response processing.
 */
public class StepFlowPreviewService {

    private final ProcessorManager processorManager;

    public StepFlowPreviewService(ProcessorManager processorManager) {
        this.processorManager = processorManager;
    }

    public PreviewResult preview(List<ProcessingAction> actions,
                                 String initialBody,
                                 String method,
                                 URL url,
                                 Map<String, String> headers,
                                 String toolSource,
                                 boolean request,
                                 String phase) {
        return preview(actions, initialBody, method, url, headers, toolSource, request, phase, null);
    }

    public PreviewResult preview(List<ProcessingAction> actions, String initialBody, String method, URL url,
                                 Map<String,String> headers, String toolSource, boolean request, String phase,
                                 Map<String,String> requestHeaders) {
        List<PreviewStep> steps = new ArrayList<>();
        String currentBody = initialBody != null ? initialBody : "";

        ProcessorContext context = ProcessorContext.builder()
                .method(method != null ? method : "POST")
                .url(url)
                .headers(headers != null ? headers : Map.of())
                .requestHeaders(request ? headers : requestHeaders)
                .toolSource(toolSource != null ? toolSource : Constants.ToolSource.REPEATER)
                .isRequest(request)
                .build();

        var pipeline = new ActionPipeline(context, currentBody, null);
        String expectedPhase = phase != null ? phase : request ? Constants.ExecutionPhase.SEND : Constants.ExecutionPhase.RESPONSE_DISPLAY;
        boolean stopOnFailure = !Constants.ExecutionPhase.SEND.equals(expectedPhase) && !Constants.ExecutionPhase.RESPONSE_SEND.equals(expectedPhase);
        boolean success = true;
        List<ProcessingAction> safeActions = actions != null ? actions : List.of();
        for (int i = 0; i < safeActions.size(); i++) {
            ProcessingAction action = safeActions.get(i);
            if (action == null) {
                success = false;
                steps.add(PreviewStep.failed(i + 1, null, phase, "", currentBody, "步骤配置为空"));
                if (stopOnFailure) break;
                continue;
            }
            if (!action.isEnabled()) {
                steps.add(PreviewStep.skipped(i + 1, action, expectedPhase, "这个步骤已禁用"));
                continue;
            }

            if (!phaseMatches(action, expectedPhase, request, context.getToolSource())) {
                steps.add(PreviewStep.skipped(i + 1, action, expectedPhase,
                        "这个步骤没有配置在当前执行时机运行: " + expectedPhase));
                continue;
            }

            String input = pipeline.input(action);
            if (requiresExternalService(action)) {
                success = false;
                steps.add(PreviewStep.failed(i + 1, action, expectedPhase, input, currentBody,
                        "Offline preview does not execute external providers or key lookup."));
                if (stopOnFailure) break;
                continue;
            }
            try {
                var result = pipeline.execute(processorManager, action);
                if (!result.isSuccess()) {
                    success = false;
                    steps.add(PreviewStep.failed(i + 1, action, expectedPhase, input, currentBody,
                            result.getErrorMessage()));
                    if (stopOnFailure) break;
                    continue;
                }

                String output = result.getProcessedContent();
                currentBody = pipeline.body();
                steps.add(PreviewStep.executed(i + 1, action, expectedPhase, input, output,
                        currentBody, describeTarget(action), result.getMetadata()));
            } catch (Exception ex) {
                success = false;
                steps.add(PreviewStep.failed(i + 1, action, expectedPhase, input, currentBody,
                        ex.getMessage()));
                if (stopOnFailure) break;
            }
        }

        return new PreviewResult(success, currentBody, steps, pipeline.modifiedHeaders(), context.getSharedData());
    }

    private boolean requiresExternalService(ProcessingAction action) {
        if (!Constants.ProcessorType.CRYPTO.equals(action.getProcessor()) && !Constants.ProcessorType.SIGNATURE.equals(action.getProcessor())) return false;
        return !"internal".equalsIgnoreCase(action.getConfigString(Constants.ConfigKey.CRYPTO_PROVIDER, "external"))
                || "lookup".equalsIgnoreCase(action.getConfigString(Constants.ConfigKey.KEY_SOURCE))
                || Boolean.parseBoolean(action.getConfigString(Constants.ConfigKey.FALLBACK_LOOKUP, "false"));
    }

    private boolean phaseMatches(ProcessingAction action, String requiredPhase, boolean request, String source) {
        if (request && Constants.ExecutionPhase.SEND.equals(requiredPhase)
                && Boolean.parseBoolean(action.getConfigString(Constants.ConfigKey.EDITOR_ONLY, "false"))) return false;
        String configured = action.getConfigString(Constants.ConfigKey.EXECUTION_PHASE);
        String fallback = request ? Constants.ExecutionPhase.SEND : Constants.ExecutionPhase.RESPONSE_DISPLAY;
        return Constants.ExecutionPhase.matches(configured, requiredPhase, fallback)
                || (request && Constants.ExecutionPhase.SEND.equals(requiredPhase) && Constants.ToolSource.REPEATER.equalsIgnoreCase(source)
                    && Constants.ExecutionPhase.matches(configured, Constants.ExecutionPhase.EDITOR_SEND, fallback));
    }

    private String describeTarget(ProcessingAction action) {
        String targetType = action.getTargetType();
        if (Constants.TargetType.HEADER.equalsIgnoreCase(targetType)) {
            return "Header " + safe(action.getTargetName());
        }
        if (Constants.TargetType.FIELD.equalsIgnoreCase(targetType)) {
            String path = action.getConfigString(Constants.ConfigKey.FIELD_PATH, action.getTargetName());
            return "JSON 字段 " + safe(path);
        }
        if (Constants.TargetType.VARIABLE.equalsIgnoreCase(targetType)) {
            String variableName = action.getConfigString(Constants.ConfigKey.VARIABLE_NAME, action.getTargetName());
            return "临时变量 " + safe(variableName);
        }
        return "整个内容";
    }

    private String safe(String value) {
        return value == null || value.isBlank() ? "(未命名)" : value;
    }

    public static final class PreviewResult {
        private final boolean success;
        private final String finalBody;
        private final List<PreviewStep> steps;
        private final Map<String, String> modifiedHeaders;
        private final Map<String, Object> variables;

        private PreviewResult(boolean success,
                              String finalBody,
                              List<PreviewStep> steps,
                              Map<String, String> modifiedHeaders,
                              Map<String, Object> variables) {
            this.success = success;
            this.finalBody = finalBody;
            this.steps = List.copyOf(steps);
            this.modifiedHeaders = Map.copyOf(modifiedHeaders);
            this.variables = Map.copyOf(variables);
        }

        public boolean isSuccess() {
            return success;
        }

        public String getFinalBody() {
            return finalBody;
        }

        public List<PreviewStep> getSteps() {
            return steps;
        }

        public Map<String, String> getModifiedHeaders() {
            return modifiedHeaders;
        }

        public Map<String, Object> getVariables() {
            return variables;
        }
    }

    public static final class PreviewStep {
        private final int index;
        private final ProcessingAction action;
        private final String phase;
        private final String status;
        private final String input;
        private final String output;
        private final String bodyAfterStep;
        private final String target;
        private final String message;
        private final Map<String, Object> metadata;

        private PreviewStep(int index,
                            ProcessingAction action,
                            String phase,
                            String status,
                            String input,
                            String output,
                            String bodyAfterStep,
                            String target,
                            String message,
                            Map<String, Object> metadata) {
            this.index = index;
            this.action = action;
            this.phase = phase;
            this.status = status;
            this.input = input;
            this.output = output;
            this.bodyAfterStep = bodyAfterStep;
            this.target = target;
            this.message = message;
            this.metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
        }

        static PreviewStep executed(int index,
                                    ProcessingAction action,
                                    String phase,
                                    String input,
                                    String output,
                                    String bodyAfterStep,
                                    String target,
                                    Map<String, Object> metadata) {
            return new PreviewStep(index, action, phase, "executed", input, output, bodyAfterStep,
                    target, "", metadata);
        }

        static PreviewStep skipped(int index, ProcessingAction action, String phase, String reason) {
            return new PreviewStep(index, action, phase, "skipped", "", "", "", "", reason, Map.of());
        }

        static PreviewStep failed(int index,
                                  ProcessingAction action,
                                  String phase,
                                  String input,
                                  String bodyAfterStep,
                                  String reason) {
            return new PreviewStep(index, action, phase, "failed", input, "", bodyAfterStep,
                    "", reason, Map.of());
        }

        public int getIndex() {
            return index;
        }

        public ProcessingAction getAction() {
            return action;
        }

        public String getPhase() {
            return phase;
        }

        public String getStatus() {
            return status;
        }

        public String getInput() {
            return input;
        }

        public String getOutput() {
            return output;
        }

        public String getBodyAfterStep() {
            return bodyAfterStep;
        }

        public String getTarget() {
            return target;
        }

        public String getMessage() {
            return message;
        }

        public Map<String, Object> getMetadata() {
            return metadata;
        }
    }
}
