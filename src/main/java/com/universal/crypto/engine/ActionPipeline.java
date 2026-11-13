package com.universal.crypto.engine;

import com.universal.crypto.model.Constants;
import com.universal.crypto.model.ProcessingAction;
import com.universal.crypto.processor.ProcessorContext;
import com.universal.crypto.processor.ProcessorResult;
import com.universal.crypto.processor.ProcessorManager;
import com.universal.crypto.processor.ProcessorException;
import com.universal.crypto.util.HttpBodyEncoding;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/** Shared input and write-back semantics for wire, editor and preview execution. */
public final class ActionPipeline {
    private final ProcessorContext context;
    private final Map<String, String> modifiedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private String body;
    private boolean bodyEncryptionApplied;

    public ActionPipeline(ProcessorContext context, String body, byte[] bytes) {
        this.context = context;
        this.body = body;
        if (bytes == null) context.setBodyText(body);
        else context.setBodyBytes(bytes);
    }

    public String body() { return body; }
    public byte[] bodyBytes() { return context.getBodyBytes(); }
    public Map<String, String> modifiedHeaders() { return Collections.unmodifiableMap(modifiedHeaders); }
    public boolean bodyEncryptionApplied() { return bodyEncryptionApplied; }

    /** Failed actions cannot leak tentative headers/shared bindings into later wire steps. */
    public ProcessorResult execute(ProcessorManager manager, ProcessingAction action) throws ProcessorException {
        var headersBefore = context.getHeaders();
        var sharedBefore = context.getSharedData();
        byte[] bytesBefore = bodyBytes();
        String bodyBefore = body;
        boolean encryptionBefore = bodyEncryptionApplied;
        var writesBefore = new TreeMap<>(modifiedHeaders);
        try {
            var result = manager.process(action, input(action), context);
            if (!result.isSuccess()) context.restoreState(headersBefore, sharedBefore, bytesBefore);
            else if (result.isNoChange()) context.restoreState(headersBefore, context.getSharedData(), bytesBefore);
            else apply(action, result);
            return result;
        } catch (ProcessorException | RuntimeException error) {
            context.restoreState(headersBefore, sharedBefore, bytesBefore);
            body = bodyBefore; bodyEncryptionApplied = encryptionBefore;
            modifiedHeaders.clear(); modifiedHeaders.putAll(writesBefore);
            throw error;
        }
    }

    public String input(ProcessingAction action) {
        String source = action.getConfigString(Constants.ConfigKey.INPUT_SOURCE);
        if (source != null && !source.isBlank()) {
            return switch (source) {
                case Constants.InputSource.HEADER -> header(action.getConfigString(Constants.ConfigKey.INPUT_NAME));
                case Constants.InputSource.VARIABLE -> variable(action.getConfigString(Constants.ConfigKey.INPUT_NAME));
                default -> body;
            };
        }
        if (Constants.TargetType.HEADER.equalsIgnoreCase(action.getTargetType())) return header(action.getTargetName());
        if (Constants.TargetType.VARIABLE.equalsIgnoreCase(action.getTargetType())) return variable(variableName(action));
        return body;
    }

    public void apply(ProcessingAction action, ProcessorResult result) {
        if (!result.isSuccess() || result.isNoChange()) return;
        result.getGeneratedHeaders().forEach(this::writeHeader);
        String target = action.getTargetType();
        if (isBodyTarget(action)) {
            byte[] before = bodyBytes();
            body = context.applyBodyResult(result);
            if (Constants.ActionType.ENCRYPT.equalsIgnoreCase(action.getActionType()) && !Arrays.equals(before, bodyBytes()))
                bodyEncryptionApplied = true;
        } else if (Constants.TargetType.HEADER.equalsIgnoreCase(target)) {
            if (action.getTargetName() != null) writeHeader(action.getTargetName(), result.getProcessedContent());
        } else if (Constants.TargetType.VARIABLE.equalsIgnoreCase(target)) {
            String name = variableName(action);
            if (name != null && !name.isBlank()) context.setSharedData(name, result.getProcessedContent());
        }
    }

    public static boolean isBodyTarget(ProcessingAction action) {
        return Constants.TargetType.BODY.equalsIgnoreCase(action.getTargetType())
                || Constants.TargetType.FIELD.equalsIgnoreCase(action.getTargetType());
    }

    private String header(String name) { return name == null ? "" : context.getHeader(name); }
    private String variable(String name) {
        Object value = name == null ? null : context.getSharedData(name);
        return value == null ? "" : value.toString();
    }
    private static String variableName(ProcessingAction action) {
        String configured = action.getConfigString(Constants.ConfigKey.VARIABLE_NAME);
        return configured == null || configured.isBlank() ? action.getTargetName() : configured;
    }
    private void writeHeader(String name, String value) {
        modifiedHeaders.put(name, value);
        context.setHeader(name, value);
        // Changing charset reinterprets existing bytes; it must not silently re-encode them.
        if ("Content-Type".equalsIgnoreCase(name) && bodyBytes() != null)
            body = new String(bodyBytes(), HttpBodyEncoding.charset(context.getHeaders()));
    }
}
