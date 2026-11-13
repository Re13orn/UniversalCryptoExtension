package com.universal.crypto.util;

import com.universal.crypto.handler.HttpRequestContext;
import com.universal.crypto.handler.HttpResponseContext;
import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.processor.ProcessorResult;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Debug utility for Universal Crypto Extension
 * Provides debugging tools, performance metrics, and request tracing
 */
public class DebugUtil {

    private static final Logger logger = Logger.getInstance();
    private static volatile boolean debugMode = false;
    private static final Map<String, AtomicLong> performanceCounters = new ConcurrentHashMap<>();
    private static final Map<String, Long> timingMap = new ConcurrentHashMap<>();

    /**
     * Enable or disable debug mode
     */
    public static void setDebugMode(boolean enabled) {
        debugMode = enabled;
        logger.info("Debug mode " + (enabled ? "enabled" : "disabled"));
    }

    /**
     * Check if debug mode is enabled
     */
    public static boolean isDebugMode() {
        return debugMode;
    }

    /**
     * Debug log a message (only logs if debug mode is enabled)
     */
    public static void debug(String message) {
        if (debugMode) {
            logger.debug("[DEBUG] " + message);
        }
    }

    /**
     * Debug log with exception
     */
    public static void debug(String message, Throwable throwable) {
        if (debugMode) {
            logger.debug("[DEBUG] " + message, throwable);
        }
    }

    /**
     * Log HTTP request context for debugging
     */
    public static void debugRequest(HttpRequestContext context, String phase) {
        if (!debugMode) return;

        StringBuilder sb = new StringBuilder();
        sb.append("HTTP Request [").append(phase).append("]\n");
        sb.append("  Method: ").append(context.getMethod()).append("\n");
        sb.append("  URL: ").append(context.getUrl()).append("\n");
        sb.append("  Host: ").append(context.getHost()).append("\n");
        sb.append("  Path: ").append(context.getPath()).append("\n");
        sb.append("  Tool Source: ").append(context.getToolSource()).append("\n");
        sb.append("  Headers: ").append(context.getHeaders().size()).append(" headers\n");

        if (context.getBody() != null) {
            String body = context.getBody();
            if (body.length() > 200) {
                body = body.substring(0, 200) + "... (truncated)";
            }
            sb.append("  Body: ").append(body);
        }

        logger.debug(sb.toString());
    }

    /**
     * Log HTTP response context for debugging
     */
    public static void debugResponse(HttpResponseContext context, String phase) {
        if (!debugMode) return;

        StringBuilder sb = new StringBuilder();
        sb.append("HTTP Response [").append(phase).append("]\n");
        sb.append("  Status Code: ").append(context.getStatusCode()).append("\n");
        sb.append("  Headers: ").append(context.getHeaders().size()).append(" headers\n");

        if (context.getBody() != null) {
            String body = context.getBody();
            if (body.length() > 200) {
                body = body.substring(0, 200) + "... (truncated)";
            }
            sb.append("  Body: ").append(body);
        }

        logger.debug(sb.toString());
    }

    /**
     * Log rule matching information
     */
    public static void debugRuleMatch(ProcessingRule rule, boolean matched, String reason) {
        if (!debugMode) return;

        logger.debug("Rule Match - ID: " + rule.getId() +
                    ", Name: " + rule.getName() +
                    ", Matched: " + matched +
                    (reason != null ? ", Reason: " + reason : ""));
    }

    /**
     * Log processing result
     */
    public static void debugProcessingResult(ProcessorResult result, String processorType) {
        if (!debugMode) return;

        StringBuilder sb = new StringBuilder();
        sb.append("Processing Result [").append(processorType).append("]\n");
        sb.append("  Success: ").append(result.isSuccess()).append("\n");
        sb.append("  Content: ").append(result.getProcessedContent() != null ?
                (result.getProcessedContent().length() > 100 ?
                        result.getProcessedContent().substring(0, 100) + "..." :
                        result.getProcessedContent()) : "null").append("\n");

        if (result.getMetadata() != null && !result.getMetadata().isEmpty()) {
            sb.append("  Metadata: ").append(result.getMetadata()).append("\n");
        }

        if (result.getErrorMessage() != null) {
            sb.append("  Error: ").append(result.getErrorMessage());
        }

        logger.debug(sb.toString());
    }

    /**
     * Start timing for a performance measurement
     */
    public static void startTiming(String operationName) {
        timingMap.put(operationName, System.currentTimeMillis());
    }

    /**
     * End timing and log the duration
     */
    public static long endTiming(String operationName) {
        Long startTime = timingMap.remove(operationName);
        if (startTime == null) {
            logger.warn("No start time found for operation: " + operationName);
            return -1;
        }

        long duration = System.currentTimeMillis() - startTime;

        if (debugMode) {
            logger.debug("Performance - " + operationName + ": " + duration + "ms");
        }

        return duration;
    }

    /**
     * Increment a performance counter
     */
    public static void incrementCounter(String counterName) {
        performanceCounters.computeIfAbsent(counterName, k -> new AtomicLong(0))
                           .incrementAndGet();
    }

    /**
     * Get current value of a performance counter
     */
    public static long getCounterValue(String counterName) {
        AtomicLong counter = performanceCounters.get(counterName);
        return counter != null ? counter.get() : 0;
    }

    /**
     * Get all performance counters
     */
    public static Map<String, Long> getAllCounters() {
        Map<String, Long> result = new ConcurrentHashMap<>();
        for (Map.Entry<String, AtomicLong> entry : performanceCounters.entrySet()) {
            result.put(entry.getKey(), entry.getValue().get());
        }
        return result;
    }

    /**
     * Reset all performance counters
     */
    public static void resetCounters() {
        performanceCounters.clear();
        logger.info("Performance counters reset");
    }

    /**
     * Log current performance statistics
     */
    public static void logPerformanceStats() {
        if (performanceCounters.isEmpty()) {
            logger.info("No performance statistics available");
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Performance Statistics:\n");

        for (Map.Entry<String, AtomicLong> entry : performanceCounters.entrySet()) {
            sb.append("  ").append(entry.getKey()).append(": ").append(entry.getValue().get()).append("\n");
        }

        logger.info(sb.toString());
    }

    /**
     * Validate object state and log if invalid
     */
    public static boolean validateAndLog(Object obj, String objectName) {
        if (obj == null) {
            logger.warn("Validation failed: " + objectName + " is null");
            return false;
        }

        if (debugMode) {
            logger.debug("Validation passed: " + objectName + " is valid");
        }

        return true;
    }

    /**
     * Log memory usage information
     */
    public static void logMemoryUsage() {
        if (!debugMode) return;

        Runtime runtime = Runtime.getRuntime();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long usedMemory = totalMemory - freeMemory;
        long maxMemory = runtime.maxMemory();

        StringBuilder sb = new StringBuilder();
        sb.append("Memory Usage:\n");
        sb.append("  Used: ").append(formatBytes(usedMemory)).append("\n");
        sb.append("  Free: ").append(formatBytes(freeMemory)).append("\n");
        sb.append("  Total: ").append(formatBytes(totalMemory)).append("\n");
        sb.append("  Max: ").append(formatBytes(maxMemory));

        logger.debug(sb.toString());
    }

    /**
     * Format bytes to human readable string
     */
    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        String pre = "KMGTPE".charAt(exp - 1) + "";
        return String.format("%.1f %sB", bytes / Math.pow(1024, exp), pre);
    }

    /**
     * Create a debug trace for method entry
     */
    public static void traceEntry(String className, String methodName, Object... params) {
        if (!debugMode) return;

        StringBuilder sb = new StringBuilder();
        sb.append("ENTER ").append(className).append(".").append(methodName).append("(");

        if (params != null && params.length > 0) {
            for (int i = 0; i < params.length; i++) {
                if (i > 0) sb.append(", ");
                sb.append(params[i] != null ? params[i].toString() : "null");
            }
        }

        sb.append(")");
        logger.debug(sb.toString());
    }

    /**
     * Create a debug trace for method exit
     */
    public static void traceExit(String className, String methodName, Object result) {
        if (!debugMode) return;

        logger.debug("EXIT " + className + "." + methodName + " -> " +
                    (result != null ? result.toString() : "void"));
    }

    /**
     * Log exception with context
     */
    public static void logException(String context, Throwable throwable) {
        logger.error("Exception in " + context + ": " + throwable.getMessage(), throwable);
    }
}