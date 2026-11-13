package com.universal.crypto.engine;

import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.model.RuleCondition;

import java.net.URL;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Rule matching engine for determining if HTTP requests/responses match rule conditions
 */
public class RuleMatchEngine {

    private static final int CONTENT_PATTERN_FLAGS = Pattern.CASE_INSENSITIVE | Pattern.DOTALL;

    private final Map<String, Pattern> wildcardPatternCache = new ConcurrentHashMap<>();
    private final Map<String, Pattern> contentPatternCache = new ConcurrentHashMap<>();
    private final Set<String> invalidContentPatterns = ConcurrentHashMap.newKeySet();
    private final Map<String, String> lowercaseContentPatterns = new ConcurrentHashMap<>();

    /**
     * Clears all compiled-pattern caches.
     * Should be called when rules (and their patterns) are added/updated/removed.
     */
    public void clearCaches() {
        wildcardPatternCache.clear();
        contentPatternCache.clear();
        invalidContentPatterns.clear();
        lowercaseContentPatterns.clear();
    }

    /**
     * Match context containing HTTP request/response information
     */
    public static class MatchContext {
        private final String method;
        private final URL url;
        private final Map<String, String> headers;
        private final String contentType;
        private final String body;
        private final String toolSource;

        public MatchContext(String method, URL url, Map<String, String> headers,
                           String contentType, String body, String toolSource) {
            this.method = method;
            this.url = url;
            this.headers = headers;
            this.contentType = contentType;
            this.body = body;
            this.toolSource = toolSource;
        }

        public String getMethod() { return method; }
        public URL getUrl() { return url; }
        public Map<String, String> getHeaders() { return headers; }
        public String getContentType() { return contentType; }
        public String getBody() { return body; }
        public String getToolSource() { return toolSource; }

        public String getHost() {
            return url != null ? url.getHost() : null;
        }

        public String getPath() {
            return url != null ? url.getPath() : null;
        }
    }

    /**
     * Check if a rule matches the given context
     *
     * @param rule the rule to check
     * @param context the match context
     * @return true if the rule matches
     */
    public boolean matches(ProcessingRule rule, MatchContext context) {
        if (rule == null || !rule.isEnabled() || context == null) {
            return false;
        }

        RuleCondition condition = rule.getCondition();
        if (condition == null) {
            return false;
        }

        return matchesCondition(condition, context);
    }

    /**
     * Find all matching rules from a list
     *
     * @param rules list of rules to check
     * @param context match context
     * @return list of matching rules
     */
    public List<ProcessingRule> findMatchingRules(List<ProcessingRule> rules, MatchContext context) {
        return rules.stream()
                .filter(rule -> matches(rule, context))
                .toList();
    }

    /**
     * Explain how a rule matched or failed to match a context.
     */
    public MatchDiagnostic diagnose(ProcessingRule rule, MatchContext context) {
        if (rule == null) {
            return MatchDiagnostic.ruleLevel(null, null, false, false, "Rule is null");
        }

        if (context == null) {
            return MatchDiagnostic.ruleLevel(rule.getId(), rule.getName(), rule.isEnabled(), false, "Request context is null");
        }

        if (!rule.isEnabled()) {
            return MatchDiagnostic.ruleLevel(rule.getId(), rule.getName(), false, false, "Rule is disabled");
        }

        RuleCondition condition = rule.getCondition();
        if (condition == null) {
            return MatchDiagnostic.ruleLevel(rule.getId(), rule.getName(), true, false, "Rule has no condition");
        }

        List<ConditionDiagnostic> checks = diagnoseCondition(condition, context);
        boolean matched = checks.stream().allMatch(ConditionDiagnostic::isMatched);
        String summary = matched ? "All rule conditions matched" : "One or more rule conditions did not match";
        return new MatchDiagnostic(rule.getId(), rule.getName(), true, matched, summary, checks);
    }

    /**
     * Explain all rules against a context, preserving input order.
     */
    public List<MatchDiagnostic> diagnoseRules(List<ProcessingRule> rules, MatchContext context) {
        if (rules == null || rules.isEmpty()) {
            return List.of();
        }

        return rules.stream()
                .map(rule -> diagnose(rule, context))
                .toList();
    }

    /**
     * Check if a condition matches the context
     */
    private boolean matchesCondition(RuleCondition condition, MatchContext context) {
        // Check hosts
        if (!matchesHosts(condition.getHosts(), context.getHost())) {
            return false;
        }

        // Check paths
        if (!matchesPaths(condition.getPaths(), context.getPath())) {
            return false;
        }

        // Check methods
        if (!matchesMethods(condition.getMethods(), context.getMethod())) {
            return false;
        }

        // Check headers
        if (!matchesHeaders(condition.getHeaders(), context.getHeaders())) {
            return false;
        }

        // Check content type
        if (!matchesContentType(condition.getContentType(), context.getContentType())) {
            return false;
        }

        // Check content pattern
        if (!matchesContentPattern(condition.getContentPattern(), context.getBody())) {
            return false;
        }

        // Check tool source
        if (!matchesToolSource(condition.getToolSource(), context.getToolSource())) {
            return false;
        }

        return true;
    }

    private List<ConditionDiagnostic> diagnoseCondition(RuleCondition condition, MatchContext context) {
        List<ConditionDiagnostic> checks = new java.util.ArrayList<>();

        checks.add(diagnoseListCondition("Host", condition.getHosts(), context.getHost(),
                value -> matchesHosts(condition.getHosts(), value)));
        checks.add(diagnoseListCondition("Path", condition.getPaths(), context.getPath(),
                value -> matchesPaths(condition.getPaths(), value)));
        checks.add(diagnoseListCondition("Method", condition.getMethods(), context.getMethod(),
                value -> matchesMethods(condition.getMethods(), value)));
        checks.add(diagnoseHeaders(condition.getHeaders(), context.getHeaders()));
        checks.add(diagnoseScalarCondition("Content-Type", condition.getContentType(), context.getContentType(),
                value -> matchesContentType(condition.getContentType(), value)));
        checks.add(diagnoseScalarCondition("Content Pattern", condition.getContentPattern(), context.getBody(),
                value -> matchesContentPattern(condition.getContentPattern(), value)));
        checks.add(diagnoseScalarCondition("Tool Source", condition.getToolSource(), context.getToolSource(),
                value -> matchesToolSource(condition.getToolSource(), value)));

        return checks;
    }

    private ConditionDiagnostic diagnoseListCondition(String name, List<String> expected, String actual,
                                                      java.util.function.Predicate<String> matcher) {
        if (expected == null || expected.isEmpty()) {
            return ConditionDiagnostic.pass(name, "Any", display(actual), "No restriction");
        }

        boolean matched = matcher.test(actual);
        return new ConditionDiagnostic(
                name,
                expected.toString(),
                display(actual),
                matched,
                matched ? "Matched" : name + " did not match any configured pattern"
        );
    }

    private ConditionDiagnostic diagnoseScalarCondition(String name, String expected, String actual,
                                                        java.util.function.Predicate<String> matcher) {
        if (expected == null || expected.trim().isEmpty()) {
            return ConditionDiagnostic.pass(name, "Any", display(actual), "No restriction");
        }

        boolean matched = matcher.test(actual);
        return new ConditionDiagnostic(
                name,
                expected,
                display(actual),
                matched,
                matched ? "Matched" : name + " did not match"
        );
    }

    private ConditionDiagnostic diagnoseHeaders(Map<String, String> expectedHeaders, Map<String, String> actualHeaders) {
        if (expectedHeaders == null || expectedHeaders.isEmpty()) {
            return ConditionDiagnostic.pass("Headers", "Any", actualHeaders == null ? "<none>" : actualHeaders.keySet().toString(), "No restriction");
        }

        if (actualHeaders == null || actualHeaders.isEmpty()) {
            return ConditionDiagnostic.fail("Headers", expectedHeaders.toString(), "<none>", "Required headers are missing");
        }

        for (Map.Entry<String, String> expected : expectedHeaders.entrySet()) {
            boolean found = actualHeaders.entrySet().stream().anyMatch(actual ->
                    matchesWildcard(expected.getKey(), actual.getKey())
                            && matchesWildcard(expected.getValue(), actual.getValue()));
            if (!found) {
                return ConditionDiagnostic.fail("Headers", expectedHeaders.toString(),
                        actualHeaders.keySet().toString(),
                        "Missing header match for " + expected.getKey() + ": " + expected.getValue());
            }
        }

        return ConditionDiagnostic.pass("Headers", expectedHeaders.toString(), actualHeaders.keySet().toString(), "Matched");
    }

    private String display(String value) {
        return value == null ? "<missing>" : value;
    }

    /**
     * Match hosts with wildcard support
     */
    private boolean matchesHosts(List<String> hostPatterns, String actualHost) {
        if (hostPatterns == null || hostPatterns.isEmpty()) {
            return true; // No host restriction
        }

        if (actualHost == null) {
            return false;
        }

        return hostPatterns.stream()
                .anyMatch(pattern -> matchesWildcard(pattern, actualHost));
    }

    /**
     * Match paths with wildcard support
     */
    private boolean matchesPaths(List<String> pathPatterns, String actualPath) {
        if (pathPatterns == null || pathPatterns.isEmpty()) {
            return true; // No path restriction
        }

        if (actualPath == null) {
            return false;
        }

        return pathPatterns.stream()
                .anyMatch(pattern -> matchesWildcard(pattern, actualPath));
    }

    /**
     * Match HTTP methods
     */
    private boolean matchesMethods(List<String> methods, String actualMethod) {
        if (methods == null || methods.isEmpty()) {
            return true; // No method restriction
        }

        if (actualMethod == null) {
            return false;
        }

        return methods.stream()
                .anyMatch(method -> method.equalsIgnoreCase(actualMethod));
    }

    /**
     * Match headers with pattern support
     */
    private boolean matchesHeaders(Map<String, String> headerPatterns, Map<String, String> actualHeaders) {
        if (headerPatterns == null || headerPatterns.isEmpty()) {
            return true; // No header restriction
        }

        if (actualHeaders == null) {
            return false;
        }

        return headerPatterns.entrySet().stream()
                .allMatch(entry -> {
                    String headerNamePattern = entry.getKey();
                    String headerValuePattern = entry.getValue();

                    // Check if any actual header matches this pattern
                    boolean matchFound = actualHeaders.entrySet().stream().anyMatch(actualEntry -> {
                        // Match Name
                        boolean nameMatch = matchesWildcard(headerNamePattern, actualEntry.getKey());
                        if (!nameMatch) return false;
                        
                        // Match Value
                        return matchesWildcard(headerValuePattern, actualEntry.getValue());
                    });
                    
                    return matchFound;
                });
    }

    /**
     * Get header value ignoring case
     */
    private static String getHeaderIgnoreCase(Map<String, String> headers, String headerName) {
        if (headers == null || headerName == null) {
            return null;
        }

        // First try exact match (fastest path)
        String value = headers.get(headerName);
        if (value != null) {
            return value;
        }

        // Fall back to case-insensitive search
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (headerName.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue();
            }
        }

        return null;
    }

    /**
     * Match content type
     */
    private boolean matchesContentType(String expectedContentType, String actualContentType) {
        if (expectedContentType == null || expectedContentType.trim().isEmpty()) {
            return true; // No content type restriction
        }

        if (actualContentType == null) {
            return false;
        }

        // Extract main content type (ignore charset and other parameters)
        String mainContentType = actualContentType.split(";")[0].trim();
        return expectedContentType.equalsIgnoreCase(mainContentType);
    }

    /**
     * Match content pattern in body
     */
    private boolean matchesContentPattern(String pattern, String content) {
        if (pattern == null || pattern.trim().isEmpty()) {
            return true; // No content pattern restriction
        }

        if (content == null) {
            return false;
        }

        Pattern regex = getOrCompileContentPattern(pattern);
        if (regex != null) {
            return regex.matcher(content).find();
        }

        // Fallback to simple contains check if regex is invalid (cache lower-cased needle)
        String needle = lowercaseContentPatterns.computeIfAbsent(pattern,
                value -> value.toLowerCase(Locale.ROOT));
        return content.toLowerCase(Locale.ROOT).contains(needle);
    }

    /**
     * Match tool source
     */
    private boolean matchesToolSource(String expectedToolSource, String actualToolSource) {
        if (expectedToolSource == null || expectedToolSource.trim().isEmpty()) {
            return true; // No tool source restriction
        }

        if ("ANY".equalsIgnoreCase(expectedToolSource)) {
            return true; // Match any tool source
        }

        if (actualToolSource == null) {
            return false;
        }

        return expectedToolSource.equalsIgnoreCase(actualToolSource);
    }

    /**
     * Wildcard pattern matching (* = any characters, ? = single character)
     */
    private boolean matchesWildcard(String pattern, String text) {
        if (pattern == null || text == null) {
            return false;
        }

        // Fast paths
        if ("*".equals(pattern)) {
            return true;
        }
        if (!pattern.contains("*") && !pattern.contains("?")) {
            return pattern.equalsIgnoreCase(text);
        }

        Pattern compiled = wildcardPatternCache.computeIfAbsent(pattern, RuleMatchEngine::compileWildcardPattern);
        return compiled.matcher(text).matches();
    }

    private Pattern getOrCompileContentPattern(String pattern) {
        Pattern cached = contentPatternCache.get(pattern);
        if (cached != null) {
            return cached;
        }

        if (invalidContentPatterns.contains(pattern)) {
            return null;
        }

        try {
            Pattern compiled = Pattern.compile(pattern, CONTENT_PATTERN_FLAGS);
            Pattern existing = contentPatternCache.putIfAbsent(pattern, compiled);
            return existing != null ? existing : compiled;
        } catch (Exception e) {
            invalidContentPatterns.add(pattern);
            return null;
        }
    }

    private static Pattern compileWildcardPattern(String wildcard) {
        String regex = wildcardToAnchoredRegex(wildcard);
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    }

    private static String wildcardToAnchoredRegex(String wildcard) {
        StringBuilder out = new StringBuilder();
        out.append('^');

        for (int i = 0; i < wildcard.length(); i++) {
            char ch = wildcard.charAt(i);
            switch (ch) {
                case '*' -> out.append(".*");
                case '?' -> out.append('.');
                // Escape regex metacharacters
                case '.', '\\', '^', '$', '+', '{', '}', '[', ']', '(', ')', '|' -> out.append('\\').append(ch);
                default -> out.append(ch);
            }
        }

        out.append('$');
        return out.toString();
    }

    /**
     * Create a match context from request information
     */
    public static MatchContext createRequestContext(String method, URL url,
                                                   Map<String, String> headers,
                                                   String body, String toolSource) {
        String contentType = getHeaderIgnoreCase(headers, "Content-Type");
        return new MatchContext(method, url, headers, contentType, body, toolSource);
    }

    /**
     * Create a match context from response information
     */
    public static MatchContext createResponseContext(String method, URL url,
                                                    Map<String, String> headers,
                                                    String body, String toolSource) {
        String contentType = getHeaderIgnoreCase(headers, "Content-Type");
        return new MatchContext(method, url, headers, contentType, body, toolSource);
    }

    public static class MatchDiagnostic {
        private final String ruleId;
        private final String ruleName;
        private final boolean enabled;
        private final boolean matched;
        private final String summary;
        private final List<ConditionDiagnostic> checks;

        private MatchDiagnostic(String ruleId, String ruleName, boolean enabled, boolean matched,
                                String summary, List<ConditionDiagnostic> checks) {
            this.ruleId = ruleId;
            this.ruleName = ruleName;
            this.enabled = enabled;
            this.matched = matched;
            this.summary = summary;
            this.checks = checks != null ? List.copyOf(checks) : List.of();
        }

        private static MatchDiagnostic ruleLevel(String ruleId, String ruleName, boolean enabled,
                                                 boolean matched, String summary) {
            return new MatchDiagnostic(ruleId, ruleName, enabled, matched, summary, List.of());
        }

        public String getRuleId() { return ruleId; }
        public String getRuleName() { return ruleName; }
        public boolean isEnabled() { return enabled; }
        public boolean isMatched() { return matched; }
        public String getSummary() { return summary; }
        public List<ConditionDiagnostic> getChecks() { return checks; }
    }

    public static class ConditionDiagnostic {
        private final String name;
        private final String expected;
        private final String actual;
        private final boolean matched;
        private final String message;

        private ConditionDiagnostic(String name, String expected, String actual, boolean matched, String message) {
            this.name = name;
            this.expected = expected;
            this.actual = actual;
            this.matched = matched;
            this.message = message;
        }

        private static ConditionDiagnostic pass(String name, String expected, String actual, String message) {
            return new ConditionDiagnostic(name, expected, actual, true, message);
        }

        private static ConditionDiagnostic fail(String name, String expected, String actual, String message) {
            return new ConditionDiagnostic(name, expected, actual, false, message);
        }

        public String getName() { return name; }
        public String getExpected() { return expected; }
        public String getActual() { return actual; }
        public boolean isMatched() { return matched; }
        public String getMessage() { return message; }
    }
}
