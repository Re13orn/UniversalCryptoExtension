package com.universal.crypto.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.*;

/**
 * Rule condition model class that defines when a processing rule should be applied.
 * Supports matching on various HTTP request/response attributes.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class RuleCondition {

    @JsonProperty("hosts")
    private List<String> hosts;

    @JsonProperty("paths")
    private List<String> paths;

    @JsonProperty("methods")
    private List<String> methods;

    @JsonProperty("headers")
    private Map<String, String> headers;

    @JsonProperty("contentPattern")
    private String contentPattern;

    @JsonProperty("toolSource")
    private String toolSource;

    @JsonProperty("contentType")
    private String contentType;

    /**
     * Default constructor for JSON deserialization
     */
    public RuleCondition() {
        this.hosts = new ArrayList<>();
        this.paths = new ArrayList<>();
        this.methods = new ArrayList<>();
        this.headers = new HashMap<>();
    }

    /**
     * Constructor with basic matching criteria
     *
     * @param hosts list of host patterns to match
     * @param methods list of HTTP methods to match
     */
    public RuleCondition(List<String> hosts, List<String> methods) {
        this();
        this.hosts = hosts != null ? new ArrayList<>(hosts) : new ArrayList<>();
        this.methods = methods != null ? new ArrayList<>(methods) : new ArrayList<>();
    }

    // Getters and Setters

    public List<String> getHosts() {
        return hosts;
    }

    public void setHosts(List<String> hosts) {
        this.hosts = hosts != null ? hosts : new ArrayList<>();
    }

    public List<String> getPaths() {
        return paths;
    }

    public void setPaths(List<String> paths) {
        this.paths = paths != null ? paths : new ArrayList<>();
    }

    public List<String> getMethods() {
        return methods;
    }

    public void setMethods(List<String> methods) {
        this.methods = methods != null ? methods : new ArrayList<>();
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers != null ? headers : new HashMap<>();
    }

    public String getContentPattern() {
        return contentPattern;
    }

    public void setContentPattern(String contentPattern) {
        this.contentPattern = contentPattern;
    }

    public String getToolSource() {
        return toolSource;
    }

    public void setToolSource(String toolSource) {
        this.toolSource = toolSource;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    // Convenience methods

    /**
     * Add a host pattern to match
     *
     * @param host host pattern (supports wildcards like *.example.com)
     */
    public void addHost(String host) {
        if (this.hosts == null) {
            this.hosts = new ArrayList<>();
        }
        if (host != null && !host.trim().isEmpty()) {
            this.hosts.add(host.trim());
        }
    }

    /**
     * Add a path pattern to match
     *
     * @param path path pattern (supports wildcards like /api/*)
     */
    public void addPath(String path) {
        if (this.paths == null) {
            this.paths = new ArrayList<>();
        }
        if (path != null && !path.trim().isEmpty()) {
            this.paths.add(path.trim());
        }
    }

    /**
     * Add an HTTP method to match
     *
     * @param method HTTP method (GET, POST, etc.)
     */
    public void addMethod(String method) {
        if (this.methods == null) {
            this.methods = new ArrayList<>();
        }
        if (method != null && !method.trim().isEmpty()) {
            this.methods.add(method.trim().toUpperCase());
        }
    }

    /**
     * Add a header pattern to match
     *
     * @param headerName header name
     * @param headerPattern header value pattern
     */
    public void addHeader(String headerName, String headerPattern) {
        if (this.headers == null) {
            this.headers = new HashMap<>();
        }
        if (headerName != null && !headerName.trim().isEmpty()) {
            this.headers.put(headerName.trim(), headerPattern != null ? headerPattern.trim() : "");
        }
    }

    /**
     * Check if any matching condition is defined
     *
     * @return true if at least one condition is defined
     */
    public boolean hasConditions() {
        return (hosts != null && !hosts.isEmpty()) ||
               (paths != null && !paths.isEmpty()) ||
               (methods != null && !methods.isEmpty()) ||
               (headers != null && !headers.isEmpty()) ||
               (contentPattern != null && !contentPattern.trim().isEmpty()) ||
               (toolSource != null && !toolSource.trim().isEmpty()) ||
               (contentType != null && !contentType.trim().isEmpty());
    }

    /**
     * Check if this condition matches all requests (no restrictions)
     *
     * @return true if no conditions are specified
     */
    public boolean matchesAll() {
        return !hasConditions();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RuleCondition that = (RuleCondition) o;
        return Objects.equals(hosts, that.hosts) &&
               Objects.equals(paths, that.paths) &&
               Objects.equals(methods, that.methods) &&
               Objects.equals(headers, that.headers) &&
               Objects.equals(contentPattern, that.contentPattern) &&
               Objects.equals(toolSource, that.toolSource) &&
               Objects.equals(contentType, that.contentType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hosts, paths, methods, headers, contentPattern, toolSource, contentType);
    }

    /**
     * Create a copy of this condition
     *
     * @return cloned condition
     */
    public RuleCondition clone() {
        RuleCondition cloned = new RuleCondition();

        if (this.hosts != null) {
            cloned.hosts = new ArrayList<>(this.hosts);
        }
        if (this.paths != null) {
            cloned.paths = new ArrayList<>(this.paths);
        }
        if (this.methods != null) {
            cloned.methods = new ArrayList<>(this.methods);
        }
        if (this.headers != null) {
            cloned.headers = new HashMap<>(this.headers);
        }

        cloned.contentPattern = this.contentPattern;
        cloned.toolSource = this.toolSource;
        cloned.contentType = this.contentType;

        return cloned;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("RuleCondition{");
        if (hosts != null && !hosts.isEmpty()) {
            sb.append("hosts=").append(hosts).append(", ");
        }
        if (paths != null && !paths.isEmpty()) {
            sb.append("paths=").append(paths).append(", ");
        }
        if (methods != null && !methods.isEmpty()) {
            sb.append("methods=").append(methods).append(", ");
        }
        if (headers != null && !headers.isEmpty()) {
            sb.append("headers=").append(headers).append(", ");
        }
        if (contentPattern != null && !contentPattern.trim().isEmpty()) {
            sb.append("contentPattern='").append(contentPattern).append("', ");
        }
        if (toolSource != null && !toolSource.trim().isEmpty()) {
            sb.append("toolSource='").append(toolSource).append("', ");
        }
        if (contentType != null && !contentType.trim().isEmpty()) {
            sb.append("contentType='").append(contentType).append("', ");
        }
        if (sb.length() > 14) {
            sb.setLength(sb.length() - 2); // Remove trailing ", "
        }
        sb.append('}');
        return sb.toString();
    }
}