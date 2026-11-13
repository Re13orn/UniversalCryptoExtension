package com.universal.crypto.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Processing rule model class that defines how HTTP requests and responses should be processed.
 * Each rule contains matching conditions and processing actions.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ProcessingRule {

    @JsonProperty("id")
    private String id;

    @JsonProperty("name")
    private String name;

    @JsonProperty("category")
    private String category;

    @JsonProperty("enabled")
    private boolean enabled;

    @JsonProperty("priority")
    private int priority;

    @JsonProperty("description")
    private String description;

    @JsonProperty("condition")
    private RuleCondition condition;

    @JsonProperty("requestActions")
    private List<ProcessingAction> requestActions;

    @JsonProperty("responseActions")
    private List<ProcessingAction> responseActions;

    @JsonProperty("showInEditor")
    private boolean showInEditor;

    /**
     * Default constructor for JSON deserialization
     */
    public ProcessingRule() {
        this.enabled = true;
        this.priority = 100;
        this.showInEditor = true;
        this.requestActions = new ArrayList<>();
        this.responseActions = new ArrayList<>();
    }

    /**
     * Constructor with rule ID only
     *
     * @param id unique identifier for the rule
     */
    public ProcessingRule(String id) {
        this();
        this.id = id;
    }

    /**
     * Constructor with all required fields
     *
     * @param id unique identifier for the rule
     * @param name display name for the rule
     * @param enabled whether the rule is active
     * @param priority rule priority (lower number = higher priority)
     */
    public ProcessingRule(String id, String name, boolean enabled, int priority) {
        this();
        this.id = id;
        this.name = name;
        this.enabled = enabled;
        this.priority = priority;
    }

    // Getters and Setters

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public RuleCondition getCondition() {
        return condition;
    }

    public void setCondition(RuleCondition condition) {
        this.condition = condition;
    }

    public List<ProcessingAction> getRequestActions() {
        return requestActions;
    }

    public void setRequestActions(List<ProcessingAction> requestActions) {
        this.requestActions = requestActions != null ? requestActions : new ArrayList<>();
    }

    public List<ProcessingAction> getResponseActions() {
        return responseActions;
    }

    public void setResponseActions(List<ProcessingAction> responseActions) {
        this.responseActions = responseActions != null ? responseActions : new ArrayList<>();
    }

    public boolean isShowInEditor() {
        return showInEditor;
    }

    public void setShowInEditor(boolean showInEditor) {
        this.showInEditor = showInEditor;
    }

    // Convenience methods

    /**
     * Add a processing action for requests
     *
     * @param action the action to add
     */
    public void addRequestAction(ProcessingAction action) {
        if (this.requestActions == null) {
            this.requestActions = new ArrayList<>();
        }
        this.requestActions.add(action);
    }

    /**
     * Add a processing action for responses
     *
     * @param action the action to add
     */
    public void addResponseAction(ProcessingAction action) {
        if (this.responseActions == null) {
            this.responseActions = new ArrayList<>();
        }
        this.responseActions.add(action);
    }

    /**
     * Check if this rule has any request actions
     *
     * @return true if there are request actions
     */
    public boolean hasRequestActions() {
        return requestActions != null && !requestActions.isEmpty();
    }

    /**
     * Check if this rule has any response actions
     *
     * @return true if there are response actions
     */
    public boolean hasResponseActions() {
        return responseActions != null && !responseActions.isEmpty();
    }

    /**
     * Get request action count
     *
     * @return number of request actions
     */
    public int getRequestActionCount() {
        return requestActions != null ? requestActions.size() : 0;
    }

    /**
     * Get response action count
     *
     * @return number of response actions
     */
    public int getResponseActionCount() {
        return responseActions != null ? responseActions.size() : 0;
    }

    /**
     * Remove a request action
     *
     * @param action action to remove
     * @return true if action was removed
     */
    public boolean removeRequestAction(ProcessingAction action) {
        if (requestActions != null) {
            return requestActions.remove(action);
        }
        return false;
    }

    /**
     * Remove a response action
     *
     * @param action action to remove
     * @return true if action was removed
     */
    public boolean removeResponseAction(ProcessingAction action) {
        if (responseActions != null) {
            return responseActions.remove(action);
        }
        return false;
    }

    /**
     * Clear all request actions
     */
    public void clearRequestActions() {
        if (requestActions != null) {
            requestActions.clear();
        }
    }

    /**
     * Clear all response actions
     */
    public void clearResponseActions() {
        if (responseActions != null) {
            responseActions.clear();
        }
    }

    /**
     * Check if this rule has any actions
     *
     * @return true if has request or response actions
     */
    public boolean hasActions() {
        return hasRequestActions() || hasResponseActions();
    }

    /**
     * Create a copy of this rule
     *
     * @return cloned rule
     */
    public ProcessingRule clone() {
        ProcessingRule cloned = new ProcessingRule();
        cloned.id = this.id;
        cloned.name = this.name;
        cloned.category = this.category;
        cloned.enabled = this.enabled;
        cloned.priority = this.priority;
        cloned.description = this.description;
        cloned.showInEditor = this.showInEditor;

        if (this.condition != null) {
            cloned.condition = this.condition.clone();
        }

        if (this.requestActions != null) {
            cloned.requestActions = new ArrayList<>();
            for (ProcessingAction action : this.requestActions) {
                cloned.requestActions.add(action.clone());
            }
        }

        if (this.responseActions != null) {
            cloned.responseActions = new ArrayList<>();
            for (ProcessingAction action : this.responseActions) {
                cloned.responseActions.add(action.clone());
            }
        }

        return cloned;
    }

    /**
     * Create a deep copy of this rule using JSON serialization
     * @return deep copy of the rule
     */
    public ProcessingRule deepClone() {
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            String json = mapper.writeValueAsString(this);
            return mapper.readValue(json, ProcessingRule.class);
        } catch (Exception e) {
            throw new RuntimeException("Deep clone failed", e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProcessingRule that = (ProcessingRule) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "ProcessingRule{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", enabled=" + enabled +
                ", priority=" + priority +
                ", requestActions=" + (requestActions != null ? requestActions.size() : 0) +
                ", responseActions=" + (responseActions != null ? responseActions.size() : 0) +
                '}';
    }
}