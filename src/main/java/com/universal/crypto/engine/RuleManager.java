package com.universal.crypto.engine;

import com.universal.crypto.model.ProcessingRule;
import com.universal.crypto.util.Logger;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * Rule manager for handling processing rules lifecycle - add, remove, update, query
 * This class is thread-safe and supports concurrent access
 */
public class RuleManager {

    private volatile List<ProcessingRule> rules;
    private final java.util.concurrent.atomic.AtomicLong revision = new java.util.concurrent.atomic.AtomicLong();
    public long getRevision() { return revision.get(); }
    private final Object rulesLock = new Object();
    private final RuleConfigStorage storage;
    private final List<Runnable> ruleChangeListeners = new CopyOnWriteArrayList<>();

    /**
     * Constructor with storage dependency
     *
     * @param storage rule configuration storage
     */
    public RuleManager(RuleConfigStorage storage) {
        this.rules = new CopyOnWriteArrayList<>();
        this.storage = storage;
    }

    /**
     * Register a callback invoked after rules are added/updated/removed/replaced.
     * Intended for cache invalidation in matching/processing components.
     */
    public void addRuleChangeListener(Runnable listener) {
        if (listener != null) {
            ruleChangeListeners.add(listener);
        }
    }

    /**
     * Unregister a previously registered rule change callback.
     */
    public boolean removeRuleChangeListener(Runnable listener) {
        if (listener == null) {
            return false;
        }
        return ruleChangeListeners.remove(listener);
    }

    private void notifyRulesChanged() {
        revision.incrementAndGet();
        if (ruleChangeListeners.isEmpty()) {
            return;
        }

        for (Runnable listener : ruleChangeListeners) {
            try {
                listener.run();
            } catch (Exception e) {
                Logger.getInstance().error("Rule change listener failed: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Add a new processing rule
     *
     * @param rule the rule to add
     * @throws IllegalArgumentException if rule is invalid
     */
    public void addRule(ProcessingRule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("Rule cannot be null");
        }

        if (rule.getId() == null || rule.getId().trim().isEmpty()) {
            throw new IllegalArgumentException("Rule ID cannot be null or empty");
        }

        synchronized (rulesLock) {
            // Check for duplicate ID
            if (getRuleById(rule.getId()) != null) {
                throw new IllegalArgumentException("Rule with ID '" + rule.getId() + "' already exists");
            }

            rules.add(rule.clone());
        }

        notifyRulesChanged();
    }

    /**
     * Remove a processing rule by ID
     *
     * @param ruleId the ID of the rule to remove
     * @return true if rule was removed, false if not found
     */
    public boolean removeRule(String ruleId) {
        if (ruleId == null || ruleId.trim().isEmpty()) {
            return false;
        }

        boolean removed;
        synchronized (rulesLock) {
            removed = rules.removeIf(rule -> ruleId.equals(rule.getId()));
        }

        if (removed) {
            notifyRulesChanged();
        }

        return removed;
    }

    /**
     * Update an existing processing rule
     *
     * @param updatedRule the updated rule
     * @return true if rule was updated, false if not found
     * @throws IllegalArgumentException if rule is invalid
     */
    public boolean updateRule(ProcessingRule updatedRule) {
        if (updatedRule == null) {
            throw new IllegalArgumentException("Updated rule cannot be null");
        }

        if (updatedRule.getId() == null || updatedRule.getId().trim().isEmpty()) {
            throw new IllegalArgumentException("Rule ID cannot be null or empty");
        }

        boolean updated = false;
        synchronized (rulesLock) {
            for (int i = 0; i < rules.size(); i++) {
                if (updatedRule.getId().equals(rules.get(i).getId())) {
                    rules.set(i, updatedRule.clone());
                    updated = true;
                    break;
                }
            }
        }

        if (updated) {
            notifyRulesChanged();
        }

        return updated;
    }

    /**
     * Get a processing rule by ID (returns a deep copy for thread safety)
     *
     * @param ruleId the rule ID
     * @return deep copy of the rule or null if not found
     */
    public ProcessingRule getRuleById(String ruleId) {
        if (ruleId == null || ruleId.trim().isEmpty()) {
            return null;
        }

        // CopyOnWriteArrayList allows safe iteration without synchronization
        ProcessingRule rule = rules.stream()
                .filter(r -> ruleId.equals(r.getId()))
                .findFirst()
                .orElse(null);

        return rule != null ? rule.clone() : null;
    }

    /**
     * Get all processing rules (read-only deep copies)
     *
     * @return list of deep copied rules for thread safety
     */
    public List<ProcessingRule> getAllRules() {
        List<ProcessingRule> result = new ArrayList<>();
        for (ProcessingRule rule : rules) {
            result.add(rule.clone());
        }
        return result;
    }

    /**
     * Get all enabled processing rules (read-only deep copies)
     *
     * @return list of deep copied enabled rules for thread safety
     */
    public List<ProcessingRule> getEnabledRules() {
        return rules.stream()
                .filter(ProcessingRule::isEnabled)
                .map(ProcessingRule::clone)
                .collect(Collectors.toList());
    }

    /**
     * Get rules sorted by priority (ascending order - lower number = higher priority)
     *
     * @return list of deep copied rules sorted by priority for thread safety
     */
    public List<ProcessingRule> getRulesByPriority() {
        return rules.stream()
                .sorted(Comparator.comparingInt(ProcessingRule::getPriority))
                .map(ProcessingRule::clone)
                .collect(Collectors.toList());
    }

    /**
     * Get enabled rules sorted by priority
     *
     * @return list of deep copied enabled rules sorted by priority for thread safety
     */
    public List<ProcessingRule> getEnabledRulesByPriority() {
        return rules.stream()
                .filter(ProcessingRule::isEnabled)
                .sorted(Comparator.comparingInt(ProcessingRule::getPriority))
                .map(ProcessingRule::clone)
                .collect(Collectors.toList());
    }

    /**
     * Enable or disable a rule
     *
     * @param ruleId the rule ID
     * @param enabled new enabled state
     * @return true if rule was found and updated
     */
    public boolean setRuleEnabled(String ruleId, boolean enabled) {
        if (ruleId == null || ruleId.isBlank()) return false;
        boolean found = false;
        synchronized (rulesLock) {
            for (int i = 0; i < rules.size(); i++) {
                if (ruleId.equals(rules.get(i).getId())) {
                    var updated = rules.get(i).clone(); updated.setEnabled(enabled);
                    rules.set(i, updated); found = true; break;
                }
            }
        }
        if (found) notifyRulesChanged();
        return found;
    }

    /**
     * Get the total number of rules
     *
     * @return rule count
     */
    public int getRuleCount() {
        return rules.size();
    }

    /**
     * Get the number of enabled rules
     *
     * @return enabled rule count
     */
    public int getEnabledRuleCount() {
        return (int) rules.stream().filter(ProcessingRule::isEnabled).count();
    }

    /**
     * Check if any rules exist
     *
     * @return true if at least one rule exists
     */
    public boolean hasRules() {
        return !rules.isEmpty();
    }

    /**
     * Check if any enabled rules exist
     *
     * @return true if at least one enabled rule exists
     */
    public boolean hasEnabledRules() {
        return rules.stream().anyMatch(ProcessingRule::isEnabled);
    }

    /**
     * Clear all rules
     */
    public void clearRules() {
        synchronized (rulesLock) {
            rules.clear();
        }

        notifyRulesChanged();
    }

    /**
     * Replace all rules with new list
     *
     * @param newRules new list of rules
     */
    public void setRules(List<ProcessingRule> newRules) {
        List<ProcessingRule> snapshots = snapshotRules(newRules);
        synchronized (rulesLock) {
            rules = new CopyOnWriteArrayList<>(snapshots);
        }
        notifyRulesChanged();
    }

    private List<ProcessingRule> snapshotRules(List<ProcessingRule> newRules) {
        List<ProcessingRule> snapshots = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        if (newRules != null) {
            for (ProcessingRule rule : newRules) {
                if (rule == null || rule.getId() == null || rule.getId().isBlank())
                    throw new IllegalArgumentException("Invalid rule in the list");
                if (!ids.add(rule.getId())) throw new IllegalArgumentException("Duplicate rule ID: " + rule.getId());
                snapshots.add(rule.clone());
            }
        }
        return snapshots;
    }

    /** Persist a detached batch before making it available to matching and UI listeners. */
    public void updateRulesAndSave(java.util.function.Consumer<List<ProcessingRule>> edit) {
        Objects.requireNonNull(edit, "Rule edit cannot be null");
        synchronized (rulesLock) {
            List<ProcessingRule> candidate = snapshotRules(rules);
            edit.accept(candidate);
            List<ProcessingRule> snapshots = snapshotRules(candidate);
            try {
                storage.saveRules(snapshotRules(snapshots));
            } catch (Exception ex) {
                throw new RuntimeException("Failed to save rules", ex);
            }
            rules = new CopyOnWriteArrayList<>(snapshots);
        }
        notifyRulesChanged();
    }

    public void addRuleAndSave(ProcessingRule rule) {
        updateRulesAndSave(candidate -> candidate.add(rule));
    }

    public void updateRuleAndSave(ProcessingRule updatedRule) {
        if (updatedRule == null || updatedRule.getId() == null || updatedRule.getId().isBlank())
            throw new IllegalArgumentException("Invalid rule");
        updateRulesAndSave(candidate -> {
            for (int i = 0; i < candidate.size(); i++) {
                if (updatedRule.getId().equals(candidate.get(i).getId())) {
                    candidate.set(i, updatedRule);
                    return;
                }
            }
            throw new IllegalArgumentException("Rule no longer exists: " + updatedRule.getId());
        });
    }

    /**
     * Save all rules to storage
     *
     * @throws RuntimeException if save operation fails
     */
    public void saveRules() {
        synchronized (rulesLock) {
            try {
                storage.saveRules(getAllRules());
            } catch (Exception e) {
                throw new RuntimeException("Failed to save rules", e);
            }
        }
    }

    /**
     * Load rules from storage
     *
     * @throws RuntimeException if load operation fails
     */
    public void loadRules() {
        try {
            List<ProcessingRule> loadedRules = storage.loadRules();
            setRules(loadedRules);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load rules", e);
        }
    }

    /**
     * Initialize with defaults if no rules exist
     *
     * @param defaultRules default rules to add if storage is empty
     */
    public void initializeWithDefaults(List<ProcessingRule> defaultRules) {
        try {
            List<ProcessingRule> loadedRules = storage.loadRules();

            if (loadedRules == null || loadedRules.isEmpty()) {
                // No existing rules, add defaults
                if (defaultRules != null && !defaultRules.isEmpty()) {
                    setRules(defaultRules);
                    saveRules();
                }
            } else {
                // Load existing rules
                setRules(loadedRules);
            }
        } catch (Exception e) {
            // If loading fails, use defaults
            if (defaultRules != null && !defaultRules.isEmpty()) {
                setRules(defaultRules);
            }
        }
    }

    /**
     * Get rules by category/type for better organization
     *
     * @param category rule category (e.g., "signature", "crypto", "field", "example")
     * @return list of rules matching the category
     */
    public List<ProcessingRule> getRulesByCategory(String category) {
        if (category == null || category.trim().isEmpty()) {
            return getAllRules();
        }

        return rules.stream()
                .filter(rule -> {
                    String desc = rule.getDescription();
                    String name = rule.getName();
                    String id = rule.getId();

                    return (desc != null && desc.toLowerCase().contains(category.toLowerCase())) ||
                           (name != null && name.toLowerCase().contains(category.toLowerCase())) ||
                           (id != null && id.toLowerCase().contains(category.toLowerCase()));
                })
                .map(ProcessingRule::clone)
                .collect(Collectors.toList());
    }

    /**
     * Get summary of rules by their status
     *
     * @return map with rule counts by status
     */
    public Map<String, Integer> getRuleSummary() {
        Map<String, Integer> summary = new HashMap<>();
        summary.put("total", rules.size());
        summary.put("enabled", getEnabledRuleCount());
        summary.put("disabled", rules.size() - getEnabledRuleCount());

        // Count by categories
        summary.put("signature", getRulesByCategory("signature").size());
        summary.put("crypto", getRulesByCategory("crypto").size());
        summary.put("field", getRulesByCategory("field").size());
        summary.put("example", getRulesByCategory("example").size());

        return summary;
    }

    /**
     * Enable/disable rules in batch by category
     *
     * @param category rule category to enable/disable
     * @param enabled true to enable, false to disable
     * @return number of rules affected
     */
    public int setRulesCategoryEnabled(String category, boolean enabled) {
        List<ProcessingRule> categoryRules = getRulesByCategory(category);
        int affected = 0;

        for (ProcessingRule rule : categoryRules) {
            if (setRuleEnabled(rule.getId(), enabled)) {
                affected++;
            }
        }

        return affected;
    }

    /**
     * Get user-friendly status description
     *
     * @return human-readable status
     */
    public String getStatusDescription() {
        Map<String, Integer> summary = getRuleSummary();
        return String.format("总计 %d 条规则，其中 %d 条已启用，%d 条已禁用",
                summary.get("total"), summary.get("enabled"), summary.get("disabled"));
    }

    @Override
    public String toString() {
        return "RuleManager{" +
                "ruleCount=" + getRuleCount() +
                ", enabledCount=" + getEnabledRuleCount() +
                '}';
    }
}
