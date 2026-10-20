package com.ransomshield.defense;

/**
 * Defensive actions supported by RansomShield's risk-based incident response system.
 */
public enum ResponseAction {
    NONE("No Action", "Continuous passive monitoring within baseline tolerance"),
    INVESTIGATE("Investigate", "Review behavioral anomalies and gathered evidence"),
    SIMULATE_CONTAINMENT("Simulate Containment", "Simulate isolation of affected files and process containment without disk mutation"),
    QUARANTINE_FILES("Quarantine Files", "Isolate affected files into a protected, reversible sandbox quarantine"),
    RESTORE_FILES("Restore Files", "Safely restore quarantined files back to their original locations"),
    TERMINATE_PROCESS("Terminate Process", "Guarded termination of verified malicious process (requires reliable attribution)");

    private final String displayName;
    private final String description;

    ResponseAction(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
