package com.ransomshield.simulator;

/**
 * Controlled, safe test simulation modes for demonstrating RansomShield's behavioral detection.
 */
public enum SimulationMode {
    NORMAL_ACTIVITY(
            "Mode 1: Normal Activity",
            "Modifies 2-3 files slowly with natural text. Expected: NORMAL (Low Score)"
    ),
    HIGH_ENTROPY_SINGLE(
            "Mode 2: High Entropy Test (False-Positive Defense)",
            "Modifies 1 file with high-entropy bytes. Demonstrates that entropy alone does NOT trigger CRITICAL."
    ),
    MASS_MODIFICATION(
            "Mode 3: Mass File Modification",
            "Modifies 50+ files in rapid succession without encryption. Tests modification rate and file count detection."
    ),
    SUSPICIOUS_RENAME(
            "Mode 4: Suspicious Extension Rename",
            "Renames multiple test files from .txt to .encrypted. Tests extension anomaly recognition."
    ),
    MULTI_DIRECTORY_TRAVERSAL(
            "Mode 5: Multi-Directory Traversal",
            "Modifies files across Documents, Images, Reports, and Projects subdirectories. Tests directory scope detection."
    ),
    COMBINED_RANSOMWARE_SIMULATION(
            "Mode 6: Combined Ransomware-like Simulation",
            "Full attack pattern: rapid mass modification + high entropy bytes + multi-directory traversal + .encrypted rename. Expected: HIGH / CRITICAL"
    );

    private final String title;
    private final String description;

    SimulationMode(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return title;
    }
}
