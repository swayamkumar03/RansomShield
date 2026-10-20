package com.ransomshield.model;

/**
 * Lifecycle states of an identified security incident.
 */
public enum IncidentStatus {
    OPEN("Open", "#ef4444"),
    DETECTED("Detected", "#ef4444"),
    ACKNOWLEDGED("Acknowledged", "#f59e0b"),
    CONTAINMENT_REQUESTED("Containment Requested", "#38bdf8"),
    CONTAINED("Contained", "#8b5cf6"),
    RESOLVED("Resolved", "#10b981"),
    FAILED("Failed", "#dc2626");

    private final String label;
    private final String colorHex;

    IncidentStatus(String label, String colorHex) {
        this.label = label;
        this.colorHex = colorHex;
    }

    public String getLabel() {
        return label;
    }

    public String getColorHex() {
        return colorHex;
    }
}
