package com.ransomshield.model;

/**
 * Categorical threat level classifications based on calculated threat scores.
 */
public enum ThreatLevel {
    NORMAL("Normal", 0, 29, "#10b981", "badge-normal"),
    SUSPICIOUS("Suspicious", 30, 59, "#f59e0b", "badge-suspicious"),
    HIGH("High", 60, 79, "#f97316", "badge-high"),
    CRITICAL("Critical", 80, 100, "#ef4444", "badge-critical");

    private final String displayName;
    private final int minScore;
    private final int maxScore;
    private final String colorHex;
    private final String styleClass;

    ThreatLevel(String displayName, int minScore, int maxScore, String colorHex, String styleClass) {
        this.displayName = displayName;
        this.minScore = minScore;
        this.maxScore = maxScore;
        this.colorHex = colorHex;
        this.styleClass = styleClass;
    }

    public String getDisplayName() {
        return displayName;
    }

    public int getMinScore() {
        return minScore;
    }

    public int getMaxScore() {
        return maxScore;
    }

    public String getColorHex() {
        return colorHex;
    }

    public String getStyleClass() {
        return styleClass;
    }

    public static ThreatLevel fromScore(int score, int suspiciousThreshold, int highThreshold, int criticalThreshold) {
        if (score >= criticalThreshold) {
            return CRITICAL;
        } else if (score >= highThreshold) {
            return HIGH;
        } else if (score >= suspiciousThreshold) {
            return SUSPICIOUS;
        } else {
            return NORMAL;
        }
    }

    public static ThreatLevel fromScore(int score) {
        return fromScore(score, 30, 60, 80);
    }
}
