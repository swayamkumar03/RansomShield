package com.ransomshield.defense;

import com.ransomshield.model.Incident;
import com.ransomshield.model.ThreatAssessment;
import com.ransomshield.model.ThreatLevel;

/**
 * Risk-based response policy determining defensive posture, alerting severity,
 * and recommended remediation actions across threat tiers.
 */
public class DefensePolicy {

    public static class PolicyDecision {
        private final ThreatLevel level;
        private final ResponseAction recommendedAction;
        private final boolean requiresNotification;
        private final boolean desktopNotificationEligible;
        private final boolean requiresUserConfirmation;
        private final String guidanceMessage;

        public PolicyDecision(ThreatLevel level, ResponseAction recommendedAction,
                              boolean requiresNotification, boolean desktopNotificationEligible,
                              boolean requiresUserConfirmation, String guidanceMessage) {
            this.level = level;
            this.recommendedAction = recommendedAction;
            this.requiresNotification = requiresNotification;
            this.desktopNotificationEligible = desktopNotificationEligible;
            this.requiresUserConfirmation = requiresUserConfirmation;
            this.guidanceMessage = guidanceMessage;
        }

        public ThreatLevel getLevel() {
            return level;
        }

        public ResponseAction getRecommendedAction() {
            return recommendedAction;
        }

        public boolean isRequiresNotification() {
            return requiresNotification;
        }

        public boolean isDesktopNotificationEligible() {
            return desktopNotificationEligible;
        }

        public boolean isRequiresUserConfirmation() {
            return requiresUserConfirmation;
        }

        public String getGuidanceMessage() {
            return guidanceMessage;
        }
    }

    /**
     * Evaluates a threat assessment and incident state under RansomShield's risk policy.
     */
    public PolicyDecision evaluate(ThreatAssessment assessment, Incident incident) {
        if (assessment == null) {
            return new PolicyDecision(ThreatLevel.NORMAL, ResponseAction.NONE, false, false, false,
                    "Baseline normal state. Continuous passive monitoring active.");
        }

        int score = assessment.getScore();
        ThreatLevel level = assessment.getThreatLevel();

        // 1. NORMAL (0 - 29)
        // High entropy alone (max 20 pts) stays in NORMAL and never triggers disruption
        if (level == ThreatLevel.NORMAL || score < 30) {
            return new PolicyDecision(
                    ThreatLevel.NORMAL,
                    ResponseAction.NONE,
                    false, // Do not interrupt user
                    false,
                    false,
                    "All filesystem behavior within safe bounds. Passive monitoring continues."
            );
        }

        // 2. SUSPICIOUS (30 - 59)
        if (level == ThreatLevel.SUSPICIOUS || score < 60) {
            return new PolicyDecision(
                    ThreatLevel.SUSPICIOUS,
                    ResponseAction.INVESTIGATE,
                    true, // In-app notification
                    true, // Desktop notification eligible
                    false,
                    "Anomalous filesystem pattern detected exceeding baseline heuristics. In-app and desktop alert raised."
            );
        }

        // 3. HIGH (60 - 79)
        if (level == ThreatLevel.HIGH || score < 80) {
            return new PolicyDecision(
                    ThreatLevel.HIGH,
                    ResponseAction.SIMULATE_CONTAINMENT,
                    true,
                    true,
                    true, // Requires explicit user confirmation for disruptive actions
                    "Elevated behavioral threat detected with mass modifications and high entropy. Simulated containment advised."
            );
        }

        // 4. CRITICAL (80 - 100)
        return new PolicyDecision(
                ThreatLevel.CRITICAL,
                ResponseAction.SIMULATE_CONTAINMENT,
                true,
                true,
                true, // Explicit user confirmation required
                "CRITICAL: High-confidence ransomware heuristic pattern detected! Safe simulated containment initiated by default."
        );
    }
}
