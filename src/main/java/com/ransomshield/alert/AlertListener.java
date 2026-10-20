package com.ransomshield.alert;

import com.ransomshield.model.FileEvent;
import com.ransomshield.model.Incident;
import com.ransomshield.model.ThreatAssessment;

/**
 * Listener interface for receiving real-time threat, incident, and event notifications.
 */
public interface AlertListener {
    void onThreatAssessed(ThreatAssessment assessment);
    void onIncidentRaised(Incident incident);
    void onEventProcessed(FileEvent event);
}
