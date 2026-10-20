package com.ransomshield.alert;

import com.ransomshield.database.FileEventRepository;
import com.ransomshield.database.IncidentRepository;
import com.ransomshield.model.FileEvent;
import com.ransomshield.model.Incident;
import com.ransomshield.model.ThreatAssessment;
import com.ransomshield.model.ThreatLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Manages security alerts, incident creation, deduplication, and notification dispatch.
 */
public class AlertManager {
    private static final Logger logger = LoggerFactory.getLogger(AlertManager.class);

    private final IncidentRepository incidentRepository;
    private final FileEventRepository fileEventRepository;
    private final List<AlertListener> listeners = new CopyOnWriteArrayList<>();

    private volatile Incident activeIncident = null;
    private volatile Instant lastElevationTime = null;
    private static final Duration INCIDENT_GROUPING_WINDOW = Duration.ofSeconds(8);

    private com.ransomshield.defense.DefenseManager defenseManager;

    public AlertManager(IncidentRepository incidentRepository, FileEventRepository fileEventRepository) {
        this.incidentRepository = incidentRepository;
        this.fileEventRepository = fileEventRepository;
    }

    public AlertManager(IncidentRepository incidentRepository, FileEventRepository fileEventRepository,
                        com.ransomshield.defense.DefenseManager defenseManager) {
        this.incidentRepository = incidentRepository;
        this.fileEventRepository = fileEventRepository;
        this.defenseManager = defenseManager;
    }

    public void setDefenseManager(com.ransomshield.defense.DefenseManager defenseManager) {
        this.defenseManager = defenseManager;
    }

    public com.ransomshield.defense.DefenseManager getDefenseManager() {
        return defenseManager;
    }

    public void addListener(AlertListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public void removeListener(AlertListener listener) {
        listeners.remove(listener);
    }

    /**
     * Dispatches an event processed notification to listeners and persists event.
     */
    public void notifyEventProcessed(FileEvent event) {
        String incidentId = (activeIncident != null) ? activeIncident.getId() : null;
        if (activeIncident != null && event != null && event.getPath() != null) {
            activeIncident.addAffectedPath(event.getPath().toAbsolutePath().normalize().toString());
        }
        if (fileEventRepository != null) {
            fileEventRepository.save(event, incidentId);
        }
        for (AlertListener listener : listeners) {
            try {
                listener.onEventProcessed(event);
            } catch (Exception e) {
                logger.warn("Error in AlertListener.onEventProcessed: {}", e.getMessage());
            }
        }
    }

    /**
     * Evaluates a threat assessment. If elevated (SUSPICIOUS/HIGH/CRITICAL), groups into an incident
     * and notifies listeners.
     */
    public synchronized void handleAssessment(ThreatAssessment assessment, String rootDirectory) {
        // Broadcast assessment update to all listeners
        for (AlertListener listener : listeners) {
            try {
                listener.onThreatAssessed(assessment);
            } catch (Exception e) {
                logger.warn("Error in AlertListener.onThreatAssessed: {}", e.getMessage());
            }
        }

        Instant now = Instant.now();
        ThreatLevel level = assessment.getThreatLevel();

        if (level == ThreatLevel.NORMAL) {
            // Check if active incident has expired its grouping window
            if (activeIncident != null && lastElevationTime != null &&
                    Duration.between(lastElevationTime, now).compareTo(INCIDENT_GROUPING_WINDOW) > 0) {
                logger.info("Active incident {} stabilized and closed.", activeIncident.getId());
                activeIncident = null;
                lastElevationTime = null;
            }
            return;
        }

        // Threat is elevated (SUSPICIOUS, HIGH, or CRITICAL)
        lastElevationTime = now;
        String reasonsSummary = String.join("; ", assessment.getReasons());

        if (activeIncident == null) {
            // Create a new incident
            activeIncident = new Incident(assessment, rootDirectory, reasonsSummary);
            activeIncident.setFirstSeen(now);
            activeIncident.setLastSeen(now);
            if (incidentRepository != null) {
                incidentRepository.save(activeIncident);
            }
            logger.warn("ALERT: New {} Incident raised (Score: {}/100, ID: {})",
                    level, assessment.getScore(), activeIncident.getId());

            for (AlertListener listener : listeners) {
                try {
                    listener.onIncidentRaised(activeIncident);
                } catch (Exception e) {
                    logger.warn("Error in AlertListener.onIncidentRaised: {}", e.getMessage());
                }
            }
        } else {
            // Update the existing active incident with higher/latest severity and metrics
            if (assessment.getScore() > activeIncident.getScore()) {
                activeIncident.setScore(assessment.getScore());
                activeIncident.setSeverity(level);
            }
            activeIncident.setLastSeen(now);
            activeIncident.setFilesAffected(Math.max(activeIncident.getFilesAffected(), assessment.getAffectedFiles()));
            activeIncident.setDirectoriesAffected(Math.max(activeIncident.getDirectoriesAffected(), assessment.getAffectedDirectories()));
            activeIncident.setAverageEntropy(assessment.getAverageEntropy());
            activeIncident.setMaxEntropy(Math.max(activeIncident.getMaxEntropy(), assessment.getMaxEntropy()));
            activeIncident.setModificationRate(Math.max(activeIncident.getModificationRate(), assessment.getModificationRate()));
            activeIncident.setOperationSummary(reasonsSummary);

            if (incidentRepository != null) {
                incidentRepository.save(activeIncident);
            }

            for (AlertListener listener : listeners) {
                try {
                    listener.onIncidentRaised(activeIncident);
                } catch (Exception e) {
                    logger.warn("Error in AlertListener.onIncidentRaised update: {}", e.getMessage());
                }
            }
        }

        if (defenseManager != null) {
            try {
                defenseManager.processAssessment(assessment, activeIncident, rootDirectory);
            } catch (Exception e) {
                logger.warn("Error in defenseManager.processAssessment: {}", e.getMessage());
            }
        }
    }

    public Incident getActiveIncident() {
        return activeIncident;
    }
}
