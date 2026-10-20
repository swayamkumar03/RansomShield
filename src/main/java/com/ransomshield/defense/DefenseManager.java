package com.ransomshield.defense;

import com.ransomshield.alert.NotificationService;
import com.ransomshield.database.IncidentRepository;
import com.ransomshield.model.Incident;
import com.ransomshield.model.IncidentStatus;
import com.ransomshield.model.ThreatAssessment;
import com.ransomshield.model.ThreatLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Central incident response orchestrator implementing risk-based active defense,
 * containment dispatch, sandboxed quarantine, and defensive audit logging.
 */
public class DefenseManager {
    private static final Logger logger = LoggerFactory.getLogger(DefenseManager.class);

    public interface DefenseListener {
        void onResponseAction(ResponseResult result, Incident incident);
    }

    private final IncidentRepository incidentRepository;
    private final QuarantineService quarantineService;
    private final ProcessContainmentService processContainmentService;
    private final DefensePolicy defensePolicy;
    private final NotificationService notificationService;

    private final AtomicBoolean activeDefenseEnabled = new AtomicBoolean(true);
    private final AtomicBoolean safeSimulationMode = new AtomicBoolean(true);

    private final List<DefenseListener> defenseListeners = new CopyOnWriteArrayList<>();

    public DefenseManager(IncidentRepository incidentRepository,
                          QuarantineService quarantineService,
                          ProcessContainmentService processContainmentService,
                          DefensePolicy defensePolicy,
                          NotificationService notificationService) {
        this.incidentRepository = incidentRepository;
        this.quarantineService = quarantineService;
        this.processContainmentService = processContainmentService;
        this.defensePolicy = defensePolicy != null ? defensePolicy : new DefensePolicy();
        this.notificationService = notificationService;
    }

    public void addListener(DefenseListener listener) {
        if (listener != null && !defenseListeners.contains(listener)) {
            defenseListeners.add(listener);
        }
    }

    public void removeListener(DefenseListener listener) {
        defenseListeners.remove(listener);
    }

    public boolean isActiveDefenseEnabled() {
        return activeDefenseEnabled.get();
    }

    public void setActiveDefenseEnabled(boolean enabled) {
        this.activeDefenseEnabled.set(enabled);
        logger.info("Active Defense is now: {}", enabled ? "ENABLED" : "DISABLED");
    }

    public boolean isSafeSimulationMode() {
        return safeSimulationMode.get();
    }

    public void setSafeSimulationMode(boolean simulationMode) {
        this.safeSimulationMode.set(simulationMode);
        logger.info("Defense Simulation Mode is now: {}", simulationMode ? "SAFE SIMULATION" : "LIVE ACTION");
    }

    public DefensePolicy getDefensePolicy() {
        return defensePolicy;
    }

    public QuarantineService getQuarantineService() {
        return quarantineService;
    }

    public ProcessContainmentService getProcessContainmentService() {
        return processContainmentService;
    }

    public NotificationService getNotificationService() {
        return notificationService;
    }

    /**
     * Evaluates a threat assessment against policy and coordinates alerting.
     */
    public DefensePolicy.PolicyDecision processAssessment(ThreatAssessment assessment, Incident incident, String monitoredDir) {
        DefensePolicy.PolicyDecision decision = defensePolicy.evaluate(assessment, incident);

        if (!activeDefenseEnabled.get()) {
            return decision;
        }

        if (decision.isRequiresNotification() && notificationService != null) {
            String affectedPath = incident != null && !incident.getAffectedPaths().isEmpty()
                    ? incident.getAffectedPaths().get(0)
                    : monitoredDir;

            notificationService.dispatchAlert(
                    assessment.getThreatLevel(),
                    assessment.getScore(),
                    affectedPath,
                    assessment.getReasons(),
                    incident
            );
        }

        return decision;
    }

    /**
     * Executes safe simulated containment.
     * Records defensive actions into the incident history without modifying disk or terminating processes.
     */
    public ResponseResult simulateContainment(Incident incident) {
        if (incident == null) {
            return ResponseResult.failure(ResponseAction.SIMULATE_CONTAINMENT, "No active incident to contain", "Null incident reference");
        }

        String msg = String.format(
                "SIMULATED CONTAINMENT: Evaluated incident %s (Threat Score %d/100, %s). " +
                "Simulated isolation of %d affected file(s) and defensive process lock. " +
                "Zero disk or process mutations executed.",
                incident.getId().substring(0, Math.min(8, incident.getId().length())),
                incident.getScore(),
                incident.getSeverity(),
                incident.getFilesAffected()
        );

        incident.setStatus(IncidentStatus.CONTAINED);
        incident.setResponseAction("SIMULATE_CONTAINMENT");
        incident.setSimulated(true);
        incident.setResponseResult(msg);
        incident.setLastSeen(Instant.now());

        if (incidentRepository != null) {
            incidentRepository.save(incident);
        }

        ResponseResult result = ResponseResult.successSimulated(
                ResponseAction.SIMULATE_CONTAINMENT,
                msg,
                incident.getAffectedPaths()
        );

        notifyListeners(result, incident);
        logger.info("Executed safe simulated containment for incident {}", incident.getId());
        return result;
    }

    /**
     * Executes validated file quarantine within the designated scope root.
     */
    public ResponseResult quarantineIncidentFiles(Incident incident, Path allowedScopeRoot) {
        if (incident == null) {
            return ResponseResult.failure(ResponseAction.QUARANTINE_FILES, "No incident specified", "Null incident reference");
        }
        if (allowedScopeRoot == null) {
            return ResponseResult.failure(ResponseAction.QUARANTINE_FILES, "Scope root not specified", "Null scope path");
        }

        List<String> pathsToQuarantine = incident.getAffectedPaths();
        if (pathsToQuarantine.isEmpty()) {
            return ResponseResult.failure(ResponseAction.QUARANTINE_FILES, "No affected file paths tracked for incident", "Empty file list");
        }

        ResponseResult result = quarantineService.quarantineFiles(pathsToQuarantine, allowedScopeRoot, incident.getId());

        if (result.isSuccess()) {
            incident.setStatus(IncidentStatus.CONTAINED);
            incident.setResponseAction("QUARANTINE_FILES");
            incident.setSimulated(false);
            incident.setResponseResult(result.getMessage());
        } else {
            incident.setStatus(IncidentStatus.FAILED);
            incident.setResponseAction("QUARANTINE_FILES");
            incident.setResponseResult("FAILED: " + result.getErrorDetails());
        }
        incident.setLastSeen(Instant.now());

        if (incidentRepository != null) {
            incidentRepository.save(incident);
        }

        notifyListeners(result, incident);
        return result;
    }

    /**
     * Safely restores quarantined files belonging to an incident or all quarantined files in scope.
     */
    public ResponseResult restoreQuarantinedFiles(Incident incident, Path allowedScopeRoot) {
        String incidentId = incident != null ? incident.getId() : null;
        ResponseResult result = quarantineService.restoreQuarantinedFiles(incidentId, allowedScopeRoot);

        if (incident != null) {
            if (result.isSuccess()) {
                incident.setStatus(IncidentStatus.RESOLVED);
                incident.setResponseAction("RESTORE_FILES");
                incident.setResponseResult(result.getMessage());
            }
            incident.setLastSeen(Instant.now());
            if (incidentRepository != null) {
                incidentRepository.save(incident);
            }
        }

        notifyListeners(result, incident);
        return result;
    }

    public void acknowledgeIncident(Incident incident) {
        if (incident == null) return;
        incident.setStatus(IncidentStatus.ACKNOWLEDGED);
        incident.setLastSeen(Instant.now());
        if (incidentRepository != null) {
            incidentRepository.save(incident);
        }
        logger.info("Incident {} marked as ACKNOWLEDGED", incident.getId());
    }

    public void resolveIncident(Incident incident) {
        if (incident == null) return;
        incident.setStatus(IncidentStatus.RESOLVED);
        incident.setLastSeen(Instant.now());
        if (incidentRepository != null) {
            incidentRepository.save(incident);
        }
        logger.info("Incident {} marked as RESOLVED", incident.getId());
    }

    private void notifyListeners(ResponseResult result, Incident incident) {
        for (DefenseListener listener : defenseListeners) {
            try {
                listener.onResponseAction(result, incident);
            } catch (Exception e) {
                logger.warn("Error in DefenseListener callback: {}", e.getMessage());
            }
        }
    }
}
