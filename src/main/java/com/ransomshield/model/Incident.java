package com.ransomshield.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Encapsulates an aggregated behavioral security incident logged by RansomShield.
 */
public class Incident {
    private final String id;
    private final Instant timestamp;
    private ThreatLevel severity;
    private int score;
    private String rootDirectory;
    private int filesAffected;
    private int directoriesAffected;
    private double averageEntropy;
    private double maxEntropy;
    private double modificationRate;
    private String operationSummary;
    private IncidentStatus status;
    private final List<String> reasons = new ArrayList<>();
    private Instant firstSeen;
    private Instant lastSeen;
    private final List<String> affectedPaths = new ArrayList<>();
    private String responseAction = "NONE";
    private String responseResult = "";
    private boolean isSimulated = true;

    public Incident(String id, Instant timestamp, ThreatLevel severity, int score, String rootDirectory,
                    int filesAffected, int directoriesAffected, double averageEntropy, double maxEntropy,
                    double modificationRate, String operationSummary, IncidentStatus status, List<String> reasons) {
        this.id = id != null ? id : UUID.randomUUID().toString();
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.firstSeen = this.timestamp;
        this.lastSeen = this.timestamp;
        this.severity = severity != null ? severity : ThreatLevel.NORMAL;
        this.score = score;
        this.rootDirectory = rootDirectory != null ? rootDirectory : "";
        this.filesAffected = filesAffected;
        this.directoriesAffected = directoriesAffected;
        this.averageEntropy = averageEntropy;
        this.maxEntropy = maxEntropy;
        this.modificationRate = modificationRate;
        this.operationSummary = operationSummary != null ? operationSummary : "";
        this.status = status != null ? status : IncidentStatus.OPEN;
        if (reasons != null) {
            this.reasons.addAll(reasons);
        }
    }

    public Incident(ThreatAssessment assessment, String rootDirectory, String operationSummary) {
        this(
                UUID.randomUUID().toString(),
                assessment.getTimestamp(),
                assessment.getThreatLevel(),
                assessment.getScore(),
                rootDirectory,
                assessment.getAffectedFiles(),
                assessment.getAffectedDirectories(),
                assessment.getAverageEntropy(),
                assessment.getMaxEntropy(),
                assessment.getModificationRate(),
                operationSummary,
                IncidentStatus.DETECTED,
                assessment.getReasons()
        );
    }

    public String getId() {
        return id;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public ThreatLevel getSeverity() {
        return severity;
    }

    public void setSeverity(ThreatLevel severity) {
        this.severity = severity;
    }

    public int getScore() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public String getRootDirectory() {
        return rootDirectory;
    }

    public void setRootDirectory(String rootDirectory) {
        this.rootDirectory = rootDirectory;
    }

    public int getFilesAffected() {
        return filesAffected;
    }

    public void setFilesAffected(int filesAffected) {
        this.filesAffected = filesAffected;
    }

    public int getDirectoriesAffected() {
        return directoriesAffected;
    }

    public void setDirectoriesAffected(int directoriesAffected) {
        this.directoriesAffected = directoriesAffected;
    }

    public double getAverageEntropy() {
        return averageEntropy;
    }

    public void setAverageEntropy(double averageEntropy) {
        this.averageEntropy = averageEntropy;
    }

    public double getMaxEntropy() {
        return maxEntropy;
    }

    public void setMaxEntropy(double maxEntropy) {
        this.maxEntropy = maxEntropy;
    }

    public double getModificationRate() {
        return modificationRate;
    }

    public void setModificationRate(double modificationRate) {
        this.modificationRate = modificationRate;
    }

    public String getOperationSummary() {
        return operationSummary;
    }

    public void setOperationSummary(String operationSummary) {
        this.operationSummary = operationSummary;
    }

    public IncidentStatus getStatus() {
        return status;
    }

    public void setStatus(IncidentStatus status) {
        this.status = status;
    }

    public List<String> getReasons() {
        return new ArrayList<>(reasons);
    }

    public void addReason(String reason) {
        if (reason != null && !reason.isBlank() && !this.reasons.contains(reason)) {
            this.reasons.add(reason);
        }
    }

    public Instant getFirstSeen() {
        return firstSeen != null ? firstSeen : timestamp;
    }

    public void setFirstSeen(Instant firstSeen) {
        this.firstSeen = firstSeen;
    }

    public Instant getLastSeen() {
        return lastSeen != null ? lastSeen : timestamp;
    }

    public void setLastSeen(Instant lastSeen) {
        this.lastSeen = lastSeen;
    }

    public List<String> getAffectedPaths() {
        return new ArrayList<>(affectedPaths);
    }

    public void setAffectedPaths(List<String> paths) {
        this.affectedPaths.clear();
        if (paths != null) {
            this.affectedPaths.addAll(paths);
        }
    }

    public void addAffectedPath(String path) {
        if (path != null && !path.isBlank() && !this.affectedPaths.contains(path)) {
            this.affectedPaths.add(path);
        }
    }

    public String getResponseAction() {
        return responseAction != null ? responseAction : "NONE";
    }

    public void setResponseAction(String responseAction) {
        this.responseAction = responseAction;
    }

    public String getResponseResult() {
        return responseResult != null ? responseResult : "";
    }

    public void setResponseResult(String responseResult) {
        this.responseResult = responseResult;
    }

    public boolean isSimulated() {
        return isSimulated;
    }

    public void setSimulated(boolean simulated) {
        isSimulated = simulated;
    }
}
