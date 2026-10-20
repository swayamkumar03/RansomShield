package com.ransomshield.defense;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Result of executing an incident response action (simulated or real).
 */
public class ResponseResult {
    private final boolean success;
    private final boolean simulated;
    private final ResponseAction action;
    private final String message;
    private final List<String> affectedItems;
    private final Instant timestamp;
    private final String errorDetails;

    public ResponseResult(boolean success, boolean simulated, ResponseAction action,
                          String message, List<String> affectedItems, Instant timestamp, String errorDetails) {
        this.success = success;
        this.simulated = simulated;
        this.action = action;
        this.message = message != null ? message : "";
        this.affectedItems = affectedItems != null ? Collections.unmodifiableList(new ArrayList<>(affectedItems)) : Collections.emptyList();
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.errorDetails = errorDetails != null ? errorDetails : "";
    }

    public static ResponseResult successSimulated(ResponseAction action, String message, List<String> affectedItems) {
        return new ResponseResult(true, true, action, message, affectedItems, Instant.now(), null);
    }

    public static ResponseResult successReal(ResponseAction action, String message, List<String> affectedItems) {
        return new ResponseResult(true, false, action, message, affectedItems, Instant.now(), null);
    }

    public static ResponseResult failure(ResponseAction action, String message, String errorDetails) {
        return new ResponseResult(false, false, action, message, Collections.emptyList(), Instant.now(), errorDetails);
    }

    public boolean isSuccess() {
        return success;
    }

    public boolean isSimulated() {
        return simulated;
    }

    public ResponseAction getAction() {
        return action;
    }

    public String getMessage() {
        return message;
    }

    public List<String> getAffectedItems() {
        return affectedItems;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getErrorDetails() {
        return errorDetails;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s: %s (%s)",
                simulated ? "SIMULATED" : "REAL",
                action,
                message,
                success ? "SUCCESS" : "FAILED: " + errorDetails);
    }
}
