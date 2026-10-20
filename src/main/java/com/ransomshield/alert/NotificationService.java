package com.ransomshield.alert;

import com.ransomshield.model.Incident;
import com.ransomshield.model.ThreatLevel;
import javafx.application.Platform;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.*;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Enterprise alerting service managing in-app alert history, desktop tray notifications,
 * alert deduplication, and rate limiting.
 */
public class NotificationService {
    private static final Logger logger = LoggerFactory.getLogger(NotificationService.class);

    public record AlertMessage(
            String id,
            Instant timestamp,
            ThreatLevel severity,
            int score,
            String affectedPath,
            String reasonsSummary,
            String incidentId
    ) {}

    public interface InAppNotificationListener {
        void onNotification(AlertMessage message);
    }

    private final List<InAppNotificationListener> listeners = new CopyOnWriteArrayList<>();
    private final List<AlertMessage> alertHistory = new CopyOnWriteArrayList<>();

    // Rate limiting & deduplication cache: incidentId -> lastNotificationTimestamp
    private final Map<String, Instant> lastAlertTimes = new ConcurrentHashMap<>();
    private static final Duration DESKTOP_RATE_LIMIT = Duration.ofSeconds(5);

    private TrayIcon trayIcon;
    private boolean systemTrayAvailable = false;

    public NotificationService() {
        initSystemTray();
    }

    private void initSystemTray() {
        try {
            if (!GraphicsEnvironment.isHeadless() && SystemTray.isSupported()) {
                SystemTray tray = SystemTray.getSystemTray();
                // Create a basic 16x16 icon in memory for the tray
                int size = 16;
                java.awt.image.BufferedImage img = new java.awt.image.BufferedImage(size, size, java.awt.image.BufferedImage.TYPE_INT_ARGB);
                Graphics2D g2 = img.createGraphics();
                g2.setColor(new Color(6, 182, 212));
                g2.fillOval(1, 1, size - 2, size - 2);
                g2.setColor(new Color(11, 15, 25));
                g2.fillRect(4, 4, size - 8, size - 8);
                g2.dispose();

                trayIcon = new TrayIcon(img, "RansomShield Defensive Monitor");
                trayIcon.setImageAutoSize(true);
                tray.add(trayIcon);
                systemTrayAvailable = true;
                logger.info("SystemTray desktop notifications initialized successfully");
            } else {
                logger.info("SystemTray not supported or running in headless mode; using in-app notification fallback");
            }
        } catch (Throwable t) {
            logger.warn("Could not initialize SystemTray (using in-app alerts fallback): {}", t.getMessage());
            systemTrayAvailable = false;
        }
    }

    public void addListener(InAppNotificationListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public void removeListener(InAppNotificationListener listener) {
        listeners.remove(listener);
    }

    /**
     * Dispatches an alert with deduplication and desktop rate limiting.
     */
    public void dispatchAlert(ThreatLevel severity, int score, String affectedPath,
                              List<String> reasons, Incident incident) {
        if (severity == ThreatLevel.NORMAL) {
            return;
        }

        String incidentId = incident != null ? incident.getId() : "global";
        Instant now = Instant.now();
        Instant lastSent = lastAlertTimes.get(incidentId);

        String reasonsSummary = (reasons != null && !reasons.isEmpty())
                ? String.join("; ", reasons)
                : "Behavioral anomaly thresholds exceeded";

        AlertMessage msg = new AlertMessage(
                java.util.UUID.randomUUID().toString(),
                now,
                severity,
                score,
                affectedPath != null ? affectedPath : "",
                reasonsSummary,
                incidentId
        );

        // Store in alert history (capped at 100)
        alertHistory.add(0, msg);
        if (alertHistory.size() > 100) {
            alertHistory.remove(alertHistory.size() - 1);
        }

        // Notify in-app UI listeners asynchronously on JavaFX thread (or directly if headless test)
        for (InAppNotificationListener listener : listeners) {
            try {
                try {
                    if (Platform.isFxApplicationThread()) {
                        listener.onNotification(msg);
                    } else {
                        Platform.runLater(() -> listener.onNotification(msg));
                    }
                } catch (IllegalStateException e) {
                    // JavaFX Toolkit not running (e.g. headless unit tests)
                    listener.onNotification(msg);
                }
            } catch (Exception e) {
                logger.warn("Error delivering in-app notification: {}", e.getMessage());
            }
        }

        // Rate limit desktop balloon popups
        if (systemTrayAvailable && trayIcon != null) {
            if (lastSent == null || Duration.between(lastSent, now).compareTo(DESKTOP_RATE_LIMIT) >= 0) {
                lastAlertTimes.put(incidentId, now);
                displayDesktopNotification(msg);
            }
        }
    }

    private void displayDesktopNotification(AlertMessage msg) {
        try {
            TrayIcon.MessageType type = switch (msg.severity()) {
                case CRITICAL -> TrayIcon.MessageType.ERROR;
                case HIGH, SUSPICIOUS -> TrayIcon.MessageType.WARNING;
                default -> TrayIcon.MessageType.INFO;
            };

            String caption = String.format("RansomShield Alert: %s (Score %d/100)", msg.severity(), msg.score());
            String text = String.format("%s\nPath: %s", msg.reasonsSummary(), msg.affectedPath());
            if (text.length() > 200) {
                text = text.substring(0, 197) + "...";
            }

            trayIcon.displayMessage(caption, text, type);
        } catch (Throwable t) {
            logger.debug("Desktop notification error: {}", t.getMessage());
        }
    }

    public List<AlertMessage> getRecentAlerts() {
        return new CopyOnWriteArrayList<>(alertHistory);
    }

    public void clearHistory() {
        alertHistory.clear();
        lastAlertTimes.clear();
    }
}
