package com.ransomshield.ui;

import com.ransomshield.RansomShieldEngine;
import com.ransomshield.alert.NotificationService;
import com.ransomshield.defense.DefensePolicy;
import com.ransomshield.defense.ResponseAction;
import com.ransomshield.defense.ResponseResult;
import com.ransomshield.model.FileEvent;
import com.ransomshield.model.Incident;
import com.ransomshield.model.IncidentStatus;
import com.ransomshield.model.ThreatAssessment;
import com.ransomshield.model.ThreatLevel;
import com.ransomshield.util.FileUtils;
import com.ransomshield.util.TimeUtils;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Main real-time security dashboard view presenting live KPIs, event feed,
 * threat diagnostics, and active incident response controls.
 */
public class DashboardView extends BorderPane {

    private RansomShieldEngine engine;
    private final ObservableList<FileEvent> eventFeedList = FXCollections.observableArrayList();

    // Top KPI Labels
    private final Label lblScore = new Label("0");
    private final ProgressBar barScore = new ProgressBar(0.0);
    private final Label lblThreatLevel = new Label("NORMAL");
    private final Label lblFilesAffected = new Label("0");
    private final Label lblModRate = new Label("0.0 files/s");
    private final Label lblAvgEntropy = new Label("0.00 bits");
    private final Label lblEntropySub = new Label("Max: 0.00 bits");

    // Diagnostic Panel
    private final VBox alertBanner = new VBox(6);
    private final Label lblBannerTitle = new Label("SYSTEM SAFE");
    private final Label lblBannerSubtitle = new Label("No suspicious filesystem anomalies detected.");

    // Active Defence Section Controls
    private final Label lblDefenseStatus = new Label("DEFENSE: ACTIVE");
    private final Label lblSimModeBadge = new Label("SAFE SIMULATION MODE");
    private final Label lblActiveIncidentInfo = new Label("Active Incident: None");
    private final Label lblOpenIncidents = new Label("Open Incidents: 0");
    private final Label lblRecommendedAction = new Label("Policy: Continuous Monitoring");

    private final Button btnToggleDefense = new Button("Disable Defense");
    private final Button btnSimulateContainment = new Button("Simulate Containment");
    private final Button btnQuarantine = new Button("Quarantine Files");
    private final Button btnRestoreQuarantine = new Button("Restore Quarantined");
    private final Button btnAcknowledge = new Button("Acknowledge");
    private final Button btnResolve = new Button("Resolve");
    private final Button btnViewEvidence = new Button("Incident Evidence");

    private final ListView<String> alertFeedListView = new ListView<>();

    // Score factor progress bars
    private final ProgressBar barEntropyFactor = new ProgressBar(0.0);
    private final Label lblEntropyFactorVal = new Label("0 / 20 pts");

    private final ProgressBar barRateFactor = new ProgressBar(0.0);
    private final Label lblRateFactorVal = new Label("0 / 20 pts");

    private final ProgressBar barFilesFactor = new ProgressBar(0.0);
    private final Label lblFilesFactorVal = new Label("0 / 20 pts");

    private final ProgressBar barDirsFactor = new ProgressBar(0.0);
    private final Label lblDirsFactorVal = new Label("0 / 10 pts");

    private final ProgressBar barPatternFactor = new ProgressBar(0.0);
    private final Label lblPatternFactorVal = new Label("0 / 20 pts");

    private final ListView<String> reasonsListView = new ListView<>();
    private final TableView<FileEvent> eventTableView = new TableView<>();

    public DashboardView(RansomShieldEngine engine) {
        this.engine = engine;
        setPadding(new Insets(16));
        setTop(buildTopKpiSection());
        setCenter(buildCenterContent());

        if (engine != null && engine.getNotificationService() != null) {
            engine.getNotificationService().addListener(msg -> {
                String entry = String.format("[%s] %s | Score %d | %s",
                        TimeUtils.formatTimeOnly(msg.timestamp()),
                        msg.severity(),
                        msg.score(),
                        msg.reasonsSummary());
                Platform.runLater(() -> {
                    alertFeedListView.getItems().add(0, entry);
                    if (alertFeedListView.getItems().size() > 50) {
                        alertFeedListView.getItems().remove(alertFeedListView.getItems().size() - 1);
                    }
                });
            });
        }
    }

    public DashboardView() {
        this(null);
    }

    private VBox buildTopKpiSection() {
        VBox container = new VBox(12);
        container.setPadding(new Insets(0, 0, 16, 0));

        HBox kpiGrid = new HBox(12);
        kpiGrid.setAlignment(Pos.CENTER_LEFT);

        // Card 1: Threat Score
        VBox cardScore = createCard("THREAT SCORE", lblScore, "Range: 0 - 100");
        lblScore.getStyleClass().add("kpi-value");
        barScore.setPrefWidth(160);
        barScore.getStyleClass().add("threat-progress");
        cardScore.getChildren().add(1, barScore);

        // Card 2: Threat Level
        VBox cardLevel = createCard("THREAT LEVEL", lblThreatLevel, "Behavioral Classification");
        lblThreatLevel.getStyleClass().addAll("badge", "badge-normal");
        lblThreatLevel.setStyle("-fx-font-size: 16px; -fx-padding: 6px 16px;");

        // Card 3: Files Touched
        VBox cardFiles = createCard("FILES TOUCHED", lblFilesAffected, "Within sliding window");
        lblFilesAffected.getStyleClass().add("kpi-value");

        // Card 4: Modification Rate
        VBox cardRate = createCard("MODIFICATION RATE", lblModRate, "Burst frequency");
        lblModRate.getStyleClass().add("kpi-value");

        // Card 5: Shannon Entropy
        VBox cardEntropy = createCard("AVG SHANNON ENTROPY", lblAvgEntropy, "");
        lblAvgEntropy.getStyleClass().add("kpi-value");
        lblEntropySub.getStyleClass().add("kpi-subtitle");
        cardEntropy.getChildren().add(lblEntropySub);

        kpiGrid.getChildren().addAll(cardScore, cardLevel, cardFiles, cardRate, cardEntropy);
        HBox.setHgrow(cardScore, Priority.ALWAYS);
        HBox.setHgrow(cardLevel, Priority.ALWAYS);
        HBox.setHgrow(cardFiles, Priority.ALWAYS);
        HBox.setHgrow(cardRate, Priority.ALWAYS);
        HBox.setHgrow(cardEntropy, Priority.ALWAYS);

        container.getChildren().add(kpiGrid);
        return container;
    }

    private VBox createCard(String title, Label mainLabel, String subtitle) {
        VBox card = new VBox(6);
        card.getStyleClass().add("kpi-card");
        Label lblTitle = new Label(title);
        lblTitle.getStyleClass().add("kpi-title");
        Label lblSub = new Label(subtitle);
        lblSub.getStyleClass().add("kpi-subtitle");
        card.getChildren().addAll(lblTitle, mainLabel, lblSub);
        return card;
    }

    private SplitPane buildCenterContent() {
        SplitPane split = new SplitPane();
        split.setDividerPositions(0.62);

        // Left side: Event feed
        VBox leftPane = new VBox(10);
        leftPane.setPadding(new Insets(0, 8, 0, 0));

        HBox feedHeader = new HBox(10);
        feedHeader.setAlignment(Pos.CENTER_LEFT);
        Label lblFeedTitle = new Label("REAL-TIME FILESYSTEM EVENT STREAM");
        lblFeedTitle.setStyle("-fx-font-size: 13px; -fx-font-weight: bold; -fx-text-fill: #38bdf8;");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button btnClearFeed = new Button("Clear Feed");
        btnClearFeed.getStyleClass().add("btn-secondary");
        btnClearFeed.setOnAction(e -> eventFeedList.clear());

        feedHeader.getChildren().addAll(lblFeedTitle, spacer, btnClearFeed);

        setupEventTable();
        VBox.setVgrow(eventTableView, Priority.ALWAYS);
        leftPane.getChildren().addAll(feedHeader, eventTableView);

        // Right side: Threat diagnostics & Active Defense
        VBox rightPane = new VBox(12);
        rightPane.setPadding(new Insets(0, 6, 0, 6));

        // 1. Alert Banner
        alertBanner.getStyleClass().addAll("alert-banner", "alert-banner-normal");
        lblBannerTitle.setStyle("-fx-font-size: 15px; -fx-font-weight: bold;");
        lblBannerSubtitle.setStyle("-fx-font-size: 12px; -fx-text-fill: #94a3b8;");
        alertBanner.getChildren().addAll(lblBannerTitle, lblBannerSubtitle);

        // 2. Active Defence Section
        VBox defenseCard = buildActiveDefenseSection();

        // 3. Score Factor Breakdown Box
        VBox factorBox = new VBox(8);
        factorBox.getStyleClass().add("kpi-card");
        Label lblFactorTitle = new Label("MULTI-FACTOR SCORING DECOMPOSITION");
        lblFactorTitle.getStyleClass().add("kpi-title");

        factorBox.getChildren().addAll(
                lblFactorTitle,
                createFactorRow("Shannon Entropy (max 20)", barEntropyFactor, lblEntropyFactorVal),
                createFactorRow("Modification Rate (max 20)", barRateFactor, lblRateFactorVal),
                createFactorRow("Volume of Files (max 20)", barFilesFactor, lblFilesFactorVal),
                createFactorRow("Directory Traversal (max 10)", barDirsFactor, lblDirsFactorVal),
                createFactorRow("Operation Anomaly (max 20)", barPatternFactor, lblPatternFactorVal)
        );

        // 4. Reasons Box
        VBox reasonsBox = new VBox(8);
        reasonsBox.getStyleClass().add("kpi-card");
        Label lblReasonsTitle = new Label("BEHAVIORAL ANOMALY REASONS");
        lblReasonsTitle.getStyleClass().add("kpi-title");
        reasonsListView.setPrefHeight(110);
        reasonsListView.setStyle("-fx-background-color: #0b0f19; -fx-border-color: #1e293b;");
        reasonsBox.getChildren().addAll(lblReasonsTitle, reasonsListView);

        rightPane.getChildren().addAll(alertBanner, defenseCard, factorBox, reasonsBox);

        ScrollPane rightScroll = new ScrollPane(rightPane);
        rightScroll.setFitToWidth(true);
        rightScroll.setStyle("-fx-background: transparent; -fx-background-color: transparent; -fx-border-color: transparent;");

        split.getItems().addAll(leftPane, rightScroll);
        return split;
    }

    private VBox buildActiveDefenseSection() {
        VBox card = new VBox(10);
        card.getStyleClass().add("kpi-card");

        // Header: Title + Badges
        HBox header = new HBox(8);
        header.setAlignment(Pos.CENTER_LEFT);
        Label lblTitle = new Label("ACTIVE DEFENCE & INCIDENT RESPONSE");
        lblTitle.getStyleClass().add("kpi-title");

        lblSimModeBadge.getStyleClass().addAll("badge", "badge-simulated");
        lblDefenseStatus.getStyleClass().addAll("badge", "badge-normal");

        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);

        header.getChildren().addAll(lblTitle, sp, lblSimModeBadge, lblDefenseStatus);

        // Status row
        HBox statusRow = new HBox(12);
        statusRow.setAlignment(Pos.CENTER_LEFT);
        lblActiveIncidentInfo.setStyle("-fx-font-size: 11px; -fx-text-fill: #cbd5e1;");
        lblOpenIncidents.setStyle("-fx-font-size: 11px; -fx-font-weight: bold; -fx-text-fill: #38bdf8;");
        lblRecommendedAction.setStyle("-fx-font-size: 11px; -fx-font-weight: bold; -fx-text-fill: #f59e0b;");
        statusRow.getChildren().addAll(lblActiveIncidentInfo, lblOpenIncidents, lblRecommendedAction);

        // Action Buttons Row 1 (Containment & Quarantine)
        HBox actionsRow1 = new HBox(8);
        actionsRow1.setAlignment(Pos.CENTER_LEFT);

        btnSimulateContainment.getStyleClass().add("btn-primary");
        btnSimulateContainment.setOnAction(e -> handleSimulateContainment());

        btnQuarantine.getStyleClass().add("btn-warning");
        btnQuarantine.setOnAction(e -> handleQuarantineFiles());

        btnRestoreQuarantine.getStyleClass().add("btn-secondary");
        btnRestoreQuarantine.setOnAction(e -> handleRestoreQuarantined());

        actionsRow1.getChildren().addAll(btnSimulateContainment, btnQuarantine, btnRestoreQuarantine);

        // Action Buttons Row 2 (Acknowledge, Resolve, Evidence, Toggle)
        HBox actionsRow2 = new HBox(8);
        actionsRow2.setAlignment(Pos.CENTER_LEFT);

        btnAcknowledge.getStyleClass().add("btn-secondary");
        btnAcknowledge.setOnAction(e -> handleAcknowledge());

        btnResolve.getStyleClass().add("btn-success");
        btnResolve.setOnAction(e -> handleResolve());

        btnViewEvidence.getStyleClass().add("btn-secondary");
        btnViewEvidence.setOnAction(e -> handleViewEvidence());

        btnToggleDefense.getStyleClass().add("btn-secondary");
        btnToggleDefense.setOnAction(e -> handleToggleDefense());

        actionsRow2.getChildren().addAll(btnAcknowledge, btnResolve, btnViewEvidence, btnToggleDefense);

        // In-App Alert Feed snippet
        VBox alertFeedBox = new VBox(4);
        Label lblAlertFeed = new Label("IN-APP DEFENSIVE ALERT LOG");
        lblAlertFeed.setStyle("-fx-font-size: 10px; -fx-font-weight: bold; -fx-text-fill: #94a3b8;");
        alertFeedListView.setPrefHeight(80);
        alertFeedListView.setStyle("-fx-background-color: #0b0f19; -fx-border-color: #1e293b;");
        alertFeedBox.getChildren().addAll(lblAlertFeed, alertFeedListView);

        card.getChildren().addAll(header, statusRow, actionsRow1, actionsRow2, alertFeedBox);
        return card;
    }

    private void handleToggleDefense() {
        if (engine == null || engine.getDefenseManager() == null) return;
        boolean current = engine.getDefenseManager().isActiveDefenseEnabled();
        boolean next = !current;
        engine.getDefenseManager().setActiveDefenseEnabled(next);

        if (next) {
            lblDefenseStatus.setText("DEFENSE: ACTIVE");
            lblDefenseStatus.getStyleClass().removeAll("badge-suspicious");
            lblDefenseStatus.getStyleClass().add("badge-normal");
            btnToggleDefense.setText("Disable Defense");
        } else {
            lblDefenseStatus.setText("DEFENSE: PAUSED");
            lblDefenseStatus.getStyleClass().removeAll("badge-normal");
            lblDefenseStatus.getStyleClass().add("badge-suspicious");
            btnToggleDefense.setText("Enable Defense");
        }
    }

    private void handleSimulateContainment() {
        if (engine == null) return;
        Incident active = engine.getAlertManager().getActiveIncident();
        if (active == null) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("No Active Incident");
            alert.setHeaderText("No Incident Requires Containment");
            alert.setContentText("The system is currently operating within safe baseline parameters.");
            alert.showAndWait();
            return;
        }

        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
        confirm.setTitle("Simulate Containment");
        confirm.setHeaderText("Confirm Safe Simulated Containment");
        confirm.setContentText(String.format(
                "Simulate containment for incident %s?\n\n" +
                "Threat Level: %s (Score %d/100)\n" +
                "Affected Files: %d\n\n" +
                "Result: A simulated isolation record will be logged and marked [SIMULATED]. " +
                "Zero files or processes will be modified on disk.",
                active.getId().substring(0, Math.min(8, active.getId().length())),
                active.getSeverity(),
                active.getScore(),
                active.getFilesAffected()
        ));

        Optional<ButtonType> choice = confirm.showAndWait();
        if (choice.isPresent() && choice.get() == ButtonType.OK) {
            ResponseResult result = engine.getDefenseManager().simulateContainment(active);
            updateIncidentDisplay(active);

            Alert done = new Alert(Alert.AlertType.INFORMATION);
            done.setTitle("Containment Executed");
            done.setHeaderText("Safe Simulated Containment Successful");
            done.setContentText(result.getMessage());
            done.showAndWait();
        }
    }

    private void handleQuarantineFiles() {
        if (engine == null) return;
        Incident active = engine.getAlertManager().getActiveIncident();
        Path scope = engine.getActiveMonitoredPath();
        if (active == null || active.getAffectedPaths().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle("Quarantine Unavailable");
            alert.setHeaderText("No Affected Files Identified");
            alert.setContentText("No specific affected file paths are tracked for the active incident.");
            alert.showAndWait();
            return;
        }

        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
        confirm.setTitle("Confirm File Quarantine");
        confirm.setHeaderText("Execute Sandboxed File Quarantine");
        confirm.setContentText(String.format(
                "Are you sure you want to quarantine %d tracked file(s) into .quarantine?\n\n" +
                "Target Sandbox Scope: %s\n\n" +
                "Files will be moved to .quarantine with full metadata preservation. " +
                "Path traversal outside the test scope is strictly blocked.",
                active.getAffectedPaths().size(),
                scope != null ? scope.toString() : "Current test directory"
        ));

        Optional<ButtonType> choice = confirm.showAndWait();
        if (choice.isPresent() && choice.get() == ButtonType.OK) {
            ResponseResult result = engine.getDefenseManager().quarantineIncidentFiles(active, scope);
            updateIncidentDisplay(active);

            Alert resAlert = new Alert(result.isSuccess() ? Alert.AlertType.INFORMATION : Alert.AlertType.ERROR);
            resAlert.setTitle("Quarantine Result");
            resAlert.setHeaderText(result.isSuccess() ? "Quarantine Successful" : "Quarantine Operation Failed");
            resAlert.setContentText(result.getMessage() + (result.getErrorDetails() != null ? "\n" + result.getErrorDetails() : ""));
            resAlert.showAndWait();
        }
    }

    private void handleRestoreQuarantined() {
        if (engine == null) return;
        Incident active = engine.getAlertManager().getActiveIncident();
        Path scope = engine.getActiveMonitoredPath();

        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
        confirm.setTitle("Confirm Restore");
        confirm.setHeaderText("Restore Quarantined Files");
        confirm.setContentText("Restore files from .quarantine back to their original locations?\n\n" +
                "Existing files will not be overwritten (companion .restored files will be generated if names collide).");

        Optional<ButtonType> choice = confirm.showAndWait();
        if (choice.isPresent() && choice.get() == ButtonType.OK) {
            ResponseResult result = engine.getDefenseManager().restoreQuarantinedFiles(active, scope);
            if (active != null) {
                updateIncidentDisplay(active);
            }

            Alert resAlert = new Alert(result.isSuccess() ? Alert.AlertType.INFORMATION : Alert.AlertType.WARNING);
            resAlert.setTitle("Restore Result");
            resAlert.setHeaderText(result.isSuccess() ? "Restoration Completed" : "Restoration Notice");
            resAlert.setContentText(result.getMessage());
            resAlert.showAndWait();
        }
    }

    private void handleAcknowledge() {
        if (engine == null) return;
        Incident active = engine.getAlertManager().getActiveIncident();
        if (active != null) {
            engine.getDefenseManager().acknowledgeIncident(active);
            updateIncidentDisplay(active);
        }
    }

    private void handleResolve() {
        if (engine == null) return;
        Incident active = engine.getAlertManager().getActiveIncident();
        if (active != null) {
            engine.getDefenseManager().resolveIncident(active);
            updateIncidentDisplay(active);
        }
    }

    private void handleViewEvidence() {
        if (engine == null) return;
        Incident active = engine.getAlertManager().getActiveIncident();
        if (active == null) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("No Active Incident");
            alert.setHeaderText("No Incident Selected");
            alert.setContentText("There is currently no active security incident to inspect.");
            alert.showAndWait();
            return;
        }

        Dialog<Void> dialog = new Dialog<>();
        dialog.setTitle("Incident Behavioral Evidence Audit");
        dialog.setHeaderText("Detailed Forensic Evidence – Incident " + active.getId());

        VBox content = new VBox(10);
        content.setPadding(new Insets(14));
        content.setPrefWidth(550);

        content.getChildren().addAll(
                new Label("Threat Severity: " + active.getSeverity() + " (Score: " + active.getScore() + "/100)"),
                new Label("Status: " + active.getStatus() + " | Action: " + active.getResponseAction() + (active.isSimulated() ? " [SIMULATED]" : " [REAL]")),
                new Label("First Seen: " + TimeUtils.formatFull(active.getFirstSeen()) + " | Last Seen: " + TimeUtils.formatFull(active.getLastSeen())),
                new Label("Files Affected: " + active.getFilesAffected() + " | Directories: " + active.getDirectoriesAffected()),
                new Label("Shannon Entropy: Avg " + String.format("%.2f", active.getAverageEntropy()) + " bits | Max " + String.format("%.2f", active.getMaxEntropy()) + " bits"),
                new Label("Modification Rate: " + String.format("%.1f", active.getModificationRate()) + " files/s")
        );

        Label lblReasons = new Label("Triggered Behavioral Reasons:");
        lblReasons.setStyle("-fx-font-weight: bold; -fx-text-fill: #38bdf8;");
        ListView<String> lvReasons = new ListView<>();
        lvReasons.getItems().addAll(active.getReasons());
        lvReasons.setPrefHeight(90);

        Label lblPaths = new Label("Tracked Affected Paths (" + active.getAffectedPaths().size() + "):");
        lblPaths.setStyle("-fx-font-weight: bold; -fx-text-fill: #38bdf8;");
        ListView<String> lvPaths = new ListView<>();
        lvPaths.getItems().addAll(active.getAffectedPaths());
        lvPaths.setPrefHeight(100);

        content.getChildren().addAll(lblReasons, lvReasons, lblPaths, lvPaths);

        dialog.getDialogPane().setContent(content);
        dialog.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);
        dialog.showAndWait();
    }

    private void updateIncidentDisplay(Incident incident) {
        Platform.runLater(() -> {
            if (incident != null) {
                lblActiveIncidentInfo.setText(String.format("Incident: %s | %s (%s)",
                        incident.getId().substring(0, Math.min(8, incident.getId().length())),
                        incident.getSeverity(),
                        incident.getStatus()));
            } else {
                lblActiveIncidentInfo.setText("Active Incident: None");
            }
            if (engine != null && engine.getIncidentRepository() != null) {
                lblOpenIncidents.setText("Open Incidents: " + engine.getIncidentRepository().countOpen());
            }
        });
    }

    private HBox createFactorRow(String name, ProgressBar bar, Label valLabel) {
        HBox row = new HBox(8);
        row.setAlignment(Pos.CENTER_LEFT);
        Label lblName = new Label(name);
        lblName.setStyle("-fx-font-size: 11px; -fx-text-fill: #94a3b8;");
        lblName.setPrefWidth(160);

        bar.setPrefWidth(90);
        bar.getStyleClass().add("threat-progress");

        valLabel.setStyle("-fx-font-size: 11px; -fx-text-fill: #f8fafc; -fx-font-weight: bold;");
        valLabel.setPrefWidth(65);
        valLabel.setAlignment(Pos.CENTER_RIGHT);

        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);

        row.getChildren().addAll(lblName, sp, bar, valLabel);
        return row;
    }

    private void setupEventTable() {
        eventTableView.setItems(eventFeedList);
        eventTableView.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_ALL_COLUMNS);

        // Time
        TableColumn<FileEvent, String> colTime = new TableColumn<>("TIME");
        colTime.setCellValueFactory(d -> new SimpleStringProperty(TimeUtils.formatTimeOnly(d.getValue().getTimestamp())));
        colTime.setPrefWidth(85);

        // Event
        TableColumn<FileEvent, String> colEvent = new TableColumn<>("EVENT");
        colEvent.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getEventType()));
        colEvent.setPrefWidth(90);
        colEvent.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setGraphic(null);
                } else {
                    Label badge = new Label(item);
                    badge.getStyleClass().add("badge");
                    if ("MODIFY".equalsIgnoreCase(item)) {
                        badge.setStyle("-fx-background-color: rgba(6, 182, 212, 0.2); -fx-text-fill: #06b6d4; -fx-border-color: #06b6d4;");
                    } else if ("RENAME".equalsIgnoreCase(item)) {
                        badge.setStyle("-fx-background-color: rgba(249, 115, 22, 0.2); -fx-text-fill: #f97316; -fx-border-color: #f97316;");
                    } else if ("CREATE".equalsIgnoreCase(item)) {
                        badge.setStyle("-fx-background-color: rgba(16, 185, 129, 0.2); -fx-text-fill: #10b981; -fx-border-color: #10b981;");
                    } else {
                        badge.setStyle("-fx-background-color: rgba(156, 163, 175, 0.2); -fx-text-fill: #9ca3af; -fx-border-color: #4b5563;");
                    }
                    setGraphic(badge);
                    setAlignment(Pos.CENTER);
                }
            }
        });

        // File
        TableColumn<FileEvent, String> colFile = new TableColumn<>("FILE NAME");
        colFile.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getFileName()));
        colFile.setPrefWidth(180);

        // Size
        TableColumn<FileEvent, String> colSize = new TableColumn<>("SIZE");
        colSize.setCellValueFactory(d -> new SimpleStringProperty(FileUtils.formatBytes(d.getValue().getFileSize())));
        colSize.setPrefWidth(85);

        // Entropy
        TableColumn<FileEvent, String> colEntropy = new TableColumn<>("ENTROPY");
        colEntropy.setCellValueFactory(d -> {
            Double e = d.getValue().getEntropy();
            return new SimpleStringProperty(e != null ? String.format("%.2f bits", e) : "-");
        });
        colEntropy.setPrefWidth(95);
        colEntropy.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null || "-".equals(item)) {
                    setText(item);
                    setStyle("-fx-text-fill: #94a3b8;");
                } else {
                    setText(item);
                    try {
                        double val = Double.parseDouble(item.replace(" bits", "").trim());
                        if (val >= 7.5) {
                            setStyle("-fx-text-fill: #ef4444; -fx-font-weight: bold;");
                        } else if (val >= 6.5) {
                            setStyle("-fx-text-fill: #f59e0b; -fx-font-weight: bold;");
                        } else {
                            setStyle("-fx-text-fill: #10b981;");
                        }
                    } catch (Exception ex) {
                        setStyle("-fx-text-fill: #f1f5f9;");
                    }
                }
            }
        });

        eventTableView.getColumns().addAll(List.of(colTime, colEvent, colFile, colSize, colEntropy));
    }

    /**
     * Appends a newly processed file event to the live table feed.
     */
    public void addEvent(FileEvent event) {
        Platform.runLater(() -> {
            eventFeedList.add(0, event);
            if (eventFeedList.size() > 500) {
                eventFeedList.remove(eventFeedList.size() - 1);
            }
        });
    }

    /**
     * Updates real-time diagnostic indicators and metric cards.
     */
    public void updateAssessment(ThreatAssessment assessment) {
        Platform.runLater(() -> {
            int score = assessment.getScore();
            ThreatLevel level = assessment.getThreatLevel();

            lblScore.setText(String.valueOf(score));
            barScore.setProgress(score / 100.0);

            // Update Threat Level Badge
            lblThreatLevel.setText(level.name());
            lblThreatLevel.getStyleClass().removeAll("badge-normal", "badge-suspicious", "badge-high", "badge-critical");
            lblThreatLevel.getStyleClass().add(level.getStyleClass());

            // Metrics
            lblFilesAffected.setText(String.valueOf(assessment.getAffectedFiles()));
            lblModRate.setText(String.format("%.1f files/s", assessment.getModificationRate()));
            lblAvgEntropy.setText(String.format("%.2f bits", assessment.getAverageEntropy()));
            lblEntropySub.setText(String.format("Max: %.2f bits", assessment.getMaxEntropy()));

            // Update factor bars
            barEntropyFactor.setProgress(assessment.getEntropyScore() / 20.0);
            lblEntropyFactorVal.setText(assessment.getEntropyScore() + " / 20 pts");

            barRateFactor.setProgress(assessment.getRateScore() / 20.0);
            lblRateFactorVal.setText(assessment.getRateScore() + " / 20 pts");

            barFilesFactor.setProgress(assessment.getFilesScore() / 20.0);
            lblFilesFactorVal.setText(assessment.getFilesScore() + " / 20 pts");

            barDirsFactor.setProgress(assessment.getDirectoryScore() / 10.0);
            lblDirsFactorVal.setText(assessment.getDirectoryScore() + " / 10 pts");

            barPatternFactor.setProgress(assessment.getOperationScore() / 20.0);
            lblPatternFactorVal.setText(assessment.getOperationScore() + " / 20 pts");

            // Update Alert Banner
            alertBanner.getStyleClass().removeAll("alert-banner-normal", "alert-banner-suspicious", "alert-banner-high", "alert-banner-critical");
            if (level == ThreatLevel.CRITICAL) {
                alertBanner.getStyleClass().add("alert-banner-critical");
                lblBannerTitle.setText("CRITICAL: RANSOMWARE-LIKE ACTIVITY DETECTED!");
                lblBannerSubtitle.setText("Multi-factor threshold breach: Immediate defensive isolation advised.");
            } else if (level == ThreatLevel.HIGH) {
                alertBanner.getStyleClass().add("alert-banner-high");
                lblBannerTitle.setText("HIGH RISK: SEVERE ANOMALOUS ACTIVITY");
                lblBannerSubtitle.setText("Massive file modifications and elevated entropy observed.");
            } else if (level == ThreatLevel.SUSPICIOUS) {
                alertBanner.getStyleClass().add("alert-banner-suspicious");
                lblBannerTitle.setText("SUSPICIOUS: ABNORMAL BEHAVIOR OBSERVED");
                lblBannerSubtitle.setText("File modification patterns exceed baseline heuristics.");
            } else {
                alertBanner.getStyleClass().add("alert-banner-normal");
                lblBannerTitle.setText("STATUS: SYSTEM NORMAL");
                lblBannerSubtitle.setText("All filesystem operations within safe behavioral bounds.");
            }

            // Update Reasons
            reasonsListView.getItems().clear();
            if (assessment.getReasons().isEmpty()) {
                reasonsListView.getItems().add("Normal filesystem activity. No anomaly triggers fired.");
            } else {
                reasonsListView.getItems().addAll(assessment.getReasons());
            }

            // Update Active Defense Status Indicators
            if (engine != null) {
                Incident active = engine.getAlertManager().getActiveIncident();
                updateIncidentDisplay(active);

                if (engine.getDefenseManager() != null) {
                    DefensePolicy.PolicyDecision decision = engine.getDefenseManager().getDefensePolicy().evaluate(assessment, active);
                    lblRecommendedAction.setText("Policy: " + decision.getRecommendedAction().getDisplayName());
                }
            }
        });
    }
}
